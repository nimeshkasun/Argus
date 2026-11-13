import Anthropic from '@anthropic-ai/sdk';
import { AI_DEFAULT_BASE_URLS, type AiProvider } from '@argus/shared';
import { Redactor } from '../common/redact';
import { callExternal, IntegrationError } from '../integrations/outbound';

export interface AiRequest {
  system: string;
  prompt: string;
  /** JSON Schema of the expected answer: every object closed (additionalProperties: false), every property required. */
  schema: Record<string, unknown>;
  schemaName: string;
  /** Low for quick classification, medium for advice. */
  effort: 'low' | 'medium';
}

export interface AiResponse {
  /** Raw text the model returned; parsed and validated by the caller. */
  text: string;
  /** The model that actually answered (may differ from the requested one, e.g. after a server-side fallback). */
  model: string;
  inputTokens: number;
  outputTokens: number;
}

export interface AiClient {
  readonly provider: AiProvider;
  generate(req: AiRequest): Promise<AiResponse>;
}

export interface AiClientOptions {
  model: string;
  apiKey: string;
  /** null = the provider's public API. */
  baseUrl: string | null;
}

/** A provider answered but not with something usable (refusal, truncation, empty output). */
export class AiOutputError extends Error {
  override name = 'AiOutputError';
}

const TIMEOUT_MS = 120_000;
const MAX_TOKENS = 16_000;

/** Claude models that take output_config.effort (all current generations). */
const CLAUDE_EFFORT = /^claude-(?:(?:opus|sonnet|haiku|fable|mythos)-5|opus-4-[5-8]|sonnet-4-6)/;
/** Claude models that accept the server-side refusal fallback on the Claude API. */
const CLAUDE_FALLBACK = /^claude-(?:opus-5-5|opus-5|fable-5-1|sonnet-5-5)$/;

class AnthropicClient implements AiClient {
  readonly provider = 'anthropic' as const;
  private readonly client: Anthropic;

  constructor(private readonly opts: AiClientOptions) {
    this.client = new Anthropic({ apiKey: opts.apiKey, baseURL: opts.baseUrl ?? AI_DEFAULT_BASE_URLS.anthropic, timeout: TIMEOUT_MS, maxRetries: 2 });
  }

  async generate(req: AiRequest): Promise<AiResponse> {
    // On the Claude API, a request a model declines is re-run on a suitable fallback model instead of failing.
    const fallback = !this.opts.baseUrl && CLAUDE_FALLBACK.test(this.opts.model);
    let res: Anthropic.Beta.BetaMessage;
    try {
      res = await this.client.beta.messages.create({
        model: this.opts.model,
        max_tokens: MAX_TOKENS,
        system: req.system,
        messages: [{ role: 'user', content: req.prompt }],
        output_config: { format: { type: 'json_schema', schema: req.schema }, ...(CLAUDE_EFFORT.test(this.opts.model) ? { effort: req.effort } : {}) },
        ...(fallback ? { betas: ['server-side-fallback-2026-07-01'], fallbacks: 'default' as const } : {}),
      });
    } catch (err) {
      throw anthropicError(err, this.opts.apiKey);
    }
    if (res.stop_reason === 'refusal') throw new AiOutputError(`Claude declined the request${res.stop_details?.category ? ` (${res.stop_details.category})` : ''}.`);
    if (res.stop_reason === 'max_tokens') throw new AiOutputError('The answer was cut off at the output token limit.');
    const text = res.content.flatMap((b) => (b.type === 'text' ? [b.text] : [])).join('');
    return { text, model: res.model, inputTokens: res.usage.input_tokens + (res.usage.cache_read_input_tokens ?? 0) + (res.usage.cache_creation_input_tokens ?? 0), outputTokens: res.usage.output_tokens };
  }
}

function anthropicError(err: unknown, apiKey: string): Error {
  const redactor = new Redactor([apiKey]);
  if (err instanceof Anthropic.AuthenticationError) return new IntegrationError('Anthropic rejected the API key.', 401);
  if (err instanceof Anthropic.PermissionDeniedError) return new IntegrationError('The Anthropic API key is not allowed to use this model.', 403);
  if (err instanceof Anthropic.NotFoundError) return new IntegrationError('Anthropic does not know this model. Check the model name.', 404);
  if (err instanceof Anthropic.RateLimitError) return new IntegrationError('Anthropic rate limit reached; try again shortly.', 429);
  if (err instanceof Anthropic.APIConnectionError) return new IntegrationError(`Could not reach Anthropic: ${redactor.redact(err.message)}`);
  if (err instanceof Anthropic.APIError) return new IntegrationError(`Anthropic returned HTTP ${err.status ?? '?'}: ${redactor.redact(err.message).slice(0, 300)}`, err.status ?? null);
  return err instanceof Error ? err : new Error(String(err));
}

/** OpenAI Chat Completions with a strict JSON schema response format. Works with OpenAI-compatible gateways. */
class OpenAiClient implements AiClient {
  readonly provider: AiProvider = 'openai';
  protected readonly label: string = 'OpenAI';

  constructor(protected readonly opts: AiClientOptions) {}

  /** Extra top-level request fields (gateway extensions). */
  protected extraBody(): Record<string, unknown> {
    return {};
  }

  protected endpoint(): string {
    return (this.opts.baseUrl ?? AI_DEFAULT_BASE_URLS.openai).replace(/\/+$/, '');
  }

  async generate(req: AiRequest): Promise<AiResponse> {
    const base = this.endpoint();
    const res = await withKey(this.opts.apiKey, this.label, () =>
      callExternal(`${base}/chat/completions`, {
        service: this.label,
        method: 'POST',
        timeoutMs: TIMEOUT_MS,
        headers: { Authorization: `Bearer ${this.opts.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: this.opts.model,
          messages: [
            { role: 'system', content: req.system },
            { role: 'user', content: req.prompt },
          ],
          max_completion_tokens: MAX_TOKENS,
          response_format: { type: 'json_schema', json_schema: { name: req.schemaName, strict: true, schema: req.schema } },
          ...this.extraBody(),
        }),
      }),
    );
    const body = (await res.json()) as {
      model?: string;
      choices?: { message?: { content?: string | null; refusal?: string | null }; finish_reason?: string }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
    };
    const choice = body.choices?.[0];
    if (choice?.message?.refusal) throw new AiOutputError(`${this.label} declined the request.`);
    if (choice?.finish_reason === 'length') throw new AiOutputError('The answer was cut off at the output token limit.');
    // Relay reports the model that really served the request (after routing or fallback) in a header.
    const served = res.headers.get('x-relay-model');
    return { text: choice?.message?.content ?? '', model: served || body.model || this.opts.model, inputTokens: body.usage?.prompt_tokens ?? 0, outputTokens: body.usage?.completion_tokens ?? 0 };
  }
}

/**
 * Relay (https://github.com/nimeshkasun/Relay): a self-hosted, OpenAI-compatible LLM gateway. Same wire format as
 * OpenAI; the base URL is the gateway's /v1 endpoint, the key is a Relay key (rly_...), and the model is a Relay
 * route (smart, cheap, resilient) or a provider/model slug.
 */
class RelayClient extends OpenAiClient {
  override readonly provider = 'relay' as const;
  protected override readonly label = 'Relay';

  protected override endpoint(): string {
    const base = (this.opts.baseUrl ?? '').replace(/\/+$/, '');
    if (!base) throw new IntegrationError('Relay needs a base URL: the address of your Relay gateway, for example https://relay.example.com/v1.');
    return /\/v1$/.test(base) ? base : `${base}/v1`;
  }

  // Tag requests for Relay's own reports, and skip its response cache so every answer is fresh and counted.
  protected override extraBody(): Record<string, unknown> {
    return { relay: { tags: ['app:argus'], cache: false } };
  }
}

/** Gemini generateContent with a JSON response schema. */
class GeminiClient implements AiClient {
  readonly provider = 'gemini' as const;

  constructor(private readonly opts: AiClientOptions) {}

  async generate(req: AiRequest): Promise<AiResponse> {
    const base = (this.opts.baseUrl ?? AI_DEFAULT_BASE_URLS.gemini).replace(/\/+$/, '');
    const res = await withKey(this.opts.apiKey, 'Gemini', () =>
      callExternal(`${base}/models/${encodeURIComponent(this.opts.model)}:generateContent`, {
        service: 'Gemini',
        method: 'POST',
        timeoutMs: TIMEOUT_MS,
        // The key goes in a header, never in the URL, so it cannot end up in proxy or access logs.
        headers: { 'x-goog-api-key': this.opts.apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: req.system }] },
          contents: [{ role: 'user', parts: [{ text: req.prompt }] }],
          generationConfig: { responseMimeType: 'application/json', responseJsonSchema: req.schema, maxOutputTokens: MAX_TOKENS },
        }),
      }),
    );
    const body = (await res.json()) as {
      modelVersion?: string;
      promptFeedback?: { blockReason?: string };
      candidates?: { content?: { parts?: { text?: string; thought?: boolean }[] }; finishReason?: string }[];
      usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; thoughtsTokenCount?: number };
    };
    if (body.promptFeedback?.blockReason) throw new AiOutputError(`Gemini blocked the request (${body.promptFeedback.blockReason}).`);
    const candidate = body.candidates?.[0];
    if (candidate?.finishReason === 'MAX_TOKENS') throw new AiOutputError('The answer was cut off at the output token limit.');
    if (candidate?.finishReason && !['STOP', 'FINISH_REASON_UNSPECIFIED'].includes(candidate.finishReason)) throw new AiOutputError(`Gemini stopped early (${candidate.finishReason}).`);
    const text = (candidate?.content?.parts ?? []).filter((p) => !p.thought).map((p) => p.text ?? '').join('');
    const u = body.usageMetadata ?? {};
    return { text, model: body.modelVersion ?? this.opts.model, inputTokens: u.promptTokenCount ?? 0, outputTokens: (u.candidatesTokenCount ?? 0) + (u.thoughtsTokenCount ?? 0) };
  }
}

/** Makes sure an API key can never appear in an error message, and explains the common status codes. */
async function withKey<T>(apiKey: string, service: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (!(err instanceof IntegrationError)) throw err;
    const hint = err.status === 401 || err.status === 403 ? ` Check the ${service} API key.` : err.status === 404 ? ' Check the model name and base URL.' : err.status === 429 ? ' Rate limit or quota reached.' : '';
    throw new IntegrationError(new Redactor([apiKey]).redact(`${err.message}${hint}`), err.status);
  }
}

export function createAiClient(provider: AiProvider, opts: AiClientOptions): AiClient {
  switch (provider) {
    case 'anthropic':
      return new AnthropicClient(opts);
    case 'openai':
      return new OpenAiClient(opts);
    case 'gemini':
      return new GeminiClient(opts);
    case 'relay':
      return new RelayClient(opts);
  }
}
