import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { type AddressInfo } from 'node:net';

export interface AiCall {
  provider: 'anthropic' | 'openai' | 'gemini' | 'relay';
  headers: IncomingMessage['headers'];
  /** System and user text as sent. */
  text: string;
  body: Record<string, unknown>;
}

export interface MockAiOptions {
  /** Override the answer for a kind of request; return a string to send invalid JSON. */
  answer?: (kind: string, call: AiCall) => unknown;
  /** Respond with this HTTP status instead. */
  status?: number;
}

type Kind = 'remediation' | 'draft' | 'secret_triage' | 'applicability' | 'advisory_extraction' | 'pr_review' | 'ping';

function kindOf(schema: { properties?: Record<string, { enum?: string[] }> } | undefined): Kind {
  const p = schema?.properties ?? {};
  if (p.steps) return 'remediation';
  if (p.advisories) return 'advisory_extraction';
  if (p.comments) return 'pr_review';
  if (p.subject) return 'draft';
  if (p.verdict?.enum?.includes('likely_real')) return 'secret_triage';
  if (p.verdict) return 'applicability';
  return 'ping';
}

const DEFAULT_ANSWERS: Record<Kind, unknown> = {
  remediation: {
    summary: 'Upgrade lodash to 4.17.21.',
    steps: ['Run npm install lodash@4.17.21', 'Run the test suite', 'Deploy'],
    fixVersion: '4.17.21',
    breakingChangeRisk: 'low',
    rationale: 'The advisory lists 4.17.21 as the first fixed version; it is a patch release.',
    confidence: 0.9,
  },
  draft: { subject: 'Upgrade lodash (command injection)', body: 'lodash 4.17.20 is vulnerable.\n\nPlease upgrade to 4.17.21.' },
  secret_triage: { verdict: 'likely_false_positive', rationale: 'The value sits in a test fixture and is named as an example.', confidence: 0.8 },
  applicability: { verdict: 'likely_affected', rationale: 'The code calls _.template with user input.', confidence: 0.7 },
  advisory_extraction: { relevant: false, advisories: [], rationale: 'General news; no npm or NuGet package is named.', confidence: 0.9 },
  pr_review: {
    summary: 'Adds a checkout module and a region setting.',
    comments: [
      { path: 'src/checkout.js', line: 2, category: 'maintainability', severity: 'suggestion', comment: 'Export a function that reads the token from configuration instead of exporting the value.' },
      { path: 'src/checkout.js', line: 999, category: 'bug', severity: 'issue', comment: 'This line is not in the diff and must be dropped.' },
    ],
    confidence: 0.8,
  },
  ping: { ok: true },
};

/**
 * Anthropic Messages, OpenAI Chat Completions and Gemini generateContent endpoints under /ai/anthropic,
 * /ai/openai and /ai/gemini. Answers depend on the requested JSON schema. Every call is recorded.
 */
export function aiRoutes(calls: AiCall[], opts: MockAiOptions = {}) {
  return (req: IncomingMessage, url: URL, body: string, res: ServerResponse): boolean => {
    const json = (data: unknown, status = 200) => (res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(data)), true);
    const p = url.pathname;
    if (req.method !== 'POST' || !p.startsWith('/ai/')) return false;
    const b = JSON.parse(body || '{}') as Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
    const answer = (kind: Kind, call: AiCall) => {
      const a = opts.answer ? (opts.answer(kind, call) ?? DEFAULT_ANSWERS[kind]) : DEFAULT_ANSWERS[kind];
      return typeof a === 'string' ? a : JSON.stringify(a);
    };

    if (p === '/ai/anthropic/v1/messages') {
      const call: AiCall = { provider: 'anthropic', headers: req.headers, body: b, text: `${b.system}\n${b.messages?.[0]?.content}` };
      calls.push(call);
      if (opts.status) return json({ type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } }, opts.status);
      return json({
        id: 'msg_1',
        type: 'message',
        role: 'assistant',
        model: b.model,
        content: [{ type: 'text', text: answer(kindOf(b.output_config?.format?.schema), call) }],
        stop_reason: 'end_turn',
        stop_sequence: null,
        usage: { input_tokens: 1000, output_tokens: 200 },
      });
    }
    if (p === '/ai/openai/chat/completions') {
      const call: AiCall = { provider: 'openai', headers: req.headers, body: b, text: (b.messages ?? []).map((m: { content: string }) => m.content).join('\n') };
      calls.push(call);
      if (opts.status) return json({ error: { message: 'Incorrect API key provided' } }, opts.status);
      return json({ model: b.model, choices: [{ message: { content: answer(kindOf(b.response_format?.json_schema?.schema), call) }, finish_reason: 'stop' }], usage: { prompt_tokens: 1000, completion_tokens: 200 } });
    }
    if (p === '/ai/relay/v1/chat/completions') {
      const call: AiCall = { provider: 'relay', headers: req.headers, body: b, text: (b.messages ?? []).map((m: { content: string }) => m.content).join('\n') };
      calls.push(call);
      if (opts.status) return json({ error: { message: 'Invalid API key', type: 'invalid_request_error', code: 'invalid_api_key' } }, opts.status);
      // Relay names the model that really answered (after routing) in a header; the body echoes the requested route.
      res.setHeader('x-relay-model', 'openai/gpt-6.1-sol');
      return json({ model: b.model, choices: [{ message: { content: answer(kindOf(b.response_format?.json_schema?.schema), call) }, finish_reason: 'stop' }], usage: { prompt_tokens: 1000, completion_tokens: 200 } });
    }
    const gemini = /^\/ai\/gemini\/models\/([^/]+):generateContent$/.exec(p);
    if (gemini) {
      const call: AiCall = { provider: 'gemini', headers: req.headers, body: b, text: `${b.systemInstruction?.parts?.[0]?.text}\n${b.contents?.[0]?.parts?.[0]?.text}` };
      calls.push(call);
      if (opts.status) return json({ error: { code: opts.status, message: 'API key not valid' } }, opts.status);
      return json({
        modelVersion: decodeURIComponent(gemini[1]),
        candidates: [{ content: { parts: [{ text: answer(kindOf(b.generationConfig?.responseJsonSchema), call) }] }, finishReason: 'STOP' }],
        usageMetadata: { promptTokenCount: 1000, candidatesTokenCount: 200 },
      });
    }
    return false;
  };
}

/** Standalone mock for unit tests. */
export async function startMockAi(opts: MockAiOptions = {}): Promise<{ url: string; calls: AiCall[]; close(): Promise<void> }> {
  const calls: AiCall[] = [];
  const route = aiRoutes(calls, opts);
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString('utf8')));
    req.on('end', () => {
      if (!route(req, new URL(req.url ?? '/', 'http://localhost'), body, res)) res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, calls, close: () => new Promise<void>((r) => server.close(() => r())) };
}
