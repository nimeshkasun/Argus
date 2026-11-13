import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { type DataStore, type Repository, type User } from '@argus/data';
import {
  AI_MODEL_PRICES,
  AI_PROVIDERS,
  AI_USE_CASES,
  type AiProvider,
  type AiProviderSettings,
  type AiSettingsDto,
  type AiSettingsInput,
  type AiStatusDto,
  type AiUsageDto,
  type AiUseCase,
  type ConnectionTestDto,
  DEFAULT_AI_SETTINGS,
} from '@argus/shared';
import { type RequestContext } from '../common/request';
import { AppConfig } from '../config/app-config';
import { AuditService } from '../core/audit.service';
import { CryptoService } from '../core/crypto.service';
import { DATA_STORE } from '../core/tokens';
import { IntegrationError } from '../integrations/outbound';
import { type OutputSpec, SYSTEM_PREAMBLE, USE_CASE_EFFORT } from './output-schemas';
import { AiOutputError, type AiClient, createAiClient } from './providers';
import { capText, redactForPrompt } from './redaction';

const SETTINGS_KEY = 'ai';

interface StoredProvider extends AiProviderSettings {
  keyEnc: string | null;
  keyHint: string | null;
}

interface StoredAi extends Omit<AiSettingsInput, 'providers'> {
  providers: Record<AiProvider, StoredProvider>;
}

/** AI cannot run for this request (switched off, excluded, not configured, over budget). */
export class AiUnavailableError extends BadRequestException {}

export interface AiRunRequest<T> {
  useCase: AiUseCase;
  /** The repository the content comes from (its AI opt-out applies), or null for content not tied to one (security news). */
  repo: Repository | null;
  /** null for background work (scans). */
  actor: User | null;
  /** Use-case specific instructions, appended to the shared preamble. */
  instructions: string;
  /** Facts and repository content. Redacted and capped here before anything leaves the process. */
  prompt: string;
  /** Exact values to remove in addition to pattern-based redaction (e.g. the detected secret). */
  knownSecrets?: string[];
  output: OutputSpec<T>;
  subject: { type: string; id: string };
}

export interface AiRunResult<T> {
  output: T;
  provider: AiProvider;
  model: string;
  redactions: number;
}

function monthRange(month?: string): { from: Date; to: Date; label: string } {
  const now = new Date();
  const [y, m] = month ? month.split('-').map(Number) : [now.getUTCFullYear(), now.getUTCMonth() + 1];
  const from = new Date(Date.UTC(y, m - 1, 1));
  const to = new Date(Date.UTC(y, m, 1));
  return { from, to, label: `${y}-${String(m).padStart(2, '0')}` };
}

/**
 * The single gateway to AI providers. Every request passes the same guardrails: feature and per-repository
 * switches, the monthly budget, secret redaction, a context size cap, schema validation of the answer, usage
 * accounting and an audit entry. Prompts and answers are never logged or audited.
 */
@Injectable()
export class AiService {
  private readonly logger = new Logger('AI');

  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly crypto: CryptoService,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  private async stored(): Promise<StoredAi> {
    const v = (await this.store.settings.get<Partial<StoredAi>>(SETTINGS_KEY))?.value ?? {};
    const providers = Object.fromEntries(
      AI_PROVIDERS.map((p) => [p, { ...DEFAULT_AI_SETTINGS.providers[p], keyEnc: null, keyHint: null, ...(v.providers?.[p] ?? {}) }]),
    ) as Record<AiProvider, StoredProvider>;
    const useCases = Object.fromEntries(AI_USE_CASES.map((u) => [u, { ...DEFAULT_AI_SETTINGS.useCases[u], ...(v.useCases?.[u] ?? {}) }])) as StoredAi['useCases'];
    return { ...DEFAULT_AI_SETTINGS, ...v, providers, useCases };
  }

  async getSettings(): Promise<AiSettingsDto> {
    const s = await this.stored();
    const providers = Object.fromEntries(
      AI_PROVIDERS.map((p) => {
        const { keyEnc, keyHint, ...rest } = s.providers[p];
        return [p, { ...rest, keyConfigured: !!keyEnc, keyHint }];
      }),
    ) as AiSettingsDto['providers'];
    return { ...s, providers };
  }

  async updateSettings(input: AiSettingsInput, actor: User, ctx: RequestContext): Promise<AiSettingsDto> {
    const current = await this.stored();
    const providers = {} as Record<AiProvider, StoredProvider>;
    const keysChanged: string[] = [];
    for (const p of AI_PROVIDERS) {
      const { apiKey, clearApiKey, ...rest } = input.providers[p];
      const prev = current.providers[p];
      const keyEnc = apiKey ? this.crypto.encrypt(apiKey) : clearApiKey ? null : prev.keyEnc;
      if (apiKey || (clearApiKey && prev.keyEnc)) keysChanged.push(p);
      providers[p] = { ...rest, baseUrl: rest.baseUrl?.replace(/\/+$/, '') ?? null, keyEnc, keyHint: apiKey ? `••••${apiKey.slice(-4)}` : keyEnc ? prev.keyHint : null };
      if (rest.enabled && !keyEnc) throw new BadRequestException(`Enter an API key for ${p} before enabling it.`);
      if (p === 'relay' && rest.enabled && !providers[p].baseUrl) throw new BadRequestException('Enter the base URL of your Relay gateway before enabling it.');
    }
    if (input.enabled && !providers[input.defaultProvider].enabled) throw new BadRequestException('The default provider must be enabled.');
    const value: StoredAi = { ...input, providers };
    await this.store.settings.set(SETTINGS_KEY, value, actor.id);
    await this.audit.record({
      action: 'settings.ai_updated',
      actor,
      details: {
        enabled: value.enabled,
        defaultProvider: value.defaultProvider,
        providers: Object.fromEntries(AI_PROVIDERS.map((p) => [p, { enabled: providers[p].enabled, model: providers[p].model, baseUrl: providers[p].baseUrl }])),
        useCases: value.useCases,
        monthlyBudgetUsd: value.monthlyBudgetUsd,
        maxContextChars: value.maxContextChars,
        keysChanged,
      },
      ip: ctx.ip,
    });
    return this.getSettings();
  }

  async status(): Promise<AiStatusDto> {
    const s = await this.stored();
    const ready = (u: AiUseCase) => {
      const p = s.providers[s.useCases[u].provider ?? s.defaultProvider];
      return s.enabled && s.useCases[u].enabled && p.enabled && !!p.keyEnc;
    };
    return {
      enabled: s.enabled,
      useCases: Object.fromEntries(AI_USE_CASES.map((u) => [u, ready(u)])) as AiStatusDto['useCases'],
      budgetExhausted: await this.overBudget(s),
    };
  }

  /** The most repository content one prompt may include (administrator setting). */
  async contextLimit(): Promise<number> {
    return (await this.stored()).maxContextChars;
  }

  /** Whether a background use case may run for this repository (no exception, for scans). */
  async canRun(useCase: AiUseCase, repo: Repository | null): Promise<boolean> {
    try {
      await this.prepare(useCase, repo);
      return true;
    } catch {
      return false;
    }
  }

  async usage(month?: string): Promise<AiUsageDto> {
    const s = await this.stored();
    const { from, to, label } = monthRange(month);
    const rows = await this.store.aiUsage.summary(from, to);
    return { month: label, budgetUsd: s.monthlyBudgetUsd, spentUsd: rows.reduce((n, r) => n + r.costUsd, 0), rows };
  }

  private async overBudget(s: StoredAi): Promise<boolean> {
    if (s.monthlyBudgetUsd === null) return false;
    const { from, to } = monthRange();
    return (await this.store.aiUsage.totalCost(from, to)) >= s.monthlyBudgetUsd;
  }

  private cost(provider: StoredProvider, model: string, inputTokens: number, outputTokens: number): number {
    const listed = AI_MODEL_PRICES[model] ?? AI_MODEL_PRICES[provider.model];
    const input = provider.inputPricePerMTok ?? listed?.input ?? 0;
    const output = provider.outputPricePerMTok ?? listed?.output ?? 0;
    return (inputTokens * input + outputTokens * output) / 1_000_000;
  }

  private clientFor(name: AiProvider, p: StoredProvider): AiClient {
    if (!p.enabled || !p.keyEnc) throw new AiUnavailableError(`The AI provider ${name} is not configured. An administrator can set it up under Administration → AI.`);
    if (this.config.offline && !p.baseUrl) throw new AiUnavailableError('Argus runs in offline mode; AI is only available through a self-hosted endpoint (base URL).');
    return createAiClient(name, { model: p.model, apiKey: this.crypto.decrypt(p.keyEnc), baseUrl: p.baseUrl });
  }

  private async prepare(useCase: AiUseCase, repo: Repository | null) {
    const s = await this.stored();
    if (!s.enabled) throw new AiUnavailableError('AI assistance is turned off.');
    if (!s.useCases[useCase].enabled) throw new AiUnavailableError('This AI feature is turned off.');
    if (repo && !repo.aiEnabled) throw new AiUnavailableError(`${repo.fullName} is excluded from AI assistance.`);
    const name = s.useCases[useCase].provider ?? s.defaultProvider;
    const client = this.clientFor(name, s.providers[name]);
    if (await this.overBudget(s)) throw new AiUnavailableError('The monthly AI budget has been reached.');
    return { s, name, provider: s.providers[name], client };
  }

  async run<T>(req: AiRunRequest<T>): Promise<AiRunResult<T>> {
    const { s, name, provider, client } = await this.prepare(req.useCase, req.repo);
    const redacted = redactForPrompt(req.prompt, req.knownSecrets);
    const prompt = capText(redacted.text, s.maxContextChars);
    const system = `${SYSTEM_PREAMBLE}\n\n${req.instructions}`;

    const account = async (outcome: 'ok' | 'error' | 'invalid_output', model: string, inputTokens = 0, outputTokens = 0) => {
      const costUsd = this.cost(provider, model, inputTokens, outputTokens);
      await this.store.aiUsage.record({ provider: name, model, useCase: req.useCase, userId: req.actor?.id ?? null, repoId: req.repo?.id ?? null, inputTokens, outputTokens, costUsd, outcome });
      await this.audit.record({
        action: 'ai.request',
        actor: req.actor,
        target: req.subject,
        outcome: outcome === 'ok' ? 'success' : 'failure',
        details: { useCase: req.useCase, provider: name, model, repo: req.repo?.fullName ?? null, inputTokens, outputTokens, costUsd: Math.round(costUsd * 1e6) / 1e6, redactions: redacted.redactions, outcome },
      });
    };

    let res;
    try {
      res = await client.generate({ system, prompt, schema: req.output.schema, schemaName: req.output.name, effort: USE_CASE_EFFORT[req.useCase] });
    } catch (err) {
      await account('error', provider.model);
      if (err instanceof IntegrationError || err instanceof AiOutputError) throw err;
      this.logger.warn(`AI request failed: ${err instanceof Error ? err.message : String(err)}`);
      throw new IntegrationError('The AI provider request failed.');
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(res.text);
    } catch {
      parsed = undefined;
    }
    const valid = req.output.validate.safeParse(parsed);
    if (!valid.success) {
      await account('invalid_output', res.model, res.inputTokens, res.outputTokens);
      throw new AiOutputError('The AI answer did not match the expected format, so it was discarded. Try again or choose another model.');
    }
    await account('ok', res.model, res.inputTokens, res.outputTokens);
    return { output: valid.data, provider: name, model: res.model, redactions: redacted.redactions };
  }

  /** Sends a tiny request to check the key, model and endpoint (works before the provider is enabled). */
  async test(name: AiProvider, actor: User): Promise<ConnectionTestDto> {
    const s = await this.stored();
    const p = s.providers[name];
    try {
      const client = this.clientFor(name, { ...p, enabled: true });
      const res = await client.generate({
        system: 'Reply with the JSON object requested.',
        prompt: 'Return {"ok": true}.',
        schema: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'], additionalProperties: false },
        schemaName: 'ping',
        effort: 'low',
      });
      await this.audit.record({ action: 'ai.provider_tested', actor, details: { provider: name, model: res.model, ok: true } });
      return { ok: true, message: `Connected. ${res.model} answered (${res.inputTokens + res.outputTokens} tokens).` };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.audit.record({ action: 'ai.provider_tested', actor, outcome: 'failure', details: { provider: name, model: p.model, ok: false } });
      return { ok: false, message };
    }
  }
}
