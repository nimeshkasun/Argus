import { z } from 'zod';

export const AI_PROVIDERS = ['anthropic', 'openai', 'gemini'] as const;
export type AiProvider = (typeof AI_PROVIDERS)[number];

export const AI_PROVIDER_LABELS: Record<AiProvider, string> = {
  anthropic: 'Anthropic Claude',
  openai: 'OpenAI',
  gemini: 'Google Gemini',
};

/** Public API endpoints; an administrator may point a provider at a compatible gateway instead. */
export const AI_DEFAULT_BASE_URLS: Record<AiProvider, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com/v1',
  gemini: 'https://generativelanguage.googleapis.com/v1beta',
};

/** Suggested models. Administrators can enter any model their account offers. */
export const AI_DEFAULT_MODELS: Record<AiProvider, string> = {
  anthropic: 'claude-opus-5-5',
  openai: 'gpt-6.1-sol',
  gemini: 'gemini-3.8-flash',
};

export const AI_SUGGESTED_MODELS: Record<AiProvider, string[]> = {
  anthropic: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5', 'claude-fable-5-1'],
  openai: ['gpt-6.1-sol', 'gpt-6-astra', 'gpt-6-luna'],
  gemini: ['gemini-3.8-flash', 'gemini-4-argon', 'gemini-3.1-flash-lite'],
};

/**
 * List prices in USD per million tokens (input, output), used to estimate cost against the monthly budget.
 * Prices change; a provider's price fields in the AI settings override these.
 */
export const AI_MODEL_PRICES: Record<string, { input: number; output: number }> = {
  'claude-fable-5-1': { input: 10, output: 50 },
  'claude-opus-5-5': { input: 4, output: 20 },
  'claude-sonnet-5-5': { input: 2, output: 10 },
  'claude-haiku-5-5': { input: 0.1, output: 0.5 },
  'gpt-6-astra': { input: 10, output: 50 },
  'gpt-6.1-sol': { input: 2, output: 10 },
  'gpt-6-luna': { input: 0.1, output: 0.5 },
  'gemini-4-argon': { input: 2, output: 10 },
  'gemini-3.8-flash': { input: 0.75, output: 3.75 },
  'gemini-3.1-flash-lite': { input: 0.25, output: 1.5 },
};

export const AI_USE_CASES = ['remediation', 'ticket_draft', 'secret_triage', 'vuln_applicability', 'advisory_extraction', 'pr_fix'] as const;
export type AiUseCase = (typeof AI_USE_CASES)[number];

export const AI_USE_CASE_LABELS: Record<AiUseCase, { label: string; description: string }> = {
  remediation: { label: 'Remediation suggestions', description: 'Step-by-step fix guidance on a ticket, generated on request.' },
  ticket_draft: { label: 'Jira and email drafting', description: 'Drafts a Jira description or an email message from a ticket, for you to edit before sending.' },
  secret_triage: { label: 'Secret triage', description: 'During scans, flags detected secrets that look like test fixtures or placeholders. Hints only — never suppresses.' },
  vuln_applicability: { label: 'Vulnerability applicability', description: 'During scans, judges from how a vulnerable package is used whether the repository is likely affected. Hints only.' },
  advisory_extraction: { label: 'Advisory extraction', description: 'Reads new items from security news feeds and proposes package advisories for review.' },
  pr_fix: { label: 'Pull request fix suggestions', description: 'During pull request scans, suggests a code change for new code and configuration issues, shown in the pull request comment for review.' },
};

/** Use cases that run during scans (on new findings) rather than on request. */
export const AI_SCAN_USE_CASES: AiUseCase[] = ['secret_triage', 'vuln_applicability'];

export type AiSubjectType = 'ticket' | 'finding';

const LOOPBACK = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i;
const https = z.url().refine((u) => u.startsWith('https://') || LOOPBACK.test(u), 'Must be an https:// URL.');
const price = z.number().min(0).max(1000).nullable();

export const aiProviderSettingsSchema = z.object({
  enabled: z.boolean(),
  model: z.string().trim().min(1).max(120).regex(/^[\w.:/-]+$/, 'Not a valid model name.'),
  /** null = the provider's public API. */
  baseUrl: https.nullable(),
  /** USD per million tokens; null = use the built-in price list. */
  inputPricePerMTok: price,
  outputPricePerMTok: price,
});

const providerInput = aiProviderSettingsSchema.extend({
  /** Write-only. Omit to keep the stored key. */
  apiKey: z.string().trim().min(8).max(4096).optional(),
  clearApiKey: z.boolean().optional(),
});

const useCaseSettings = z.object({
  enabled: z.boolean(),
  /** null = the default provider. */
  provider: z.enum(AI_PROVIDERS).nullable(),
});

export const aiSettingsSchema = z.object({
  enabled: z.boolean(),
  defaultProvider: z.enum(AI_PROVIDERS),
  providers: z.object({ anthropic: providerInput, openai: providerInput, gemini: providerInput }),
  useCases: z.object({ remediation: useCaseSettings, ticket_draft: useCaseSettings, secret_triage: useCaseSettings, vuln_applicability: useCaseSettings,
    // Added in Phase 5; optional so earlier clients keep working.
    advisory_extraction: useCaseSettings.default({ enabled: false, provider: null }),
    pr_fix: useCaseSettings.default({ enabled: false, provider: null }),
  }),
  /** Requests stop once the estimated spend this calendar month (UTC) reaches the budget. null = no cap. */
  monthlyBudgetUsd: z.number().min(0).max(1_000_000).nullable(),
  /** Upper bound on the characters of repository content (code snippets, finding details) in one prompt. */
  maxContextChars: z.number().int().min(1000).max(100_000),
  /** Upper bound on AI checks per scan (secret triage and applicability together). */
  maxScanChecks: z.number().int().min(0).max(200),
});
export type AiSettingsInput = z.infer<typeof aiSettingsSchema>;

export type AiProviderSettings = z.infer<typeof aiProviderSettingsSchema>;

export interface AiProviderSettingsDto extends AiProviderSettings {
  keyConfigured: boolean;
  keyHint: string | null;
}

export interface AiSettingsDto extends Omit<AiSettingsInput, 'providers'> {
  providers: Record<AiProvider, AiProviderSettingsDto>;
}

const defaultProvider = (p: AiProvider): AiProviderSettings => ({ enabled: false, model: AI_DEFAULT_MODELS[p], baseUrl: null, inputPricePerMTok: null, outputPricePerMTok: null });

export const DEFAULT_AI_SETTINGS: Omit<AiSettingsInput, 'providers'> & { providers: Record<AiProvider, AiProviderSettings> } = {
  enabled: false,
  defaultProvider: 'anthropic',
  providers: { anthropic: defaultProvider('anthropic'), openai: defaultProvider('openai'), gemini: defaultProvider('gemini') },
  useCases: {
    remediation: { enabled: true, provider: null },
    ticket_draft: { enabled: true, provider: null },
    secret_triage: { enabled: false, provider: null },
    vuln_applicability: { enabled: false, provider: null },
    advisory_extraction: { enabled: false, provider: null },
    pr_fix: { enabled: false, provider: null },
  },
  monthlyBudgetUsd: 50,
  maxContextChars: 12_000,
  maxScanChecks: 20,
};

/** What users without settings access need to know: which AI actions are available. */
export interface AiStatusDto {
  enabled: boolean;
  useCases: Record<AiUseCase, boolean>;
  budgetExhausted: boolean;
}

export const aiProviderTestSchema = z.object({ provider: z.enum(AI_PROVIDERS) });

// ---------------------------------------------------------------- outputs (validated before they are stored or shown)

const text = (max: number) => z.string().trim().min(1).max(max);
const confidence = z.number().min(0).max(1);

export const remediationOutputSchema = z.object({
  summary: text(1000),
  steps: z.array(text(1000)).min(1).max(12),
  /** Version that fixes the issue, when the fix is an upgrade. */
  fixVersion: z.string().trim().max(100).nullable(),
  breakingChangeRisk: z.enum(['low', 'medium', 'high', 'unknown']),
  rationale: text(2000),
  confidence,
});
export type RemediationOutput = z.infer<typeof remediationOutputSchema>;

export const prFixOutputSchema = z.object({
  /** One or two sentences: what to change and why. */
  summary: text(600),
  /** Replacement for the flagged lines, or null when the fix is not a local code change. */
  code: z.string().max(4000).nullable(),
  confidence,
});
export type PrFixOutput = z.infer<typeof prFixOutputSchema>;

export const draftOutputSchema = z.object({
  subject: text(250),
  body: text(8000),
});
export type DraftOutput = z.infer<typeof draftOutputSchema>;

export const secretTriageOutputSchema = z.object({
  verdict: z.enum(['likely_real', 'likely_false_positive', 'uncertain']),
  rationale: text(2000),
  confidence,
});
export type SecretTriageOutput = z.infer<typeof secretTriageOutputSchema>;

export const applicabilityOutputSchema = z.object({
  verdict: z.enum(['likely_affected', 'likely_not_affected', 'uncertain']),
  rationale: text(2000),
  confidence,
});
export type ApplicabilityOutput = z.infer<typeof applicabilityOutputSchema>;

export const AI_VERDICT_LABELS: Record<string, string> = {
  likely_real: 'Likely a real secret',
  likely_false_positive: 'Likely a false positive',
  likely_affected: 'Likely affected',
  likely_not_affected: 'Likely not affected',
  uncertain: 'Uncertain',
};

/** Every AI output is shown with its provenance so people can tell it apart from scanner facts. */
export interface AiInsightDto<T = Record<string, unknown>> {
  id: string;
  useCase: AiUseCase;
  subjectType: AiSubjectType;
  subjectId: string;
  provider: AiProvider;
  model: string;
  output: T;
  /** How many secret-like values were replaced before the prompt was sent. */
  redactions: number;
  createdAt: string;
  createdByName: string | null;
}

/** AI hint shown next to a finding (secret triage or vulnerability applicability). Advisory only. */
export interface FindingAiHintDto {
  useCase: AiUseCase;
  verdict: string;
  rationale: string;
  confidence: number;
  provider: AiProvider;
  model: string;
  createdAt: string;
}

export const aiDraftSchema = z.object({ target: z.enum(['jira', 'email']) });
export type AiDraftInput = z.infer<typeof aiDraftSchema>;

export interface AiDraftDto {
  subject: string;
  body: string;
  provider: AiProvider;
  model: string;
  redactions: number;
}

export interface AiUsageRowDto {
  provider: AiProvider;
  model: string;
  useCase: AiUseCase;
  requests: number;
  failures: number;
  inputTokens: number;
  outputTokens: number;
  costUsd: number;
}

export interface AiUsageDto {
  /** Calendar month, UTC, e.g. "2026-10". */
  month: string;
  budgetUsd: number | null;
  spentUsd: number;
  rows: AiUsageRowDto[];
}

export const aiUsageQuerySchema = z.object({ month: z.string().regex(/^\d{4}-(0[1-9]|1[0-2])$/).optional() });
