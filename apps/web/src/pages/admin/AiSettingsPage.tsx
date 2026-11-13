import {
  AI_PROVIDER_LABELS,
  AI_PROVIDERS,
  AI_SUGGESTED_MODELS,
  AI_USE_CASE_LABELS,
  AI_USE_CASES,
  type AiProvider,
  type AiSettingsDto,
  type AiUsageDto,
  type AiUseCase,
  type ConnectionTestDto,
} from '@argus/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, ShieldCheck, XCircle } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Badge, Button, Card, CardHeader, CenteredSpinner, Checkbox, ErrorAlert, Field, Input, PageHeader, Select, Table } from '../../components/ui';
import { api } from '../../lib/api';

type ProviderForm = { enabled: boolean; model: string; baseUrl: string; inputPricePerMTok: string; outputPricePerMTok: string; apiKey: string; clearApiKey: boolean };
type Form = Omit<AiSettingsDto, 'providers' | 'monthlyBudgetUsd'> & { monthlyBudgetUsd: string; providers: Record<AiProvider, ProviderForm> };

const usd = (n: number) => `$${n < 1 ? n.toFixed(4) : n.toFixed(2)}`;

function toForm(d: AiSettingsDto): Form {
  const providers = Object.fromEntries(
    AI_PROVIDERS.map((p) => {
      const s = d.providers[p];
      return [p, { enabled: s.enabled, model: s.model, baseUrl: s.baseUrl ?? '', inputPricePerMTok: s.inputPricePerMTok?.toString() ?? '', outputPricePerMTok: s.outputPricePerMTok?.toString() ?? '', apiKey: '', clearApiKey: false }];
    }),
  ) as Record<AiProvider, ProviderForm>;
  return { ...d, monthlyBudgetUsd: d.monthlyBudgetUsd?.toString() ?? '', providers };
}

function toBody(f: Form) {
  const num = (v: string) => (v.trim() === '' ? null : Number(v));
  return {
    ...f,
    monthlyBudgetUsd: num(f.monthlyBudgetUsd),
    providers: Object.fromEntries(
      AI_PROVIDERS.map((p) => {
        const s = f.providers[p];
        return [
          p,
          {
            enabled: s.enabled,
            model: s.model.trim(),
            baseUrl: s.baseUrl.trim() || null,
            inputPricePerMTok: num(s.inputPricePerMTok),
            outputPricePerMTok: num(s.outputPricePerMTok),
            ...(s.apiKey ? { apiKey: s.apiKey } : {}),
            ...(s.clearApiKey ? { clearApiKey: true } : {}),
          },
        ];
      }),
    ),
  };
}

function ProviderCard({ name, form, saved, onChange }: { name: AiProvider; form: ProviderForm; saved: AiSettingsDto['providers'][AiProvider]; onChange(p: Partial<ProviderForm>): void }) {
  const test = useMutation({ mutationFn: () => api<ConnectionTestDto>('/settings/ai/test', { method: 'POST', body: { provider: name } }) });
  const listId = `models-${name}`;
  return (
    <Card>
      <CardHeader
        title={AI_PROVIDER_LABELS[name]}
        description={saved.keyConfigured ? `API key stored (${saved.keyHint}).` : 'No API key stored.'}
        actions={saved.enabled ? <Badge tone="green">Enabled</Badge> : <Badge>Off</Badge>}
      />
      <div className="space-y-4 p-5">
        {test.data && (
          <div className={`flex items-start gap-2 rounded-md p-3 text-sm ring-1 ${test.data.ok ? 'bg-green-50 text-green-800 ring-green-600/20 dark:bg-green-500/10 dark:text-green-300' : 'bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300'}`}>
            {test.data.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
            {test.data.message}
          </div>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Model" hint={name === 'relay' ? 'A Relay route (smart, cheap, resilient) or a provider/model slug.' : 'Any model your account can use.'}>
            {(id) => (
              <>
                <Input id={id} list={listId} value={form.model} onChange={(e) => onChange({ model: e.target.value })} required />
                <datalist id={listId}>
                  {AI_SUGGESTED_MODELS[name].map((m) => (
                    <option key={m} value={m} />
                  ))}
                </datalist>
              </>
            )}
          </Field>
          <Field label="API key" hint={saved.keyConfigured ? 'Leave empty to keep the stored key.' : 'Stored encrypted; never shown again.'}>
            {(id) => <Input id={id} type="password" autoComplete="new-password" value={form.apiKey} onChange={(e) => onChange({ apiKey: e.target.value, clearApiKey: false })} />}
          </Field>
          <Field label="Base URL (optional)" hint={name === 'relay' ? 'Required: your Relay gateway, e.g. https://relay.example.com/v1.' : "For a gateway or private endpoint. Empty uses the provider's public API."}>
            {(id) => <Input id={id} type="url" value={form.baseUrl} onChange={(e) => onChange({ baseUrl: e.target.value })} placeholder="https://" required={name === 'relay' && form.enabled} />}
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Input $ / 1M tokens" hint="Empty: built-in price list.">
              {(id) => <Input id={id} type="number" min={0} step="0.01" value={form.inputPricePerMTok} onChange={(e) => onChange({ inputPricePerMTok: e.target.value })} />}
            </Field>
            <Field label="Output $ / 1M tokens">{(id) => <Input id={id} type="number" min={0} step="0.01" value={form.outputPricePerMTok} onChange={(e) => onChange({ outputPricePerMTok: e.target.value })} />}</Field>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <Checkbox label="Enabled" checked={form.enabled} onChange={(e) => onChange({ enabled: e.target.checked })} />
          {saved.keyConfigured && <Checkbox label="Remove stored key" checked={form.clearApiKey} onChange={(e) => onChange({ clearApiKey: e.target.checked, apiKey: '', enabled: e.target.checked ? false : form.enabled })} />}
          <Button type="button" variant="secondary" size="sm" className="ml-auto" loading={test.isPending} disabled={!saved.keyConfigured} onClick={() => test.mutate()}>
            Test saved settings
          </Button>
        </div>
      </div>
    </Card>
  );
}

function UsageCard() {
  const usage = useQuery({ queryKey: ['ai', 'usage'], queryFn: () => api<AiUsageDto>('/settings/ai/usage') });
  const u = usage.data;
  const pct = u?.budgetUsd ? Math.min(100, (u.spentUsd / u.budgetUsd) * 100) : 0;
  return (
    <Card>
      <CardHeader title="Usage this month" description={u ? `${u.month} (UTC). Costs are estimates from token counts and list prices.` : undefined} />
      <div className="space-y-4 p-5">
        <ErrorAlert error={usage.error} />
        {u && (
          <>
            <div>
              <div className="flex justify-between text-sm">
                <span>
                  Spent <strong>{usd(u.spentUsd)}</strong>
                </span>
                <span className="text-slate-500">{u.budgetUsd === null ? 'No budget cap' : `Budget ${usd(u.budgetUsd)}`}</span>
              </div>
              {u.budgetUsd !== null && (
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800">
                  <div className={`h-full ${pct >= 100 ? 'bg-red-500' : pct >= 80 ? 'bg-amber-500' : 'bg-indigo-600'}`} style={{ width: `${pct}%` }} />
                </div>
              )}
            </div>
            {u.rows.length > 0 && (
              <Table head={['Provider', 'Model', 'Use', 'Requests', 'Failed', 'Tokens in / out', 'Cost']}>
                {u.rows.map((r) => (
                  <tr key={`${r.provider}-${r.model}-${r.useCase}`}>
                    <td className="px-4 py-2">{AI_PROVIDER_LABELS[r.provider]}</td>
                    <td className="px-4 py-2 font-mono text-xs">{r.model}</td>
                    <td className="px-4 py-2">{AI_USE_CASE_LABELS[r.useCase].label}</td>
                    <td className="px-4 py-2">{r.requests}</td>
                    <td className="px-4 py-2">{r.failures}</td>
                    <td className="px-4 py-2">
                      {r.inputTokens.toLocaleString()} / {r.outputTokens.toLocaleString()}
                    </td>
                    <td className="px-4 py-2">{usd(r.costUsd)}</td>
                  </tr>
                ))}
              </Table>
            )}
          </>
        )}
      </div>
    </Card>
  );
}

export function AiSettingsPage() {
  const qc = useQueryClient();
  const current = useQuery({ queryKey: ['settings', 'ai'], queryFn: () => api<AiSettingsDto>('/settings/ai') });
  const [f, setF] = useState<Form | null>(null);
  useEffect(() => {
    if (current.data) setF(toForm(current.data));
  }, [current.data]);
  const save = useMutation({
    mutationFn: (form: Form) => api<AiSettingsDto>('/settings/ai', { method: 'PUT', body: toBody(form) }),
    onSuccess: (d) => {
      qc.setQueryData(['settings', 'ai'], d);
      void qc.invalidateQueries({ queryKey: ['ai'] });
      toast.success('AI settings saved.');
    },
  });
  if (current.isLoading || !f || !current.data) return current.error ? <ErrorAlert error={current.error} /> : <CenteredSpinner />;
  const saved = current.data;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(f);
  };
  const setUseCase = (u: AiUseCase, patch: Partial<Form['useCases'][AiUseCase]>) => setF({ ...f, useCases: { ...f.useCases, [u]: { ...f.useCases[u], ...patch } } });

  return (
    <form onSubmit={submit} className="space-y-6">
      <PageHeader
        title="AI assistance"
        description="Use Claude, OpenAI, Gemini or a Relay gateway to suggest fixes, draft Jira issues and emails, and triage findings."
        actions={
          <Button type="submit" loading={save.isPending}>
            Save
          </Button>
        }
      />
      <ErrorAlert error={save.error} />

      <div className="flex items-start gap-3 rounded-lg bg-indigo-50 p-4 text-sm text-indigo-900 ring-1 ring-indigo-600/20 dark:bg-indigo-500/10 dark:text-indigo-200">
        <ShieldCheck className="mt-0.5 size-5 shrink-0" />
        <div className="space-y-1">
          <p className="font-medium">Guardrails, always on</p>
          <p>
            Secrets are redacted before any prompt is sent, repository content is capped in size, and repositories can opt out. Answers must match a strict schema, are labelled
            AI-assisted, and never close, suppress or re-score anything. Every request is audited (without its content) and counted against the monthly budget.
          </p>
        </div>
      </div>

      <Card>
        <CardHeader title="General" />
        <div className="space-y-4 p-5">
          <Checkbox label="Enable AI assistance" description="When off, no data is sent to any AI provider." checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Default provider">
              {(id) => (
                <Select id={id} value={f.defaultProvider} onChange={(e) => setF({ ...f, defaultProvider: e.target.value as AiProvider })}>
                  {AI_PROVIDERS.map((p) => (
                    <option key={p} value={p}>
                      {AI_PROVIDER_LABELS[p]}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Monthly budget (USD)" hint="Requests stop when reached. Empty for no cap.">
              {(id) => <Input id={id} type="number" min={0} step="1" value={f.monthlyBudgetUsd} onChange={(e) => setF({ ...f, monthlyBudgetUsd: e.target.value })} />}
            </Field>
            <Field label="Context limit (characters)" hint="Most repository content one prompt may include.">
              {(id) => <Input id={id} type="number" min={1000} max={100000} step={1000} value={f.maxContextChars} onChange={(e) => setF({ ...f, maxContextChars: Number(e.target.value) })} />}
            </Field>
            <Field label="AI checks per scan" hint="Cap on triage requests in one scan.">
              {(id) => <Input id={id} type="number" min={0} max={200} value={f.maxScanChecks} onChange={(e) => setF({ ...f, maxScanChecks: Number(e.target.value) })} />}
            </Field>
          </div>
        </div>
      </Card>

      <Card>
        <CardHeader title="Features" description="Turn each use of AI on or off, and optionally route it to a specific provider." />
        <div className="divide-y divide-slate-100 dark:divide-slate-800">
          {AI_USE_CASES.map((u) => (
            <div key={u} className="flex flex-wrap items-center gap-4 px-5 py-4">
              <div className="min-w-60 flex-1">
                <Checkbox label={AI_USE_CASE_LABELS[u].label} description={AI_USE_CASE_LABELS[u].description} checked={f.useCases[u].enabled} onChange={(e) => setUseCase(u, { enabled: e.target.checked })} />
                {u === 'pr_review' && f.useCases.pr_review.enabled && (
                  <div className="mt-3 pl-7">
                    <Checkbox
                      label="Post remarks as inline comments"
                      description="Each remark is posted on its line of the pull request, like a reviewer's comment, instead of being listed in the summary comment. A new scan replaces the previous scan's inline comments."
                      checked={f.prReviewInline}
                      onChange={(e) => setF({ ...f, prReviewInline: e.target.checked })}
                    />
                  </div>
                )}
              </div>
              <Select aria-label={`Provider for ${AI_USE_CASE_LABELS[u].label}`} className="w-56" value={f.useCases[u].provider ?? ''} onChange={(e) => setUseCase(u, { provider: (e.target.value || null) as AiProvider | null })}>
                <option value="">Default provider</option>
                {AI_PROVIDERS.map((p) => (
                  <option key={p} value={p}>
                    {AI_PROVIDER_LABELS[p]}
                  </option>
                ))}
              </Select>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        {AI_PROVIDERS.map((p) => (
          <ProviderCard key={p} name={p} form={f.providers[p]} saved={saved.providers[p]} onChange={(patch) => setF({ ...f, providers: { ...f.providers, [p]: { ...f.providers[p], ...patch } } })} />
        ))}
      </div>

      <UsageCard />
    </form>
  );
}
