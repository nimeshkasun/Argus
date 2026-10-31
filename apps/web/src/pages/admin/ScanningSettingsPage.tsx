import { type IntelStatusDto, type RiskWeights, type ScanningSettings, type ToolStatus } from '@argus/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, XCircle } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { RetentionCard } from '../../components/RetentionCard';
import { Button, Card, CardHeader, CenteredSpinner, Checkbox, ErrorAlert, Field, Input, PageHeader, Select, Table } from '../../components/ui';
import { api } from '../../lib/api';
import { useAuth } from '../../lib/auth';
import { formatRelative } from '../../lib/utils';

const WEIGHTS: { key: keyof RiskWeights; label: string; hint: string }[] = [
  { key: 'kev', label: 'Known exploited (CISA KEV)', hint: 'Added when a vulnerability is being exploited in the wild.' },
  { key: 'epssMax', label: 'Exploit probability (EPSS), maximum', hint: 'Scaled by the EPSS probability (0–100%).' },
  { key: 'publicRepo', label: 'Public repository', hint: 'Added for issues in publicly visible repositories.' },
  { key: 'devDependency', label: 'Development-only dependency', hint: 'Negative: not shipped to production.' },
  { key: 'transitiveDependency', label: 'Transitive dependency', hint: 'Negative: not referenced directly.' },
  { key: 'testPath', label: 'Test or example code', hint: 'Negative: e.g. secrets under test/ or fixtures/.' },
  { key: 'criticalityLow', label: 'Low business criticality', hint: 'Applied per repository setting.' },
  { key: 'criticalityHigh', label: 'High business criticality', hint: '' },
  { key: 'criticalityCritical', label: 'Critical business criticality', hint: '' },
  { key: 'verifiedActive', label: 'Secret verified active', hint: 'Live verification found the secret still works.' },
  { key: 'verifiedInactive', label: 'Secret rejected by its issuer', hint: 'Negative: revoked or invalid.' },
];

const list = (s: string) =>
  s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

function ToolRow({ label, tool, missing }: { label: string; tool: ToolStatus; missing: string }) {
  return (
    <tr>
      <td className="px-4 py-2.5">{label}</td>
      <td className="px-4 py-2.5 text-slate-500">—</td>
      <td className="px-4 py-2.5 text-sm">
        {tool.available ? (
          <span className="inline-flex items-center gap-1 text-green-700 dark:text-green-400">
            <CheckCircle2 className="size-4" /> Installed ({tool.version})
          </span>
        ) : (
          <span className="text-amber-700 dark:text-amber-400">{missing}</span>
        )}
      </td>
    </tr>
  );
}

export function IntelStatusCard() {
  const query = useQuery({ queryKey: ['intel', 'status'], queryFn: () => api<IntelStatusDto>('/intel/status') });
  return (
    <Card>
      <CardHeader title="Threat intelligence sources" description="Where vulnerability and lifecycle data comes from. Lookups are cached and refreshed automatically." />
      <ErrorAlert error={query.error} />
      {!query.data ? (
        <CenteredSpinner />
      ) : (
        <Table head={['Source', 'Last used', 'Status']}>
          {query.data.feeds.map((f) => (
            <tr key={f.key}>
              <td className="px-4 py-2.5">{f.label}</td>
              <td className="px-4 py-2.5 whitespace-nowrap text-slate-500">{formatRelative(f.fetchedAt)}</td>
              <td className="px-4 py-2.5 text-sm">
                {f.error ? (
                  <span className="inline-flex items-center gap-1 text-red-600 dark:text-red-400">
                    <XCircle className="size-4" /> {f.error}
                  </span>
                ) : f.fetchedAt ? (
                  <span className="inline-flex items-center gap-1 text-green-700 dark:text-green-400">
                    <CheckCircle2 className="size-4" /> OK{f.entries !== null ? ` · ${f.entries.toLocaleString()} entries` : ''}
                  </span>
                ) : (
                  <span className="text-slate-400">Not used yet</span>
                )}
              </td>
            </tr>
          ))}
          <ToolRow label="Gitleaks secret scanner" tool={query.data.gitleaks} missing="Not installed — Argus built-in rules are used" />
          <ToolRow
            label="Opengrep code analysis"
            tool={query.data.opengrep.available && !query.data.opengrep.rules ? { available: false, version: null } : query.data.opengrep}
            missing={query.data.opengrep.available ? 'Installed, but no rules are configured (ARGUS_OPENGREP_RULES) — code analysis is skipped' : 'Not installed — code analysis is skipped'}
          />
          <ToolRow label="Trivy (infrastructure as code, container images)" tool={query.data.trivy} missing="Not installed — infrastructure-as-code and image scanning are skipped" />
        </Table>
      )}
    </Card>
  );
}

export function ScanningSettingsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can('settings:manage');
  const query = useQuery({ queryKey: ['settings', 'scanning'], queryFn: () => api<ScanningSettings>('/settings/scanning') });
  const [form, setForm] = useState<ScanningSettings | null>(null);
  const [deny, setDeny] = useState('');
  const [review, setReview] = useState('');
  useEffect(() => {
    if (!query.data) return;
    setForm(query.data);
    setDeny(query.data.licenseDeny.join(', '));
    setReview(query.data.licenseReview.join(', '));
  }, [query.data]);
  const save = useMutation({
    mutationFn: (body: ScanningSettings) => api<ScanningSettings>('/settings/scanning', { method: 'PUT', body }),
    onSuccess: (data) => {
      qc.setQueryData(['settings', 'scanning'], data);
      toast.success('Scanning settings saved. They apply from the next scan.');
    },
  });
  if (!form) return <CenteredSpinner />;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate({ ...form, licenseDeny: list(deny), licenseReview: list(review) });
  };

  return (
    <>
      <PageHeader title="Scanning settings" description="How findings are scored and which licenses and lifecycles are acceptable." />
      <form onSubmit={submit} className="space-y-6">
        <ErrorAlert error={query.error ?? save.error} />
        <fieldset disabled={!manage} className="space-y-6">
          <Card>
            <CardHeader title="Risk score adjustments" description="Each finding starts from a base score (e.g. CVSS × 10, or the type of secret) and these points are added or removed. The result is clamped to 0–100." />
            <div className="grid gap-4 p-5 sm:grid-cols-3">
              {WEIGHTS.map((w) => (
                <Field key={w.key} label={w.label} hint={w.hint}>
                  {(id) => <Input id={id} type="number" min={-50} max={50} value={form.riskWeights[w.key]} onChange={(e) => setForm({ ...form, riskWeights: { ...form.riskWeights, [w.key]: Number(e.target.value) } })} required />}
                </Field>
              ))}
            </div>
          </Card>
          <Card>
            <CardHeader title="License policy" description="SPDX identifiers, comma-separated. A trailing * matches prefixes (e.g. GPL-3.0* matches GPL-3.0-only and GPL-3.0-or-later)." />
            <div className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label="Not allowed">{(id) => <Input id={id} value={deny} onChange={(e) => setDeny(e.target.value)} />}</Field>
              <Field label="Needs review">{(id) => <Input id={id} value={review} onChange={(e) => setReview(e.target.value)} />}</Field>
            </div>
          </Card>
          <Card>
            <CardHeader title="Early warnings" />
            <div className="grid gap-4 p-5 sm:grid-cols-2">
              <Field label="Framework end-of-life warning (days)" hint="Flag frameworks and runtimes this long before support ends.">
                {(id) => <Input id={id} type="number" min={0} max={730} value={form.eolWarningDays} onChange={(e) => setForm({ ...form, eolWarningDays: Number(e.target.value) })} required />}
              </Field>
              <Field label="Certificate and token expiry warning (days)" hint="Flag credentials this long before they expire.">
                {(id) => <Input id={id} type="number" min={1} max={365} value={form.expiryWarningDays} onChange={(e) => setForm({ ...form, expiryWarningDays: Number(e.target.value) })} required />}
              </Field>
            </div>
            <div className="border-t border-slate-100 p-5 dark:border-slate-800">
              <Checkbox
                label="Verify detected secrets with their issuer"
                description="For GitHub, GitLab, Slack and npm tokens, AWS access keys and Azure Storage account keys, makes one read-only request to the issuer's own API to tell whether the secret still works; the risk score rises if it does and drops if it was revoked. Off by default: the detected secret is sent to its issuer (and nowhere else)."
                checked={form.verifySecrets}
                onChange={(e) => setForm({ ...form, verifySecrets: e.target.checked })}
              />
            </div>
            <div className="grid gap-4 border-t border-slate-100 p-5 sm:grid-cols-2 dark:border-slate-800">
              <Field label="Commits of history to scan for secrets" hint="0 scans only the current code. Finds secrets that were committed and later deleted; clones fetch this many commits.">
                {(id) => <Input id={id} type="number" min={0} max={1000} value={form.secretHistoryCommits} onChange={(e) => setForm({ ...form, secretHistoryCommits: Number(e.target.value) })} required />}
              </Field>
            </div>
          </Card>
          <Card>
            <CardHeader title="Container images" description="Scan the images a repository references (Dockerfile FROM, Docker Compose and Kubernetes manifests) for vulnerable packages, with Trivy." />
            <div className="space-y-4 p-5">
              <Checkbox
                label="Scan referenced container images"
                description="Off by default. Each image is pulled from its registry, and Trivy downloads its vulnerability database. Private registries need credentials in Trivy's environment (see the documentation). Not available in offline mode."
                checked={form.containerImages.enabled}
                onChange={(e) => setForm({ ...form, containerImages: { ...form.containerImages, enabled: e.target.checked } })}
              />
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Images per scan" hint="The first images by file path are scanned; the rest are listed as not scanned.">
                  {(id) => <Input id={id} type="number" min={1} max={50} value={form.containerImages.maxImages} onChange={(e) => setForm({ ...form, containerImages: { ...form.containerImages, maxImages: Number(e.target.value) } })} required />}
                </Field>
                <Field label="Lowest severity reported">
                  {(id) => (
                    <Select id={id} value={form.containerImages.minSeverity} onChange={(e) => setForm({ ...form, containerImages: { ...form.containerImages, minSeverity: e.target.value as ScanningSettings['containerImages']['minSeverity'] } })}>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </Select>
                  )}
                </Field>
              </div>
              <Checkbox
                label="Only vulnerabilities with a fix"
                description="Skip vulnerabilities that have no fixed package version yet; there is nothing to act on until there is."
                checked={form.containerImages.fixableOnly}
                onChange={(e) => setForm({ ...form, containerImages: { ...form.containerImages, fixableOnly: e.target.checked } })}
              />
            </div>
          </Card>
        </fieldset>
        {manage && (
          <div className="flex justify-end">
            <Button type="submit" loading={save.isPending}>
              Save settings
            </Button>
          </div>
        )}
      </form>
      <div className="mt-6">
        <RetentionCard />
      </div>
      <div className="mt-6">
        <IntelStatusCard />
      </div>
    </>
  );
}
