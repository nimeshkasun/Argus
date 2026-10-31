import { type FindingDto, SCANNER_LABELS, type Severity, type SuppressionDto } from '@argus/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertOctagon, BadgeCheck, ExternalLink, Flame, ShieldOff } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { Link } from 'react-router';
import { toast } from 'sonner';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { cn, formatDateTime, formatRelative } from '../lib/utils';
import { Badge, Button, CenteredSpinner, ErrorAlert, Field, Input, Modal, Select } from './ui';
import { AiHintPanel } from './ai';
import { ApproveLicenseModal } from './LicenseExceptions';

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-red-600 text-white ring-red-700',
  high: 'bg-orange-500 text-white ring-orange-600',
  medium: 'bg-amber-100 text-amber-900 ring-amber-300 dark:bg-amber-500/20 dark:text-amber-200 dark:ring-amber-500/40',
  low: 'bg-sky-50 text-sky-800 ring-sky-200 dark:bg-sky-500/10 dark:text-sky-300 dark:ring-sky-500/30',
  info: 'bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-700',
};

export function SeverityBadge({ severity, score }: { severity: Severity; score?: number }) {
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold capitalize ring-1 ring-inset whitespace-nowrap', SEVERITY_STYLE[severity])}>
      {severity}
      {score !== undefined && <span className="font-mono opacity-80">{score}</span>}
    </span>
  );
}

export function FindingStatusBadge({ status }: { status: FindingDto['status'] }) {
  return <Badge tone={status === 'open' ? 'red' : status === 'fixed' ? 'green' : 'slate'}>{status[0].toUpperCase() + status.slice(1)}</Badge>;
}

export function findingLocation(f: FindingDto): string {
  if (f.package) return `${f.package.name}@${f.package.version} · ${f.path}`;
  return f.path ? `${f.path}${f.line ? `:${f.line}` : ''}` : '—';
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-3 gap-3 py-1.5 text-sm">
      <dt className="text-slate-500 dark:text-slate-400">{label}</dt>
      <dd className="col-span-2 min-w-0 break-words">{children}</dd>
    </div>
  );
}

export function SuppressModal({ finding, onClose }: { finding: FindingDto; onClose(): void }) {
  const qc = useQueryClient();
  const [scope, setScope] = useState<'repo' | 'global'>('repo');
  const [by, setBy] = useState<'rule' | 'package' | 'path'>(finding.advisory ? 'rule' : finding.package ? 'package' : finding.path ? 'path' : 'rule');
  const [reason, setReason] = useState('');
  const [expires, setExpires] = useState('');
  const mutation = useMutation({
    mutationFn: () =>
      api<SuppressionDto>('/suppressions', {
        method: 'POST',
        body: {
          repoId: scope === 'repo' ? finding.repoId : null,
          scanner: finding.scanner,
          ruleId: by === 'rule' ? finding.ruleId : null,
          packageName: by === 'package' ? (finding.package?.name ?? null) : null,
          pathPattern: by === 'path' ? finding.path : null,
          reason,
          expiresAt: expires ? new Date(`${expires}T23:59:59Z`).toISOString() : null,
        },
      }),
    onSuccess: (s) => {
      toast.success(`Suppressed ${s.matchedFindings ?? 0} finding(s).`);
      void qc.invalidateQueries({ queryKey: ['findings'] });
      void qc.invalidateQueries({ queryKey: ['finding'] });
      void qc.invalidateQueries({ queryKey: ['suppressions'] });
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    mutation.mutate();
  };
  return (
    <Modal
      open
      onClose={onClose}
      title="Suppress finding"
      description="Suppressed findings stay visible but stop counting as open risk. Every suppression is audited."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="suppress-form" loading={mutation.isPending}>
            Suppress
          </Button>
        </>
      }
    >
      <form id="suppress-form" onSubmit={submit} className="space-y-4">
        <ErrorAlert error={mutation.error} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Applies to">
            {(id) => (
              <Select id={id} value={scope} onChange={(e) => setScope(e.target.value as 'repo' | 'global')}>
                <option value="repo">{finding.repoFullName ?? 'This repository'}</option>
                <option value="global">All repositories</option>
              </Select>
            )}
          </Field>
          <Field label="Match on">
            {(id) => (
              <Select id={id} value={by} onChange={(e) => setBy(e.target.value as 'rule' | 'package' | 'path')}>
                <option value="rule">Rule {finding.ruleId}</option>
                {finding.package && <option value="package">Package {finding.package.name}</option>}
                {finding.path && <option value="path">Path {finding.path}</option>}
              </Select>
            )}
          </Field>
        </div>
        <Field label="Justification" hint="Why this is acceptable, e.g. not reachable, compensating control, tracked elsewhere.">
          {(id) => <Input id={id} value={reason} onChange={(e) => setReason(e.target.value)} minLength={5} maxLength={1000} required />}
        </Field>
        <Field label="Expires (optional)" hint="After this date the finding counts as open again at the next scan.">
          {(id) => <Input id={id} type="date" value={expires} min={new Date(Date.now() + 86_400_000).toISOString().slice(0, 10)} onChange={(e) => setExpires(e.target.value)} />}
        </Field>
      </form>
    </Modal>
  );
}

export function FindingModal({ findingId, onClose }: { findingId: string; onClose(): void }) {
  const { can } = useAuth();
  const [suppressing, setSuppressing] = useState(false);
  const [approving, setApproving] = useState(false);
  const query = useQuery({ queryKey: ['finding', findingId], queryFn: () => api<FindingDto>(`/findings/${findingId}`) });
  const f = query.data;
  const suppression = (f?.details?.suppression ?? null) as { source: string; reason: string } | null;

  return (
    <>
      <Modal open={!suppressing && !approving} onClose={onClose} wide title={f?.title ?? 'Finding'} description={f ? `${f.repoFullName ?? ''} · ${SCANNER_LABELS[f.scanner]}` : undefined}>
        <ErrorAlert error={query.error} />
        {!f ? (
          <CenteredSpinner />
        ) : (
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} score={f.riskScore} />
              <FindingStatusBadge status={f.status} />
              {f.advisory?.kev && (
                <Badge tone="red">
                  <Flame className="mr-1 size-3" />
                  Known exploited
                </Badge>
              )}
              {f.ticketId && (
                <Link to={`/tickets/${f.ticketId}`} className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400" onClick={onClose}>
                  View ticket →
                </Link>
              )}
              {can('settings:manage') && f.scanner === 'licenses' && f.status === 'open' && f.package && (
                <Button size="sm" variant="secondary" className="ml-auto" icon={<BadgeCheck className="size-4" />} onClick={() => setApproving(true)}>
                  Approve license
                </Button>
              )}
              {can('tickets:triage') && f.status === 'open' && (
                <Button size="sm" variant="secondary" className={f.scanner === 'licenses' && can('settings:manage') && f.package ? '' : 'ml-auto'} icon={<ShieldOff className="size-4" />} onClick={() => setSuppressing(true)}>
                  Suppress
                </Button>
              )}
            </div>

            {f.status === 'suppressed' && (
              <div className="rounded-md bg-slate-50 p-3 text-sm ring-1 ring-slate-200 dark:bg-slate-800/50 dark:ring-slate-700">
                Suppressed{suppression?.source === 'repo-file' ? ' by the repository’s .argus.yml' : ''}: {suppression?.reason ?? 'see Suppressions'}
              </div>
            )}

            <section>
              <h3 className="mb-1 text-xs font-semibold tracking-wide text-slate-500 uppercase">Why this score</h3>
              <ul className="divide-y divide-slate-100 rounded-md ring-1 ring-slate-200 dark:divide-slate-800 dark:ring-slate-800">
                {f.riskFactors.map((rf, i) => (
                  <li key={i} className="flex justify-between px-3 py-1.5 text-sm">
                    <span>{rf.label}</span>
                    <span className={cn('font-mono', rf.points < 0 ? 'text-green-600' : i === 0 ? '' : 'text-red-600')}>
                      {i === 0 ? rf.points : rf.points > 0 ? `+${rf.points}` : rf.points}
                    </span>
                  </li>
                ))}
                <li className="flex justify-between bg-slate-50 px-3 py-1.5 text-sm font-semibold dark:bg-slate-800/50">
                  <span>Risk score (0–100)</span>
                  <span className="font-mono">{f.riskScore}</span>
                </li>
              </ul>
            </section>

            {f.aiHint && <AiHintPanel hint={f.aiHint} />}

            {f.remediation && (
              <section className="rounded-md bg-indigo-50 p-3 text-sm ring-1 ring-indigo-100 dark:bg-indigo-500/10 dark:ring-indigo-500/20">
                <div className="mb-1 font-semibold">How to fix</div>
                {f.remediation}
              </section>
            )}

            <dl className="divide-y divide-slate-100 dark:divide-slate-800">
              <Row label="Location">
                <code className="text-xs">{findingLocation(f)}</code>
              </Row>
              {f.package && (
                <Row label="Package">
                  {f.package.ecosystem} · {f.package.name}@{f.package.version} · {f.package.direct ? 'direct' : 'transitive'}
                  {f.package.dev && ' · dev only'}
                  {f.package.fixedVersion && <div className="text-green-700 dark:text-green-400">Fixed in {f.package.fixedVersion}</div>}
                </Row>
              )}
              {f.advisory && (
                <Row label="Advisory">
                  <div className="flex flex-wrap items-center gap-x-2">
                    {f.advisory.url ? (
                      <a href={f.advisory.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-indigo-600 hover:underline dark:text-indigo-400">
                        {f.advisory.id} <ExternalLink className="size-3" />
                      </a>
                    ) : (
                      f.advisory.id
                    )}
                    {f.advisory.aliases.map((a) => (
                      <span key={a} className="text-slate-500">
                        {a}
                      </span>
                    ))}
                  </div>
                  <div className="text-xs text-slate-500">
                    {f.advisory.cvssScore !== null && `CVSS ${f.advisory.cvssScore.toFixed(1)}`}
                    {f.advisory.epss !== null && ` · EPSS ${(f.advisory.epss * 100).toFixed(1)}%`}
                    {f.advisory.published && ` · published ${formatDateTime(f.advisory.published)}`}
                  </div>
                </Row>
              )}
              {f.secret && (
                <Row label="Secret">
                  <code className="text-xs">{f.secret.preview}</code> <span className="text-xs text-slate-500">({f.secret.type}; the full value is never stored)</span>
                </Row>
              )}
              {f.details &&
                Object.entries(f.details)
                  .filter(([k, v]) => k !== 'suppression' && v !== null && typeof v !== 'object')
                  .map(([k, v]) => (
                    <Row key={k} label={k.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase())}>
                      {String(v)}
                    </Row>
                  ))}
              <Row label="First seen">{formatDateTime(f.firstSeenAt)}</Row>
              <Row label="Last seen">{formatRelative(f.lastSeenAt)}</Row>
              {f.fixedAt && <Row label="Fixed">{formatDateTime(f.fixedAt)}</Row>}
            </dl>

            {f.description && (
              <section>
                <h3 className="mb-1 text-xs font-semibold tracking-wide text-slate-500 uppercase">Details</h3>
                <p className="text-sm whitespace-pre-line text-slate-700 dark:text-slate-300">{f.description}</p>
              </section>
            )}
          </div>
        )}
      </Modal>
      {suppressing && f && <SuppressModal finding={f} onClose={() => setSuppressing(false)} />}
      {approving && f && <ApproveLicenseModal finding={f} onClose={() => setApproving(false)} />}
    </>
  );
}

export function EmptyFindings() {
  return (
    <div className="flex flex-col items-center px-6 py-12 text-center">
      <AlertOctagon className="mb-3 size-6 text-slate-400" />
      <div className="text-sm font-semibold">No findings</div>
      <p className="mt-1 max-w-sm text-sm text-slate-500 dark:text-slate-400">Nothing matches these filters.</p>
    </div>
  );
}
