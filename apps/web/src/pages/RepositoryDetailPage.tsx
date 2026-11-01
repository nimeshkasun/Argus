import {
  type Criticality,
  CRITICALITIES,
  type FindingSummary,
  SCANNER_LABELS,
  SCANNERS,
  type ScannerName,
  type Paged,
  PROVIDER_LABELS,
  type RepositoryDto,
  type RepoUpdateInput,
  type ScanRunDto,
  SCHEDULE_LABELS,
  SCHEDULE_PRESETS,
  type SchedulePreset,
  type TeamDto,
} from '@argus/shared';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ExternalLink, History, Play } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router';
import { toast } from 'sonner';
import { DependenciesTable } from '../components/DependenciesTable';
import { SeverityBadge } from '../components/findings';
import { FindingsTable } from '../components/FindingsTable';
import { PullRequestScansTab } from '../components/PullRequestScans';
import { formatDuration, isActiveScan, ScanRunModal, ScanStatusBadge, TRIGGER_LABELS } from '../components/scans';
import { Badge, Button, Card, CardHeader, CenteredSpinner, Checkbox, EmptyState, ErrorAlert, Field, Input, Pagination, Select, Table } from '../components/ui';
import { api } from '../lib/api';
import { useAuth } from '../lib/auth';
import { formatDateTime, formatRelative } from '../lib/utils';

const RUNS_PAGE_SIZE = 20;

interface FormState {
  active: boolean;
  teamId: string;
  criticality: Criticality;
  branch: string;
  preset: SchedulePreset;
  cron: string;
  scanOnPush: boolean;
  jiraProjectKey: string;
  notifyEmails: string;
  disabledScanners: ScannerName[];
  aiEnabled: boolean;
}

function toForm(r: RepositoryDto): FormState {
  return {
    active: r.active,
    teamId: r.teamId ?? '',
    criticality: r.criticality,
    branch: r.branch ?? '',
    preset: r.schedule.preset,
    cron: r.schedule.cron ?? '',
    scanOnPush: r.scanOnPush,
    jiraProjectKey: r.jiraProjectKey ?? '',
    notifyEmails: r.notifyEmails.join(', '),
    disabledScanners: r.disabledScanners,
    aiEnabled: r.aiEnabled,
  };
}

function SettingsCard({ repo }: { repo: RepositoryDto }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can('repos:manage');
  const teams = useQuery({ queryKey: ['teams'], queryFn: () => api<TeamDto[]>('/teams') });
  const [form, setForm] = useState<FormState>(() => toForm(repo));
  useEffect(() => setForm(toForm(repo)), [repo]);

  const save = useMutation({
    mutationFn: () => {
      const body: RepoUpdateInput = {
        active: form.active,
        teamId: form.teamId || null,
        criticality: form.criticality,
        branch: form.branch.trim() || null,
        schedule: { preset: form.preset, cron: form.preset === 'custom' ? form.cron.trim() : null },
        scanOnPush: form.scanOnPush,
        jiraProjectKey: form.jiraProjectKey.trim().toUpperCase() || null,
        notifyEmails: form.notifyEmails
          .split(/[,;\s]+/)
          .map((e) => e.trim())
          .filter(Boolean),
        disabledScanners: form.disabledScanners,
        aiEnabled: form.aiEnabled,
      };
      return api<RepositoryDto>(`/repos/${repo.id}`, { method: 'PATCH', body });
    },
    onSuccess: (updated) => {
      qc.setQueryData(['repo', repo.id], updated);
      void qc.invalidateQueries({ queryKey: ['repos'] });
      toast.success('Repository settings saved.');
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate();
  };

  return (
    <Card className="lg:col-span-2">
      <CardHeader title="Monitoring settings" description={manage ? undefined : 'Only administrators and security managers can change these settings.'} />
      <form onSubmit={submit} className="space-y-5 p-5">
        <ErrorAlert error={save.error} />
        <fieldset disabled={!manage} className="space-y-5">
          <Checkbox
            label="Monitor this repository"
            description={repo.removed ? 'This repository is no longer available from its source.' : 'Scanned on the schedule below and, if enabled, whenever code is pushed.'}
            checked={form.active}
            disabled={repo.removed}
            onChange={(e) => setForm({ ...form, active: e.target.checked })}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Owning team" hint="Developers and viewers see only their teams' repositories.">
              {(id) => (
                <Select id={id} value={form.teamId} onChange={(e) => setForm({ ...form, teamId: e.target.value })}>
                  <option value="">Unassigned</option>
                  {teams.data?.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Business criticality" hint="Raises or lowers the risk score of this repository's findings.">
              {(id) => (
                <Select id={id} value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value as Criticality })}>
                  {CRITICALITIES.map((c) => (
                    <option key={c} value={c}>
                      {c[0].toUpperCase() + c.slice(1)}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Scan schedule" hint="Preset times are spread out between 01:00 and 06:00 UTC.">
              {(id) => (
                <Select id={id} value={form.preset} onChange={(e) => setForm({ ...form, preset: e.target.value as SchedulePreset })}>
                  {SCHEDULE_PRESETS.map((p) => (
                    <option key={p} value={p}>
                      {SCHEDULE_LABELS[p]}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {form.preset === 'custom' ? (
              <Field label="Cron expression (UTC)" hint="Five fields: minute hour day month weekday. At most every 15 minutes.">
                {(id) => <Input id={id} className="font-mono" placeholder="0 3 * * 1-5" value={form.cron} onChange={(e) => setForm({ ...form, cron: e.target.value })} required />}
              </Field>
            ) : (
              <Field label="Branch" hint={`Leave empty to scan the default branch${repo.defaultBranch ? ` (${repo.defaultBranch})` : ''}.`}>
                {(id) => <Input id={id} value={form.branch} onChange={(e) => setForm({ ...form, branch: e.target.value })} placeholder={repo.defaultBranch ?? 'default branch'} />}
              </Field>
            )}
            {form.preset === 'custom' && (
              <Field label="Branch" hint="Leave empty to scan the default branch.">
                {(id) => <Input id={id} value={form.branch} onChange={(e) => setForm({ ...form, branch: e.target.value })} placeholder={repo.defaultBranch ?? 'default branch'} />}
              </Field>
            )}
            <Field label="Jira project key" hint="Tickets for this repository can be raised in this Jira project.">
              {(id) => <Input id={id} value={form.jiraProjectKey} onChange={(e) => setForm({ ...form, jiraProjectKey: e.target.value })} placeholder="e.g. PAY" />}
            </Field>
            <Field label="Notification recipients" hint="Comma-separated email addresses for alerts about this repository.">
              {(id) => <Input id={id} value={form.notifyEmails} onChange={(e) => setForm({ ...form, notifyEmails: e.target.value })} placeholder="team@example.com" />}
            </Field>
          </div>
          <Checkbox label="Scan on push" description="Requires the source's push webhook to be configured." checked={form.scanOnPush} onChange={(e) => setForm({ ...form, scanOnPush: e.target.checked })} />
          <Checkbox
            label="Allow AI assistance"
            description="When off, nothing from this repository (findings, code snippets, tickets) is sent to an AI provider."
            checked={form.aiEnabled}
            onChange={(e) => setForm({ ...form, aiEnabled: e.target.checked })}
          />
          <div>
            <div className="mb-2 text-sm font-medium text-slate-700 dark:text-slate-300">Scanners</div>
            <div className="grid gap-2 sm:grid-cols-2">
              {SCANNERS.map((s) => (
                <Checkbox
                  key={s}
                  label={SCANNER_LABELS[s]}
                  checked={!form.disabledScanners.includes(s)}
                  onChange={(e) => setForm({ ...form, disabledScanners: e.target.checked ? form.disabledScanners.filter((x) => x !== s) : [...form.disabledScanners, s] })}
                />
              ))}
            </div>
          </div>
        </fieldset>
        {manage && (
          <Button type="submit" loading={save.isPending}>
            Save settings
          </Button>
        )}
      </form>
    </Card>
  );
}

export function RepositoryDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [runsPage, setRunsPage] = useState(1);
  const [openRun, setOpenRun] = useState<string | null>(null);
  // ?tab=pull-requests&scan=<id> is the link Argus puts in pull request comments.
  const [params, setParams] = useSearchParams();
  const tab = (['findings', 'dependencies', 'history', 'pull-requests'] as const).find((t) => t === params.get('tab')) ?? 'findings';
  const setTab = (t: typeof tab) => setParams(t === 'findings' ? {} : { tab: t }, { replace: true });
  const openPrScan = params.get('scan');
  const summary = useQuery({ queryKey: ['findings', 'summary', id], queryFn: () => api<FindingSummary>('/findings/summary', { query: { repoId: id } }) });

  const repo = useQuery({
    queryKey: ['repo', id],
    queryFn: () => api<RepositoryDto>(`/repos/${id}`),
    refetchInterval: (q) => (isActiveScan(q.state.data?.lastScanStatus) || (q.state.data?.active && !q.state.data.lastScanAt) ? 3000 : false),
  });
  const runs = useQuery({
    queryKey: ['repo', id, 'scans', runsPage],
    queryFn: () => api<Paged<ScanRunDto>>(`/repos/${id}/scans`, { query: { page: runsPage, pageSize: RUNS_PAGE_SIZE } }),
    refetchInterval: (q) => (q.state.data?.items.some((r) => isActiveScan(r.status)) ? 3000 : false),
  });
  const scan = useMutation({
    mutationFn: () => api<{ run: ScanRunDto; alreadyQueued: boolean }>(`/repos/${id}/scans`, { method: 'POST' }),
    onSuccess: (res) => {
      toast.success(res.alreadyQueued ? 'A scan is already queued or running.' : 'Scan queued.');
      void qc.invalidateQueries({ queryKey: ['repo', id] });
      setOpenRun(res.run.id);
    },
  });

  if (repo.isLoading) return <CenteredSpinner />;
  if (!repo.data) return <ErrorAlert error={repo.error} />;
  const r = repo.data;

  return (
    <>
      <Link to="/repositories" className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:hover:text-slate-300">
        <ArrowLeft className="size-4" /> Repositories
      </Link>
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight break-all">{r.fullName}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            {r.active ? <Badge tone="green">Monitored</Badge> : <Badge>Not monitored</Badge>}
            <Badge tone={r.visibility === 'public' ? 'amber' : 'slate'}>{r.visibility}</Badge>
            {r.archived && <Badge>Archived</Badge>}
            {r.removed && <Badge tone="red">Removed from source</Badge>}
            <span>{PROVIDER_LABELS[r.provider]}</span>
            {r.htmlUrl && (
              <a href={r.htmlUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-indigo-600 hover:underline dark:text-indigo-400">
                Open <ExternalLink className="size-3" />
              </a>
            )}
          </div>
          {r.description && <p className="mt-2 max-w-2xl text-sm text-slate-600 dark:text-slate-300">{r.description}</p>}
          {summary.data && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
              <span className="text-slate-500">Open findings:</span>
              {summary.data.openTotal === 0 ? (
                <span className="text-green-700 dark:text-green-400">none</span>
              ) : (
                (['critical', 'high', 'medium', 'low', 'info'] as const)
                  .filter((s) => summary.data.open[s] > 0)
                  .map((s) => <SeverityBadge key={s} severity={s} score={summary.data.open[s]} />)
              )}
            </div>
          )}
        </div>
        <div className="flex gap-2">
          {can('reports:read') && (
            <Link to={`/reports?repoId=${r.id}`}>
              <Button variant="secondary">Report</Button>
            </Link>
          )}
          {can('scans:run') && (
            <Button icon={<Play className="size-4" />} loading={scan.isPending} disabled={r.removed || isActiveScan(r.lastScanStatus)} onClick={() => scan.mutate()}>
              {isActiveScan(r.lastScanStatus) ? 'Scan in progress…' : 'Scan now'}
            </Button>
          )}
        </div>
      </div>
      <ErrorAlert error={scan.error} />

      <div className="grid gap-6 lg:grid-cols-3">
        <SettingsCard repo={r} />
        <Card>
          <CardHeader title="Status" />
          <dl className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
            {[
              ['Last scan', <span className="flex items-center gap-2"><ScanStatusBadge status={r.lastScanStatus} />{r.lastScanAt && formatRelative(r.lastScanAt)}</span>],
              ['Next scan', r.nextScanAt ? formatDateTime(r.nextScanAt) : '—'],
              ['Default branch', r.defaultBranch ?? 'Resolved at scan time'],
              ['Language', r.language ?? '—'],
              ['Last push', formatRelative(r.lastPushedAt)],
              ['Discovered', formatDateTime(r.createdAt)],
            ].map(([k, v]) => (
              <div key={k as string} className="flex justify-between gap-4 px-5 py-2.5">
                <dt className="text-slate-500 dark:text-slate-400">{k}</dt>
                <dd className="text-right font-medium">{v}</dd>
              </div>
            ))}
          </dl>
        </Card>

        <Card className="lg:col-span-3">
          <div className="flex gap-1 border-b border-slate-200 px-3 pt-2 dark:border-slate-800" role="tablist">
            {(
              [
                ['findings', 'Findings'],
                ['dependencies', 'Dependencies'],
                ['history', 'Scan history'],
                ['pull-requests', 'Pull requests'],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                role="tab"
                aria-selected={tab === key}
                onClick={() => setTab(key)}
                className={`-mb-px border-b-2 px-3 py-2 text-sm font-medium ${tab === key ? 'border-indigo-600 text-indigo-700 dark:text-indigo-300' : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-300'}`}
              >
                {label}
              </button>
            ))}
          </div>
          {tab === 'findings' && <FindingsTable repoId={r.id} />}
          {tab === 'dependencies' && <DependenciesTable repoId={r.id} />}
          {tab === 'pull-requests' && <PullRequestScansTab repo={r} openScanId={openPrScan} onOpenScan={(scan) => setParams(scan ? { tab: 'pull-requests', scan } : { tab: 'pull-requests' }, { replace: true })} />}
          {tab === 'history' && (
            <>
              <p className="px-5 pt-3 text-xs text-slate-500">Scan runs are kept for 90 days.</p>
              <ErrorAlert error={runs.error} />
              {runs.isLoading ? (
                <CenteredSpinner />
              ) : !runs.data?.items.length ? (
                <EmptyState icon={<History className="size-5" />} title="No scans yet" description={r.active ? 'The first scan starts shortly after monitoring is turned on.' : 'Turn on monitoring or run a scan manually.'} />
              ) : (
                <>
                  <Table head={['Queued', 'Trigger', 'Status', 'Branch / commit', 'Duration', 'Result']}>
                    {runs.data.items.map((run) => (
                      <tr key={run.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => setOpenRun(run.id)}>
                        <td className="px-4 py-2.5 whitespace-nowrap">{formatDateTime(run.queuedAt)}</td>
                        <td className="px-4 py-2.5">{TRIGGER_LABELS[run.trigger]}</td>
                        <td className="px-4 py-2.5">
                          <ScanStatusBadge status={run.status} />
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs">
                          {run.branch ?? '—'}
                          {run.commitSha && <span className="text-slate-500"> @ {run.commitSha.slice(0, 8)}</span>}
                        </td>
                        <td className="px-4 py-2.5">{formatDuration(run.durationMs)}</td>
                        <td className="px-4 py-2.5">
                          {run.error ? (
                            <span className="text-xs text-red-600 dark:text-red-400">{run.error.slice(0, 80)}</span>
                          ) : run.stats?.findings ? (
                            <span className="text-xs">
                              {run.stats.findings.new} new · {run.stats.findings.fixed} fixed
                            </span>
                          ) : (
                            <div className="flex flex-wrap gap-1">{run.stats?.ecosystems.map((e) => <Badge key={e} tone="indigo">{e}</Badge>) ?? '—'}</div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </Table>
                  <Pagination page={runsPage} pageSize={RUNS_PAGE_SIZE} total={runs.data.total} onPage={setRunsPage} />
                </>
              )}
            </>
          )}
        </Card>
      </div>
      {openRun && <ScanRunModal runId={openRun} onClose={() => setOpenRun(null)} />}
    </>
  );
}
