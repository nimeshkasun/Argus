import { type Paged, type PrScanDto, type RepositoryDto, SCANNER_LABELS, SEVERITIES } from '@argus/shared';
import { useQuery } from '@tanstack/react-query';
import { Check, Copy, ExternalLink, GitPullRequest } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { api } from '../lib/api';
import { bitbucketPipeline, githubWorkflow } from '../lib/ci-snippets';
import { formatDateTime, formatRelative } from '../lib/utils';
import { SeverityBadge } from './findings';
import { Badge, Button, CenteredSpinner, EmptyState, ErrorAlert, Modal, Pagination, Table } from './ui';

const PAGE_SIZE = 20;

function GateBadge({ scan }: { scan: PrScanDto }) {
  if (scan.status === 'queued' || scan.status === 'running') return <Badge tone="indigo">{scan.status === 'queued' ? 'Queued' : 'Scanning…'}</Badge>;
  if (scan.status === 'failed') return <Badge tone="red">Error</Badge>;
  return scan.gate === 'passed' ? <Badge tone="green">Passed</Badge> : <Badge tone="red">Failed</Badge>;
}

function newIssues(scan: PrScanDto): number {
  return scan.result ? SEVERITIES.reduce((n, s) => n + scan.result!.counts[s], 0) : 0;
}

function CopyBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <pre className="max-h-80 overflow-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100">{text}</pre>
      <Button
        type="button"
        size="sm"
        variant="secondary"
        className="absolute top-2 right-2"
        icon={copied ? <Check className="size-4" /> : <Copy className="size-4" />}
        onClick={() => {
          void navigator.clipboard?.writeText(text).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? 'Copied' : 'Copy'}
      </Button>
    </div>
  );
}

export function PrSetupGuide({ repo }: { repo: RepositoryDto }) {
  const argusUrl = window.location.origin;
  const [kind, setKind] = useState<'github' | 'bitbucket'>(repo.provider === 'github' ? 'github' : 'bitbucket');
  return (
    <div className="space-y-3 text-sm">
      <ol className="list-decimal space-y-1 pl-5 text-slate-600 dark:text-slate-300">
        <li>
          Create an API token under <Link to="/profile" className="text-indigo-600 hover:underline dark:text-indigo-400">your profile</Link> with the <strong>CI pull request scans</strong> preset (scopes <code>scans:run</code> and <code>repos:read</code>). Its owner must be able to see this repository.
        </li>
        <li>
          Store it as a secret named <code>ARGUS_TOKEN</code> in {kind === 'github' ? 'the repository or organisation secrets' : 'the repository or workspace variables (secured)'}.
        </li>
        <li>Add the pipeline step below. It requests a scan of the pull request, waits for it, and fails the build when a new issue reaches the gate (high by default).</li>
        <li>
          For the comment on the pull request, the source&apos;s credentials in Argus need write access to pull requests (
          <Link to="/docs/features/pull-request-scans#1-let-argus-comment" className="text-indigo-600 hover:underline dark:text-indigo-400">
            which permission
          </Link>
          ).
        </li>
      </ol>
      <div className="flex gap-1">
        <Button type="button" size="sm" variant={kind === 'github' ? 'primary' : 'secondary'} onClick={() => setKind('github')}>
          GitHub Actions
        </Button>
        <Button type="button" size="sm" variant={kind === 'bitbucket' ? 'primary' : 'secondary'} onClick={() => setKind('bitbucket')}>
          Bitbucket Pipelines
        </Button>
      </div>
      <CopyBlock text={kind === 'github' ? githubWorkflow(argusUrl) : bitbucketPipeline(argusUrl)} />
      <p className="text-xs text-slate-500">
        The repository is identified as Argus names it ({repo.fullName}), and the pull request by its number. Any CI system can call the same API: see{' '}
        <Link to="/docs/features/pull-request-scans" className="text-indigo-600 hover:underline dark:text-indigo-400">
          Pull request scans
        </Link>
        .
      </p>
    </div>
  );
}

function PrScanModal({ scanId, onClose }: { scanId: string; onClose(): void }) {
  const q = useQuery({
    queryKey: ['pr-scan', scanId],
    queryFn: () => api<PrScanDto>(`/ci/pull-requests/${scanId}`),
    refetchInterval: (query) => (query.state.data?.status === 'queued' || query.state.data?.status === 'running' ? 3000 : false),
  });
  const s = q.data;
  return (
    <Modal open onClose={onClose} wide title={s ? `Pull request #${s.number}${s.title ? `: ${s.title}` : ''}` : 'Pull request scan'} description={s ? `${s.headBranch ?? '?'} → ${s.baseBranch ?? '?'}${s.headSha ? ` · ${s.headSha.slice(0, 12)}` : ''}` : undefined}>
      <ErrorAlert error={q.error} />
      {!s ? (
        <CenteredSpinner />
      ) : (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <GateBadge scan={s} />
            <span className="text-slate-500">gate {s.failOn === 'never' ? 'reports only' : `fails on ${s.failOn} or above`}</span>
            {s.url && (
              <a href={s.url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-indigo-600 hover:underline dark:text-indigo-400">
                Pull request <ExternalLink className="size-3" />
              </a>
            )}
            {s.commentUrl && (
              <a href={s.commentUrl} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 text-indigo-600 hover:underline dark:text-indigo-400">
                Comment <ExternalLink className="size-3" />
              </a>
            )}
          </div>
          {s.error && <p className="rounded-md bg-red-50 p-3 text-red-700 dark:bg-red-500/10 dark:text-red-300">{s.error}</p>}
          {s.result?.commentError && <p className="rounded-md bg-amber-50 p-3 text-amber-800 dark:bg-amber-500/10 dark:text-amber-300">The comment could not be posted: {s.result.commentError}</p>}
          {s.result && (
            <>
              <p className="text-slate-600 dark:text-slate-300">
                {newIssues(s)} new issue(s) in {s.result.changedFiles} changed file(s). {s.result.existingInChangedFiles} already known issue(s) in those files and {s.result.suppressed} suppressed one(s) are not counted.
              </p>
              {s.result.findings.length > 0 && (
                <Table head={['Severity', 'Issue', 'Location', 'Fix']}>
                  {s.result.findings.map((f, i) => (
                    <tr key={i} className="align-top">
                      <td className="px-4 py-2">
                        <SeverityBadge severity={f.severity} score={f.riskScore} />
                      </td>
                      <td className="px-4 py-2">
                        <div className="font-medium">{f.title}</div>
                        <div className="text-xs text-slate-500">{SCANNER_LABELS[f.scanner]}</div>
                      </td>
                      <td className="px-4 py-2 font-mono text-xs">{f.path ? `${f.path}${f.line ? `:${f.line}` : ''}` : '—'}</td>
                      <td className="max-w-sm px-4 py-2 text-xs">
                        {f.fixCommand && <code className="block break-all">{f.fixCommand}</code>}
                        {f.ai && <div className="mt-1 text-slate-600 dark:text-slate-300">AI: {f.ai.summary}</div>}
                        {!f.fixCommand && !f.ai && (f.remediation ?? '—')}
                      </td>
                    </tr>
                  ))}
                </Table>
              )}
              {s.result.truncated && <p className="text-xs text-slate-500">Only the {s.result.findings.length} most severe issues are listed.</p>}
              <div className="flex flex-wrap gap-1">
                {s.result.scanners.map((r) => (
                  <Badge key={r.scanner} tone={r.status === 'ok' ? 'slate' : r.status === 'skipped' ? 'slate' : 'amber'}>
                    {SCANNER_LABELS[r.scanner]}: {r.status}
                  </Badge>
                ))}
              </div>
            </>
          )}
          <p className="text-xs text-slate-500">
            Requested {formatDateTime(s.createdAt)}
            {s.finishedAt && ` · finished ${formatRelative(s.finishedAt)}`}. Pull request scans are a preview: their findings are not added to the repository.
          </p>
        </div>
      )}
    </Modal>
  );
}

/** Pull request scans requested from CI, with the setup guide. */
export function PullRequestScansTab({ repo, openScanId, onOpenScan }: { repo: RepositoryDto; openScanId: string | null; onOpenScan(id: string | null): void }) {
  const [page, setPage] = useState(1);
  const [setup, setSetup] = useState(false);
  const list = useQuery({
    queryKey: ['pr-scans', repo.id, page],
    queryFn: () => api<Paged<PrScanDto>>('/ci/pull-requests', { query: { repoId: repo.id, page, pageSize: PAGE_SIZE } }),
    refetchInterval: (q) => (q.state.data?.items.some((s) => s.status === 'queued' || s.status === 'running') ? 3000 : false),
  });
  return (
    <>
      <div className="flex items-center justify-between gap-3 px-5 pt-3">
        <p className="text-xs text-slate-500">Scans requested by CI pipelines for pull requests. Only issues a pull request introduces are reported, on the pull request itself.</p>
        <Button size="sm" variant="secondary" onClick={() => setSetup(!setup)}>
          {setup ? 'Hide setup' : 'Set up CI'}
        </Button>
      </div>
      {setup && (
        <div className="px-5 pt-3">
          <PrSetupGuide repo={repo} />
        </div>
      )}
      <ErrorAlert error={list.error} />
      {list.isLoading ? (
        <CenteredSpinner />
      ) : !list.data?.items.length ? (
        !setup && <EmptyState icon={<GitPullRequest className="size-5" />} title="No pull request scans yet" description="Add the Argus step to this repository's CI pipeline to scan each pull request." action={<Button size="sm" onClick={() => setSetup(true)}>Set up CI</Button>} />
      ) : (
        <>
          <Table head={['Pull request', 'Commit', 'Result', 'New issues', 'Requested']}>
            {list.data.items.map((s) => (
              <tr key={s.id} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={() => onOpenScan(s.id)}>
                <td className="px-4 py-2.5">
                  <span className="font-mono text-xs text-slate-500">#{s.number}</span> {s.title}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{s.headSha?.slice(0, 8) ?? '—'}</td>
                <td className="px-4 py-2.5">
                  <GateBadge scan={s} />
                </td>
                <td className="px-4 py-2.5">{s.result ? newIssues(s) : '—'}</td>
                <td className="px-4 py-2.5 whitespace-nowrap text-slate-500">{formatRelative(s.createdAt)}</td>
              </tr>
            ))}
          </Table>
          <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={setPage} />
        </>
      )}
      {openScanId && <PrScanModal scanId={openScanId} onClose={() => onOpenScan(null)} />}
    </>
  );
}
