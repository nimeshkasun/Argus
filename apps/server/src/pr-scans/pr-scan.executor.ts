import { mkdir, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { type DataStore, type Job, type PrScan, type PrScanPatch } from '@argus/data';
import { type PrScanResult } from '@argus/shared';
import { AiService } from '../ai/ai.service';
import { Redactor } from '../common/redact';
import { AppConfig } from '../config/app-config';
import { DATA_STORE } from '../core/tokens';
import { type JobContext, JobRunner, PermanentJobError } from '../jobs/job-runner.service';
import { ScanPipeline } from '../scanning/scan-pipeline.service';
import { GitError, runGit } from '../scans/git';
import { walkFiles } from '../scans/inventory';
import { assertCloneUrlAllowed, MAX_PR_FILES, ProviderError } from '../sources/providers';
import { SourcesService } from '../sources/sources.service';
import { suggestFixes } from './pr-ai';
import { buildResult, pullRequestDelta } from './pr-analysis';
import { renderPrComment } from './pr-comment';
import { PR_SCAN_JOB, PrScansService } from './pr-scans.service';

const MAX_LOG_LINES = 300;
const MAX_READ_BYTES = 1024 * 1024;

/**
 * Executes `pr.scan` jobs: fetches the pull request's head into an ephemeral workspace, runs the scanners without
 * storing their findings, keeps the issues the pull request introduces, and posts (or updates) one comment on it.
 */
@Injectable()
export class PrScanExecutor implements OnModuleInit {
  private readonly logger = new Logger('PrScanExecutor');

  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly sources: SourcesService,
    private readonly runner: JobRunner,
    private readonly config: AppConfig,
    private readonly pipeline: ScanPipeline,
    private readonly ai: AiService,
    private readonly scans: PrScansService,
  ) {}

  onModuleInit(): void {
    // Like repository scans, pull request scans only run on instances that scan (SCAN=true).
    if (this.config.scanEnabled) this.runner.register(PR_SCAN_JOB, (job, ctx) => this.execute(job, ctx));
  }

  async execute(job: Job, jobCtx: JobContext): Promise<void> {
    const scan = await this.store.prScans.findById(String(job.payload.prScanId));
    if (!scan || scan.status === 'succeeded' || scan.status === 'failed') return;
    const repo = await this.store.repositories.findById(scan.repoId);
    const source = repo ? await this.store.sources.findById(repo.sourceId) : null;

    const lines = [...scan.log];
    let redactor = new Redactor();
    const log = (message: string) => {
      if (lines.length < MAX_LOG_LINES) lines.push(`${new Date().toISOString()} ${redactor.redact(message)}`);
    };
    const finish = (patch: PrScanPatch) => this.store.prScans.update(scan.id, { ...patch, log: lines, finishedAt: new Date() });

    if (!repo || !source || repo.removedAt) {
      await finish({ status: 'failed', error: 'The repository no longer exists in its source.' });
      return;
    }

    const conn = this.sources.connection(source);
    const client = this.sources.clientFor(source);
    redactor = new Redactor([conn.token]);
    const workdir = join(this.config.scanWorkdir, `pr-${scan.id}`);
    await this.store.prScans.update(scan.id, { status: 'running', startedAt: new Date(), error: null });
    log(`Pull request scan started (attempt ${job.attempts} of ${job.maxAttempts}) for ${repo.fullName} #${scan.number}`);

    try {
      // Read again: the pull request may have moved on since the request.
      const pr = await client.pullRequest(repo.fullName, scan.number);
      const cloneUrl = assertCloneUrlAllowed(client, pr.fetch.cloneUrl ?? repo.cloneUrl);
      const authHeader = await client.gitAuthHeader();
      const encoded = authHeader.replace(/^Authorization:\s*\S+\s+/, '');
      const decodedSecret = /^Authorization:\s*Basic\s/i.test(authHeader) ? Buffer.from(encoded, 'base64').toString('utf8').split(':').slice(1).join(':') : null;
      redactor = new Redactor([conn.token, authHeader, encoded, decodedSecret]);

      await mkdir(this.config.scanWorkdir, { recursive: true });
      await rm(workdir, { recursive: true, force: true });
      log(`Fetching ${pr.fetch.ref} from ${cloneUrl.host}${cloneUrl.pathname}`);
      const git = (args: string[], cwd?: string) => runGit(args, { cwd, home: this.config.scanWorkdir, authHeader, timeoutMs: this.config.scanTimeoutMs });
      await git(['-c', 'init.defaultBranch=argus', 'init', '--quiet', workdir]);
      const fetch = (depth: string[]) => git(['-c', 'core.symlinks=false', 'fetch', ...depth, '--no-tags', '--quiet', '--', cloneUrl.toString(), pr.fetch.ref], workdir);
      try {
        await fetch(['--depth', '1']);
      } catch (err) {
        // Some servers (and git's "dumb" HTTP protocol) cannot do shallow fetches.
        if (!(err instanceof GitError && /shallow/i.test(err.stderr))) throw err;
        log('Server does not support shallow fetches; fetching the full history of the pull request');
        await fetch([]);
      }
      await git(['-c', 'core.symlinks=false', '-c', 'advice.detachedHead=false', 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], workdir);
      const headSha = await git(['rev-parse', 'HEAD'], workdir);
      log(`Checked out ${headSha}${pr.headSha && !headSha.startsWith(pr.headSha) && !pr.headSha.startsWith(headSha) ? ` (the provider reported ${pr.headSha}; the pull request changed while it was fetched)` : ''}`);

      let changed: string[] | null = null;
      try {
        changed = await client.pullRequestFiles(repo.fullName, scan.number);
        if (changed.length >= MAX_PR_FILES) {
          log(`The pull request changes ${MAX_PR_FILES} or more files; every file is treated as changed`);
          changed = null;
        }
      } catch (err) {
        log(`Could not list the changed files (${err instanceof Error ? err.message : String(err)}); every file is treated as changed`);
      }

      const files = await walkFiles(workdir);
      // Only the pull request's own code: git history is not fetched, so history scanning is off.
      const analysis = await this.pipeline.analyze(repo, workdir, files, log, { secretHistoryCommits: 0 });
      for (const w of analysis.warnings) log(`Warning: ${w}`);
      const baseline = await this.store.findings.listAllForRepo(repo.id);
      if (!baseline.length && repo.lastScanAt === null) log('The repository has not been scanned yet, so every issue in the changed files counts as new');
      const delta = pullRequestDelta(analysis.observed, baseline, changed ? new Set(changed) : null);

      const byPath = new Map(analysis.files.map((f) => [f.path, f]));
      const readRepoFile = async (path: string) => {
        const f = byPath.get(path);
        return f && f.size <= MAX_READ_BYTES ? readFile(f.abs, 'utf8').catch(() => null) : null;
      };
      const ai = await suggestFixes(this.ai, repo, delta.introduced, readRepoFile, [...analysis.secretValues.values()], log).catch((err: unknown) => {
        log(`AI fix suggestions failed: ${err instanceof Error ? err.message : String(err)}`);
        return new Map();
      });

      const result = buildResult(delta, { changedFiles: changed?.length ?? files.length, failOn: scan.failOn, scanners: analysis.results, ai });
      log(`Result: ${delta.introduced.length} new issue(s), gate ${result.gate}; ${delta.existingInChangedFiles} already known in changed files, ${delta.suppressed} suppressed`);
      const patch: PrScanPatch = { status: 'succeeded', headSha, result };
      if (scan.comment) Object.assign(patch, await this.comment(scan, repo.fullName, source.provider, repo.htmlUrl, headSha, result, log));
      await finish(patch);
    } catch (err) {
      const permanent = (err instanceof ProviderError && err.permanent) || (err instanceof GitError && /authentication failed|could not read username|not found|couldn't find remote ref|403/i.test(err.message));
      const message = redactor.redact(err instanceof Error ? err.message : String(err));
      log(`Error: ${message}`);
      if (permanent || jobCtx.finalAttempt) {
        await finish({ status: 'failed', error: message });
        throw new PermanentJobError(message);
      }
      log('Will retry');
      await this.store.prScans.update(scan.id, { status: 'queued', error: message, log: lines });
      throw new Error(message);
    } finally {
      // The checked-out code is never kept.
      await rm(workdir, { recursive: true, force: true, maxRetries: 3 }).catch((err: unknown) => this.logger.error({ err, workdir }, 'Failed to delete pull request scan workspace'));
    }
  }

  /** Posts the summary comment, or updates the one an earlier scan of this pull request posted. Never fails the scan. */
  private async comment(scan: PrScan, fullName: string, provider: 'github' | 'bitbucket_cloud' | 'bitbucket_server', repoUrl: string | null, headSha: string, result: PrScanResult, log: (m: string) => void): Promise<PrScanPatch> {
    const body = renderPrComment(result, { provider, repoUrl, headSha, failOn: scan.failOn, argusUrl: this.config.publicUrl ? this.scans.argusUrl(scan) : null });
    const previous = await this.store.prScans.findLastCommented(scan.repoId, scan.number);
    try {
      const c = await this.sources.clientFor((await this.store.sources.findById(scan.sourceId))!).upsertPullRequestComment(fullName, scan.number, body, previous?.commentId ?? null);
      log(`${previous?.commentId === c.id ? 'Updated' : 'Posted'} the pull request comment`);
      return { commentId: c.id, commentUrl: c.url };
    } catch (err) {
      const message = err instanceof ProviderError && err.status === 403 ? `${err.message} Commenting needs write access to pull requests: see the CI integration guide.` : err instanceof Error ? err.message : String(err);
      log(`Could not comment on the pull request: ${message}`);
      return { result: { ...result, commentError: message } };
    }
  }
}
