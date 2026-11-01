import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { type DataStore, type PrScan, type Repository, type User } from '@argus/data';
import { type Paged, type PrScanDto, type PrScanRequest } from '@argus/shared';
import { AuditService } from '../core/audit.service';
import { type RequestContext } from '../common/request';
import { AppConfig } from '../config/app-config';
import { DATA_STORE } from '../core/tokens';
import { JobRunner } from '../jobs/job-runner.service';
import { canSeeRepo, visibleTeams } from '../scans/scans.service';
import { ProviderError } from '../sources/providers';
import { SourcesService } from '../sources/sources.service';

export const PR_SCAN_JOB = 'pr.scan';
/** Same priority as a scan someone started by hand: a developer is waiting on the pipeline. */
const PR_SCAN_PRIORITY = 10;

@Injectable()
export class PrScansService {
  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly sources: SourcesService,
    private readonly runner: JobRunner,
    private readonly audit: AuditService,
    private readonly config: AppConfig,
  ) {}

  /** The Argus page for a scan; relative when Argus does not know its public address. */
  argusUrl(scan: Pick<PrScan, 'id' | 'repoId'>): string {
    return `${this.config.publicUrl ?? ''}/repositories/${scan.repoId}?tab=pull-requests&scan=${scan.id}`;
  }

  toDto(s: PrScan, repoFullName: string | null): PrScanDto {
    return {
      id: s.id,
      repoId: s.repoId,
      repoFullName,
      number: s.number,
      title: s.title,
      url: s.url,
      headSha: s.headSha,
      headBranch: s.headBranch,
      baseBranch: s.baseBranch,
      status: s.status,
      failOn: s.failOn,
      gate: s.result?.gate ?? null,
      result: s.result,
      commentUrl: s.commentUrl,
      error: s.error,
      argusUrl: this.argusUrl(s),
      createdAt: s.createdAt.toISOString(),
      startedAt: s.startedAt?.toISOString() ?? null,
      finishedAt: s.finishedAt?.toISOString() ?? null,
    };
  }

  /** The repository a CI pipeline names, among those the token's owner can see. */
  private async findRepository(name: string, sourceId: string | undefined, user: User): Promise<Repository> {
    const wanted = name.trim().replace(/\.git$/i, '').toLowerCase();
    const page = await this.store.repositories.list({ search: wanted, sourceId, visibleTeamIds: visibleTeams(user), offset: 0, limit: 100 });
    const matches = page.items.filter((r) => r.fullName.toLowerCase() === wanted && !r.removedAt);
    if (!matches.length) throw new NotFoundException(`Argus does not know the repository ${name}, or this token cannot see it. Check the name (as Argus shows it), sync its source, and check the token owner's team.`);
    if (matches.length > 1) throw new BadRequestException(`${name} exists in more than one source. Add "sourceId" to the request to choose one.`);
    return matches[0];
  }

  async request(input: PrScanRequest, actor: User, ctx: RequestContext): Promise<{ scan: PrScanDto; created: boolean }> {
    const repo = await this.findRepository(input.repository, input.sourceId, actor);
    if (!repo.active) throw new ConflictException(`${repo.fullName} is not monitored by Argus. Activate it under Repositories first.`);
    const source = await this.store.sources.findById(repo.sourceId);
    if (!source) throw new NotFoundException('The repository\'s source no longer exists.');

    // The pull request is read with the source's own credentials: nothing the caller sends is trusted.
    let pr;
    try {
      pr = await this.sources.clientFor(source).pullRequest(repo.fullName, input.pullRequest);
    } catch (err) {
      if (err instanceof ProviderError && err.status === 404) throw new NotFoundException(`Pull request #${input.pullRequest} was not found in ${repo.fullName}.`);
      if (err instanceof ProviderError) throw new BadRequestException(`Could not read pull request #${input.pullRequest}: ${err.message}`);
      throw err;
    }
    if (pr.state !== 'open') throw new ConflictException(`Pull request #${pr.number} is ${pr.state}; only open pull requests are scanned.`);

    const active = await this.store.prScans.findActive(repo.id, pr.number, pr.headSha);
    if (active) return { scan: this.toDto(active, repo.fullName), created: false };

    const scan = await this.store.prScans.create({
      repoId: repo.id,
      sourceId: repo.sourceId,
      number: pr.number,
      title: pr.title.slice(0, 500),
      url: pr.url,
      headSha: pr.headSha,
      headBranch: pr.headBranch,
      baseBranch: pr.baseBranch,
      failOn: input.failOn,
      comment: input.comment,
      requestedBy: actor.id,
    });
    await this.store.jobs.enqueue({ type: PR_SCAN_JOB, payload: { prScanId: scan.id }, dedupeKey: `pr-scan:${scan.id}`, priority: PR_SCAN_PRIORITY, maxAttempts: 2 });
    this.runner.poke();
    await this.audit.record({ action: 'pr_scan.requested', actor, target: { type: 'repository', id: repo.id }, details: { repo: repo.fullName, pullRequest: pr.number, headSha: pr.headSha, failOn: input.failOn }, ip: ctx.ip });
    return { scan: this.toDto(scan, repo.fullName), created: true };
  }

  private async visibleRepo(repoId: string, user: User): Promise<Repository> {
    const repo = await this.store.repositories.findById(repoId);
    if (!repo || !canSeeRepo(user, repo)) throw new NotFoundException('Pull request scan not found.');
    return repo;
  }

  async get(id: string, user: User): Promise<PrScanDto> {
    const scan = await this.store.prScans.findById(id);
    if (!scan) throw new NotFoundException('Pull request scan not found.');
    const repo = await this.visibleRepo(scan.repoId, user);
    return this.toDto(scan, repo.fullName);
  }

  async list(repoId: string, q: { page: number; pageSize: number }, user: User): Promise<Paged<PrScanDto>> {
    const repo = await this.visibleRepo(repoId, user);
    const page = await this.store.prScans.listForRepo(repo.id, { offset: (q.page - 1) * q.pageSize, limit: q.pageSize });
    return { items: page.items.map((s) => this.toDto(s, repo.fullName)), total: page.total, page: q.page, pageSize: q.pageSize };
  }
}
