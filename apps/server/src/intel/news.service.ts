import { BadRequestException, Inject, Injectable, Logger, NotFoundException, type OnModuleInit } from '@nestjs/common';
import { type Advisory, type DataStore, type IntelItem, type IntelSource, type Job, type User } from '@argus/data';
import {
  type AdvisoryExtractionOutput,
  type AdvisoryInput,
  advisoryExtractionOutputSchema,
  DEFAULT_INTEL_SOURCES,
  ECOSYSTEMS,
  type IntelItemDto,
  type IntelOverviewDto,
  type IntelReviewInput,
  type IntelSettings,
  type IntelSourceDto,
  type IntelSourceInput,
  type ListIntelItemsQuery,
  type Paged,
} from '@argus/shared';
import { AiService } from '../ai/ai.service';
import { type OutputSpec } from '../ai/output-schemas';
import { type RequestContext } from '../common/request';
import { AppConfig } from '../config/app-config';
import { AuditService } from '../core/audit.service';
import { DomainEvents } from '../core/domain-events';
import { SettingsService } from '../core/settings.service';
import { DATA_STORE } from '../core/tokens';
import { JobRunner, PermanentJobError } from '../jobs/job-runner.service';
import { isValidRange } from '../scanning/versions';
import { parseFeed } from './feed-parser';
import { RematchService } from './rematch.service';

export const CRAWL_JOB = 'intel.crawl';
export const EXTRACT_JOB = 'intel.extract';
const SEEDED_KEY = 'intel.sourcesSeeded';
const FETCH_TIMEOUT_MS = 30_000;
const MAX_FEED_BYTES = 5 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const EXTRACT_BATCH = 10;
const CVE = /^CVE-\d{4}-\d{4,}$/;

const str = { type: 'string' };
const EXTRACTION_OUTPUT: OutputSpec<AdvisoryExtractionOutput> = {
  name: 'advisory_extraction',
  schema: {
    type: 'object',
    additionalProperties: false,
    required: ['relevant', 'advisories', 'rationale', 'confidence'],
    properties: {
      relevant: { type: 'boolean', description: 'true only if the item announces a vulnerability in a package published on npm, NuGet, PyPI, Maven Central, the Go module proxy or crates.io.' },
      advisories: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['ecosystem', 'packageName', 'affectedRange', 'fixedVersion', 'severity', 'cveIds', 'title', 'summary'],
          properties: {
            ecosystem: { type: 'string', enum: [...ECOSYSTEMS] },
            packageName: { ...str, description: 'Exact package id as published: an npm or NuGet id, a PyPI project name, "groupId:artifactId" for Maven, a Go module path or a crate name.' },
            affectedRange: { ...str, description: 'Range of vulnerable versions with comparators separated by spaces, e.g. "<4.17.21" or ">=2.0.0 <2.3.1" (npm-style for npm, NuGet, Go and Cargo).' },
            fixedVersion: { anyOf: [str, { type: 'null' }] },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            cveIds: { type: 'array', items: str },
            title: str,
            summary: str,
          },
        },
      },
      rationale: str,
      confidence: { type: 'number', description: 'From 0 to 1.' },
    },
  },
  validate: advisoryExtractionOutputSchema,
};

const EXTRACTION_INSTRUCTIONS = [
  'Below is an item from a security news or advisory feed. Identify vulnerabilities it announces in packages published on npm, NuGet, PyPI, Maven Central, the Go module proxy or crates.io.',
  'For each affected package give the exact package id, an npm-style range of the vulnerable versions, the first fixed version (or null), a severity, any CVE ids, a short title and a summary.',
  'Products that are not npm or NuGet packages (operating systems, the Node.js or .NET runtimes themselves, SaaS products, browsers) are out of scope: report them only if the item names an affected npm or NuGet package.',
  'If the item does not announce such a vulnerability, set relevant to false and return no advisories. Never invent package names, versions or CVE ids that are not in the item.',
].join('\n');

function sourceDto(s: IntelSource): IntelSourceDto {
  return { ...s, lastFetchedAt: s.lastFetchedAt?.toISOString() ?? null, createdAt: s.createdAt.toISOString(), updatedAt: s.updatedAt.toISOString() };
}

/**
 * Security news: fetches RSS/Atom feeds on a schedule, asks AI (when enabled) to extract npm/NuGet advisories into
 * a review queue, and turns approved ones into Argus advisories that are matched against every repository.
 */
@Injectable()
export class NewsService implements OnModuleInit {
  private readonly logger = new Logger('IntelNews');

  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly ai: AiService,
    private readonly rematch: RematchService,
    private readonly settings: SettingsService,
    private readonly audit: AuditService,
    private readonly events: DomainEvents,
    private readonly runner: JobRunner,
    private readonly config: AppConfig,
  ) {}

  onModuleInit(): void {
    this.runner.register(CRAWL_JOB, (job) => this.crawlJob(job));
    this.runner.register(EXTRACT_JOB, () => this.extractBatch());
    // The scheduler runs on one worker at a time, so seeding and due checks never race.
    this.events.on('scheduler.tick', async ({ now }) => {
      await this.seedDefaults();
      await this.enqueueDue(now);
    });
  }

  private async seedDefaults(): Promise<void> {
    if (await this.settings.getSystemValue<boolean>(SEEDED_KEY)) return;
    await this.settings.setSystemValue(SEEDED_KEY, true);
    if ((await this.store.intelSources.list()).length) return;
    for (const s of DEFAULT_INTEL_SOURCES) await this.store.intelSources.create(s);
  }

  private async enqueueDue(now: Date): Promise<void> {
    if (this.config.offline || !(await this.rematch.intelSettings()).crawlEnabled) return;
    for (const s of await this.store.intelSources.list()) {
      if (!s.enabled) continue;
      if (s.lastFetchedAt && now.getTime() - s.lastFetchedAt.getTime() < s.intervalMinutes * 60_000) continue;
      await this.store.jobs.enqueue({ type: CRAWL_JOB, payload: { sourceId: s.id }, dedupeKey: `intel:crawl:${s.id}`, priority: 0, maxAttempts: 1 });
      this.runner.poke();
    }
  }

  // ------------------------------------------------------------------ sources

  async listSources(): Promise<IntelSourceDto[]> {
    return (await this.store.intelSources.list()).map(sourceDto);
  }

  async createSource(input: IntelSourceInput, actor: User, ctx: RequestContext): Promise<IntelSourceDto> {
    const s = await this.store.intelSources.create(input);
    await this.audit.record({ action: 'intel.source_created', actor, target: { type: 'intel_source', id: s.id }, details: { name: s.name, url: s.url }, ip: ctx.ip });
    return sourceDto(s);
  }

  async updateSource(id: string, input: IntelSourceInput, actor: User, ctx: RequestContext): Promise<IntelSourceDto> {
    if (!(await this.store.intelSources.findById(id))) throw new NotFoundException('Source not found.');
    const s = (await this.store.intelSources.update(id, input))!;
    await this.audit.record({ action: 'intel.source_updated', actor, target: { type: 'intel_source', id }, details: { name: s.name, url: s.url, enabled: s.enabled }, ip: ctx.ip });
    return sourceDto(s);
  }

  async deleteSource(id: string, actor: User, ctx: RequestContext): Promise<void> {
    const s = await this.store.intelSources.findById(id);
    if (!s || !(await this.store.intelSources.delete(id))) throw new NotFoundException('Source not found.');
    await this.audit.record({ action: 'intel.source_deleted', actor, target: { type: 'intel_source', id }, details: { name: s.name }, ip: ctx.ip });
  }

  /** Fetches a source now and reports the outcome. */
  async fetchNow(id: string): Promise<IntelSourceDto> {
    const s = await this.store.intelSources.findById(id);
    if (!s) throw new NotFoundException('Source not found.');
    await this.crawl(s);
    return sourceDto((await this.store.intelSources.findById(id))!);
  }

  // ------------------------------------------------------------------ crawling

  /** GET with a size cap and HTTPS-only redirects (a feed URL must not bounce to a plain-HTTP or non-web address). */
  private async fetchFeed(url: string): Promise<string> {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await fetch(current, { redirect: 'manual', headers: { Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5', 'User-Agent': 'Argus' }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        await res.body?.cancel().catch(() => undefined);
        const next = new URL(res.headers.get('location')!, current);
        if (next.protocol !== 'https:' && !/^(localhost|127\.0\.0\.1|\[::1\])$/.test(next.hostname)) throw new Error(`Refused redirect to ${next.protocol}//${next.host}`);
        current = next.toString();
        continue;
      }
      if (!res.ok) {
        await res.body?.cancel().catch(() => undefined);
        throw new Error(`${new URL(current).host} returned HTTP ${res.status}`);
      }
      if (Number(res.headers.get('content-length') ?? 0) > MAX_FEED_BYTES) throw new Error('Feed is larger than 5 MB.');
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_FEED_BYTES) throw new Error('Feed is larger than 5 MB.');
      return buf.toString('utf8');
    }
    throw new Error('Too many redirects.');
  }

  private async crawlJob(job: Job): Promise<void> {
    const s = await this.store.intelSources.findById(String(job.payload.sourceId));
    if (!s) throw new PermanentJobError('Source no longer exists.');
    await this.crawl(s);
  }

  async crawl(s: IntelSource): Promise<number> {
    if (this.config.offline) {
      await this.store.intelSources.update(s.id, { lastFetchedAt: new Date(), lastError: 'Argus is running in offline mode (ARGUS_OFFLINE=true).' });
      return 0;
    }
    try {
      const entries = parseFeed(await this.fetchFeed(s.url));
      const added = await this.store.intelItems.insertNew(entries.map((e) => ({ ...e, sourceId: s.id })));
      await this.store.intelSources.update(s.id, { lastFetchedAt: new Date(), lastError: null, lastNewItems: added.length });
      if (added.length && (await this.ai.canRun('advisory_extraction', null))) await this.enqueueExtraction();
      return added.length;
    } catch (err) {
      const message = (err instanceof Error ? ((err.cause as Error | undefined)?.message ?? err.message) : String(err)).slice(0, 500);
      await this.store.intelSources.update(s.id, { lastFetchedAt: new Date(), lastError: message, lastNewItems: null });
      this.logger.warn(`Feed ${s.name} failed: ${message}`);
      return 0;
    }
  }

  // ------------------------------------------------------------------ AI extraction

  async enqueueExtraction(): Promise<void> {
    await this.store.jobs.enqueue({ type: EXTRACT_JOB, payload: {}, dedupeKey: 'intel:extract', priority: 0, maxAttempts: 1 });
    this.runner.poke();
  }

  /** Analyses up to a batch of new items, then queues itself again while more remain. */
  async extractBatch(): Promise<void> {
    if (!(await this.ai.canRun('advisory_extraction', null))) return;
    const items = await this.store.intelItems.listByStatus('new', EXTRACT_BATCH);
    const settings = await this.rematch.intelSettings();
    for (const item of items) {
      try {
        await this.extract(item, settings);
      } catch (err) {
        // Budget reached or AI switched off mid-batch: leave the rest for later.
        if (!(await this.ai.canRun('advisory_extraction', null))) return;
        await this.store.intelItems.update(item.id, { status: 'error', error: (err instanceof Error ? err.message : String(err)).slice(0, 500) });
      }
    }
    if (items.length === EXTRACT_BATCH) await this.enqueueExtraction();
  }

  private async extract(item: IntelItem, settings: IntelSettings): Promise<void> {
    const source = await this.store.intelSources.findById(item.sourceId);
    const prompt = ['<context>', `Feed: ${source?.name ?? 'unknown'}`, `Title: ${item.title}`, `Link: ${item.link ?? 'n/a'}`, `Published: ${item.publishedAt?.toISOString() ?? 'unknown'}`, '</context>', '<finding>', item.summary, '</finding>'].join('\n');
    const res = await this.ai.run({ useCase: 'advisory_extraction', repo: null, actor: null, instructions: EXTRACTION_INSTRUCTIONS, prompt, output: EXTRACTION_OUTPUT, subject: { type: 'intel_item', id: item.id } });
    const o = res.output;
    // Keep only proposals Argus can act on: a parseable range and well-formed CVE ids.
    const candidates: AdvisoryInput[] = o.advisories
      .filter((a) => isValidRange(a.ecosystem, a.affectedRange))
      .map((a) => ({ ...a, cveIds: a.cveIds.filter((c) => CVE.test(c)), cvssScore: null, references: item.link && item.link.startsWith('https://') ? [item.link] : [] }));
    const extraction = { provider: res.provider, model: res.model, confidence: o.confidence, rationale: o.rationale, at: new Date() };
    if (!o.relevant || !candidates.length) {
      await this.store.intelItems.update(item.id, { status: 'no_match', candidates: [], extraction, error: null });
      return;
    }
    if (settings.autoApprove && o.confidence >= settings.autoApproveMinConfidence) {
      await this.store.intelItems.update(item.id, { candidates, extraction });
      await this.approve(item, candidates, null, true);
      return;
    }
    await this.store.intelItems.update(item.id, { status: 'review', candidates, extraction, error: null });
  }

  // ------------------------------------------------------------------ review

  async listItems(q: ListIntelItemsQuery): Promise<Paged<IntelItemDto>> {
    const page = await this.store.intelItems.list({ statuses: q.status ? [q.status] : undefined, sourceId: q.sourceId, search: q.search || undefined, offset: (q.page - 1) * q.pageSize, limit: q.pageSize });
    const sources = new Map((await this.store.intelSources.list()).map((s) => [s.id, s.name]));
    const reviewers = new Map(
      (await Promise.all([...new Set(page.items.map((i) => i.reviewedBy).filter((x): x is string => !!x))].map((id) => this.store.users.findById(id)))).filter((u) => !!u).map((u) => [u!.id, u!.displayName]),
    );
    return {
      items: page.items.map((i) => ({
        ...i,
        sourceName: sources.get(i.sourceId) ?? null,
        publishedAt: i.publishedAt?.toISOString() ?? null,
        extraction: i.extraction ? { ...i.extraction, at: i.extraction.at.toISOString() } : null,
        reviewedByName: i.reviewedBy ? (reviewers.get(i.reviewedBy) ?? null) : null,
        reviewedAt: i.reviewedAt?.toISOString() ?? null,
        fetchedAt: i.fetchedAt.toISOString(),
      })),
      total: page.total,
      page: q.page,
      pageSize: q.pageSize,
    };
  }

  async review(id: string, input: IntelReviewInput, actor: User, ctx: RequestContext): Promise<{ status: string; advisoryIds: string[] }> {
    const item = await this.store.intelItems.findById(id);
    if (!item) throw new NotFoundException('Item not found.');
    if (item.status === 'approved') throw new BadRequestException('This item has already been approved.');
    if (input.action === 'reject') {
      await this.store.intelItems.update(id, { status: 'rejected', reviewedBy: actor.id, reviewedAt: new Date() });
      await this.audit.record({ action: 'intel.item_rejected', actor, target: { type: 'intel_item', id }, details: { title: item.title, note: input.note ?? null }, ip: ctx.ip });
      return { status: 'rejected', advisoryIds: [] };
    }
    const advisories = await this.approve(item, input.advisories, actor, false);
    await this.audit.record({ action: 'intel.item_approved', actor, target: { type: 'intel_item', id }, details: { title: item.title, advisories: advisories.map((a) => a.key) }, ip: ctx.ip });
    return { status: 'approved', advisoryIds: advisories.map((a) => a.id) };
  }

  private async approve(item: IntelItem, inputs: AdvisoryInput[], actor: User | null, auto: boolean): Promise<Advisory[]> {
    for (const a of inputs) assertRange(a);
    const created: Advisory[] = [];
    for (const a of inputs) created.push(await this.store.advisories.create({ ...a, source: 'news', sourceItemId: item.id, withdrawn: false, autoApproved: auto, createdBy: actor?.id ?? null }));
    await this.store.intelItems.update(item.id, { status: 'approved', advisoryIds: created.map((a) => a.id), reviewedBy: actor?.id ?? null, reviewedAt: new Date() });
    if (auto) await this.audit.record({ action: 'intel.item_auto_approved', target: { type: 'intel_item', id: item.id }, details: { title: item.title, advisories: created.map((a) => a.key), confidence: item.extraction?.confidence ?? null } });
    await this.rematch.enqueue('advisory');
    return created;
  }

  /** Re-runs AI extraction for an item (e.g. after a failure or a model change). */
  async reanalyse(id: string): Promise<void> {
    const item = await this.store.intelItems.findById(id);
    if (!item) throw new NotFoundException('Item not found.');
    if (item.status === 'approved') throw new BadRequestException('This item has already been approved.');
    if (!(await this.ai.canRun('advisory_extraction', null))) throw new BadRequestException('AI advisory extraction is not available. An administrator can enable it under Administration → AI assistance.');
    await this.store.intelItems.update(id, { status: 'new', error: null });
    await this.extract((await this.store.intelItems.findById(id))!, await this.rematch.intelSettings());
  }

  // ------------------------------------------------------------------ overview

  async overview(): Promise<IntelOverviewDto> {
    const [items, sources, active, lastRematch, emerging, aiExtraction] = await Promise.all([
      this.store.intelItems.countByStatus(),
      this.store.intelSources.list(),
      this.store.advisories.countActive(),
      this.rematch.lastRun(),
      this.rematch.emerging(),
      this.ai.canRun('advisory_extraction', null),
    ]);
    return {
      items,
      sources: { total: sources.length, enabled: sources.filter((s) => s.enabled).length, failing: sources.filter((s) => s.enabled && s.lastError).length },
      advisories: { active },
      lastRematch,
      emerging: emerging.slice(0, 20),
      aiExtraction,
    };
  }
}

export function assertRange(a: Pick<AdvisoryInput, 'ecosystem' | 'affectedRange' | 'packageName'>): void {
  if (!isValidRange(a.ecosystem, a.affectedRange)) throw new BadRequestException({ statusCode: 400, message: `"${a.affectedRange}" is not a valid version range for ${a.packageName}. Use npm-style ranges such as "<4.17.21" or ">=2.0.0 <2.3.1".`, issues: [{ path: 'affectedRange', message: 'Not a valid version range.' }] });
}
