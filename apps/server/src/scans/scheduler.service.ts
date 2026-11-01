import { randomBytes } from 'node:crypto';
import { AuditService } from '../core/audit.service';
import { SettingsService } from '../core/settings.service';
import { hostname } from 'node:os';
import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnApplicationShutdown } from '@nestjs/common';
import { type DataStore } from '@argus/data';
import { AppConfig } from '../config/app-config';
import { DomainEvents } from '../core/domain-events';
import { DATA_STORE } from '../core/tokens';
import { IntelService } from '../scanning/intel.service';
import { SourcesService } from '../sources/sources.service';
import { ScansService } from './scans.service';
import { nextRunAt } from './schedule';

const LOCK_NAME = 'scheduler';
const DUE_BATCH = 200;
const SOURCE_SYNC_INTERVAL_MS = 24 * 60 * 60_000;
const HOUSEKEEPING_INTERVAL_MS = 60 * 60_000;
const JOB_RETENTION_MS = 7 * 24 * 60 * 60_000;
const INTEL_STALE_MS = 7 * 24 * 60 * 60_000;

/**
 * Turns schedules into jobs. Every worker runs this loop, but a database lease ensures that only one
 * instance acts at a time; if it dies, another takes over when the lease expires.
 */
@Injectable()
export class SchedulerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger('Scheduler');
  private readonly owner = `${hostname()}:${process.pid}:${randomBytes(3).toString('hex')}`;
  private timer: NodeJS.Timeout | null = null;
  private ticking = false;
  private lastHousekeeping = 0;

  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly scans: ScansService,
    private readonly sources: SourcesService,
    private readonly config: AppConfig,
    private readonly intel: IntelService,
    private readonly events: DomainEvents,
    private readonly settings: SettingsService,
    private readonly audit: AuditService,
  ) {}

  onApplicationBootstrap(): void {
    if (this.config.role === 'api') return;
    this.timer = setInterval(() => void this.tick(), this.config.schedulerIntervalMs);
    this.timer.unref();
    void this.tick();
  }

  async onApplicationShutdown(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.store.locks.release(LOCK_NAME, this.owner).catch(() => undefined);
  }

  async tick(): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;
    try {
      if (!(await this.store.locks.acquire(LOCK_NAME, this.owner, Math.max(60_000, this.config.schedulerIntervalMs * 3)))) return;
      await this.queueDueScans();
      await this.queueSourceSyncs();
      // SLA checks, Jira sync and digests run on the leader only; each handler throttles itself.
      await this.events.emit('scheduler.tick', { now: new Date() });
      if (Date.now() - this.lastHousekeeping > HOUSEKEEPING_INTERVAL_MS) {
        this.lastHousekeeping = Date.now();
        await this.housekeeping();
      }
    } catch (err) {
      this.logger.error({ err }, 'Scheduler tick failed');
    } finally {
      this.ticking = false;
    }
  }

  private async queueDueScans(): Promise<void> {
    const now = new Date();
    const due = await this.store.repositories.findDue(now, DUE_BATCH);
    for (const repo of due) {
      // A repository activated moments ago has never been scanned: label that first run accordingly.
      const trigger = repo.lastScanAt ? 'schedule' : 'activation';
      await this.scans.enqueue(repo, trigger, null);
      await this.store.repositories.update(repo.id, { nextScanAt: nextRunAt(repo.schedule, repo.id, now) });
    }
    if (due.length) this.logger.log(`Queued ${due.length} scheduled scan(s)`);
  }

  private async queueSourceSyncs(): Promise<void> {
    const cutoff = Date.now() - SOURCE_SYNC_INTERVAL_MS;
    for (const s of await this.store.sources.list()) {
      if (!s.lastSyncAt || s.lastSyncAt.getTime() < cutoff) await this.sources.enqueueSync(s.id);
    }
  }

  private async housekeeping(): Promise<void> {
    const r = await this.settings.getRetention();
    const ago = (days: number) => new Date(Date.now() - days * 86_400_000);
    const jobs = await this.store.jobs.deleteFinishedBefore(new Date(Date.now() - JOB_RETENTION_MS));
    // Expired intel is kept for a week so scans can fall back to it while a feed is unreachable.
    const cache = await this.store.cache.deleteExpired(new Date(Date.now() - INTEL_STALE_MS));
    // Data retention (Administration → Scanning settings).
    const removed = {
      scanRuns: await this.store.scanRuns.deleteFinishedBefore(ago(r.scanRunsDays)),
      prScans: await this.store.prScans.deleteFinishedBefore(ago(r.scanRunsDays)),
      fixedFindings: r.fixedFindingsDays === null ? 0 : await this.store.findings.deleteFixedBefore(ago(r.fixedFindingsDays)),
      auditEntries: r.auditDays === null ? 0 : await this.store.audit.deleteBefore(ago(r.auditDays)),
      intelItems: await this.store.intelItems.deleteSettledBefore(ago(r.intelItemsDays)),
      aiUsage: await this.store.aiUsage.deleteBefore(ago(r.aiUsageDays)),
    };
    if (jobs || cache) this.logger.log(`Housekeeping removed ${jobs} finished job(s) and ${cache} stale intel entries`);
    if (Object.values(removed).some(Boolean)) {
      this.logger.log(`Retention removed ${JSON.stringify(removed)}`);
      await this.audit.record({ action: 'retention.applied', details: { ...removed, settings: r } });
    }
    if (!this.intel.offline) await this.intel.kev().catch((err: unknown) => this.logger.warn(`CISA KEV refresh failed: ${(err as Error).message}`));
  }
}
