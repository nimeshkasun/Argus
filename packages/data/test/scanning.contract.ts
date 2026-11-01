import { describe, expect, it } from 'vitest';
import { type DataStore, type DiscoveredRepo, type DiscoveryDefaults, type NewSource } from '../src';

const newSource = (over: Partial<NewSource> = {}): NewSource => ({
  name: `src-${Math.random().toString(36).slice(2, 8)}`,
  provider: 'github',
  baseUrl: null,
  scope: 'acme',
  username: null,
  tokenEnc: 'enc',
  tokenLast4: 'abcd',
  webhookSecretEnc: 'enc-secret',
  autoActivatePattern: null,
  defaultTeamId: null,
  ...over,
});

const discovered = (n: number, over: Partial<DiscoveredRepo> = {}): DiscoveredRepo => ({
  externalId: String(n),
  fullName: `acme/repo-${n}`,
  name: `repo-${n}`,
  htmlUrl: `https://github.com/acme/repo-${n}`,
  cloneUrl: `https://github.com/acme/repo-${n}.git`,
  defaultBranch: 'main',
  visibility: 'private',
  language: 'TypeScript',
  description: `Repository ${n}`,
  archived: false,
  lastPushedAt: new Date('2026-01-01T00:00:00Z'),
  ...over,
});

const defaults = (over: Partial<DiscoveryDefaults> = {}): DiscoveryDefaults => ({
  activate: () => false,
  teamId: null,
  schedule: { preset: 'daily' },
  firstScanAt: new Date(),
  ...over,
});

/** Contract cases for sources, repositories, scan runs, jobs and locks. Registered inside the per-adapter describe. */
export function scanningContract(getStore: () => DataStore): void {
  describe('sources & repositories', () => {
    it('creates sources and counts their repositories', async () => {
      const store = getStore();
      const s = await store.sources.create(newSource());
      expect(s.status).toBe('pending');
      await store.repositories.syncFromSource(s.id, [discovered(1), discovered(2)], defaults({ activate: (r) => r.name === 'repo-1' }));
      const listed = (await store.sources.list()).find((x) => x.id === s.id)!;
      expect(listed).toMatchObject({ repoCount: 2, activeRepoCount: 1, tokenLast4: 'abcd' });
      expect((await store.sources.update(s.id, { status: 'ok', lastSyncAt: new Date(), lastSyncError: null }))?.status).toBe('ok');
    });

    it('syncs: adds with defaults, updates changed metadata, marks missing as removed, restores returning repos', async () => {
      const store = getStore();
      const team = await store.teams.create({ name: `Sync team ${Date.now()}`, description: null });
      const s = await store.sources.create(newSource());
      const first = new Date(Date.now() + 60_000);
      const r1 = await store.repositories.syncFromSource(
        s.id,
        [discovered(1), discovered(2), discovered(3, { archived: true }), discovered(1)],
        defaults({ activate: () => true, teamId: team.id, firstScanAt: first }),
      );
      expect(r1).toMatchObject({ added: 3, updated: 0, removed: 0 });
      // Archived repositories are never auto-activated.
      expect(r1.activated).toHaveLength(2);

      const repo1 = (await store.repositories.findByExternalId(s.id, '1'))!;
      expect(repo1).toMatchObject({ active: true, teamId: team.id, criticality: 'medium', schedule: { preset: 'daily' }, scanOnPush: true, notifyEmails: [], removedAt: null });
      expect(repo1.nextScanAt?.getTime()).toBe(first.getTime());
      expect(repo1.lastPushedAt).toBeInstanceOf(Date);

      // Unchanged metadata is not counted as an update; changed metadata is.
      const r2 = await store.repositories.syncFromSource(s.id, [discovered(1), discovered(2, { defaultBranch: 'develop' })], defaults());
      expect(r2).toMatchObject({ added: 0, updated: 1, removed: 1 });
      expect((await store.repositories.findByExternalId(s.id, '2'))?.defaultBranch).toBe('develop');
      const removed = (await store.repositories.findByExternalId(s.id, '3'))!;
      expect(removed.removedAt).toBeInstanceOf(Date);
      expect(removed.active).toBe(false);

      // A repository that reappears is restored but stays inactive.
      const r3 = await store.repositories.syncFromSource(s.id, [discovered(1), discovered(2, { defaultBranch: 'develop' }), discovered(3, { archived: true })], defaults());
      expect(r3).toMatchObject({ added: 0, updated: 1, removed: 0 });
      expect((await store.repositories.findByExternalId(s.id, '3'))?.removedAt).toBeNull();
    });

    it('lists with filters, team scoping and paging; excludes removed by default', async () => {
      const store = getStore();
      const t1 = await store.teams.create({ name: `List A ${Date.now()}`, description: null });
      const t2 = await store.teams.create({ name: `List B ${Date.now()}`, description: null });
      const s = await store.sources.create(newSource());
      await store.repositories.syncFromSource(s.id, [1, 2, 3, 4].map((n) => discovered(n, { fullName: `zz-list/${n}`, description: n === 4 ? 'payments 100%' : null })), defaults());
      const [a, b, c] = await Promise.all(['1', '2', '3'].map((x) => store.repositories.findByExternalId(s.id, x)));
      await store.repositories.update(a!.id, { teamId: t1.id, active: true });
      await store.repositories.update(b!.id, { teamId: t2.id });
      await store.repositories.update(c!.id, { teamId: t1.id });

      const all = await store.repositories.list({ sourceId: s.id, offset: 0, limit: 10 });
      expect(all.total).toBe(4);
      expect(all.items[0].id).toBe(a!.id); // active first
      expect((await store.repositories.list({ sourceId: s.id, active: true, offset: 0, limit: 10 })).total).toBe(1);
      expect((await store.repositories.list({ sourceId: s.id, visibleTeamIds: [t1.id], offset: 0, limit: 10 })).total).toBe(2);
      expect((await store.repositories.list({ sourceId: s.id, visibleTeamIds: [], offset: 0, limit: 10 })).total).toBe(0);
      expect((await store.repositories.list({ sourceId: s.id, visibleTeamIds: [t1.id], teamId: t2.id, offset: 0, limit: 10 })).total).toBe(0);
      expect((await store.repositories.list({ search: 'ZZ-LIST/', offset: 0, limit: 2 })).items).toHaveLength(2);
      expect((await store.repositories.list({ search: '100%', offset: 0, limit: 10 })).total).toBe(1);

      await store.repositories.syncFromSource(s.id, [discovered(1, { fullName: 'zz-list/1' })], defaults());
      expect((await store.repositories.list({ sourceId: s.id, offset: 0, limit: 10 })).total).toBe(1);
      expect((await store.repositories.list({ sourceId: s.id, includeRemoved: true, offset: 0, limit: 10 })).total).toBe(4);
      expect((await store.repositories.findByIds([a!.id, b!.id])).length).toBe(2);
    });

    it('updates settings and finds due repositories', async () => {
      const store = getStore();
      const s = await store.sources.create(newSource());
      await store.repositories.syncFromSource(s.id, [discovered(1), discovered(2)], defaults());
      const r1 = (await store.repositories.findByExternalId(s.id, '1'))!;
      const r2 = (await store.repositories.findByExternalId(s.id, '2'))!;
      const past = new Date(Date.now() - 1000);
      const updated = await store.repositories.update(r1.id, {
        active: true,
        nextScanAt: past,
        schedule: { preset: 'custom', cron: '0 3 * * 1' },
        notifyEmails: ['a@example.com'],
        criticality: 'critical',
        branch: 'release',
        jiraProjectKey: 'PAY',
      });
      expect(updated).toMatchObject({ schedule: { preset: 'custom', cron: '0 3 * * 1' }, notifyEmails: ['a@example.com'], criticality: 'critical', branch: 'release' });
      await store.repositories.update(r2.id, { active: false, nextScanAt: past });
      const due = await store.repositories.findDue(new Date(), 1000);
      expect(due.map((r) => r.id)).toContain(r1.id);
      expect(due.map((r) => r.id)).not.toContain(r2.id);
    });

    it('deleting a source deletes its repositories and runs; deleting a team unassigns repositories', async () => {
      const store = getStore();
      const team = await store.teams.create({ name: `Del ${Date.now()}`, description: null });
      const s = await store.sources.create(newSource({ defaultTeamId: team.id }));
      await store.repositories.syncFromSource(s.id, [discovered(1)], defaults({ teamId: team.id }));
      const repo = (await store.repositories.findByExternalId(s.id, '1'))!;
      await store.teams.delete(team.id);
      expect((await store.repositories.findById(repo.id))?.teamId).toBeNull();
      expect((await store.sources.findById(s.id))?.defaultTeamId).toBeNull();

      const run = await store.scanRuns.create({ repoId: repo.id, sourceId: s.id, teamId: null, trigger: 'manual', requestedBy: null, branch: null });
      expect(await store.sources.delete(s.id)).toBe(true);
      expect(await store.repositories.findById(repo.id)).toBeNull();
      expect(await store.scanRuns.findById(run.id)).toBeNull();
    });
  });

  describe('scan runs', () => {
    it('creates, updates, finds active and lists newest first without logs', async () => {
      const store = getStore();
      const team = await store.teams.create({ name: `Runs ${Date.now()}`, description: null });
      const s = await store.sources.create(newSource());
      await store.repositories.syncFromSource(s.id, [discovered(1)], defaults());
      const repo = (await store.repositories.findByExternalId(s.id, '1'))!;

      const r1 = await store.scanRuns.create({ repoId: repo.id, sourceId: s.id, teamId: team.id, trigger: 'schedule', requestedBy: null, branch: 'main' });
      expect(r1).toMatchObject({ status: 'queued', attempts: 0, log: [], stats: null });
      expect((await store.scanRuns.findActiveForRepo(repo.id))?.id).toBe(r1.id);

      const finished = new Date();
      await store.scanRuns.update(r1.id, {
        status: 'succeeded',
        finishedAt: finished,
        durationMs: 1234,
        commitSha: 'abc123',
        stats: { files: 3, bytes: 99, ecosystems: ['npm'], manifests: ['package.json'] },
        log: ['line 1', 'line 2'],
      });
      expect(await store.scanRuns.findActiveForRepo(repo.id)).toBeNull();
      const full = (await store.scanRuns.findById(r1.id))!;
      expect(full).toMatchObject({ status: 'succeeded', durationMs: 1234, log: ['line 1', 'line 2'], stats: { ecosystems: ['npm'] } });

      await new Promise((r) => setTimeout(r, 5));
      const r2 = await store.scanRuns.create({ repoId: repo.id, sourceId: s.id, teamId: team.id, trigger: 'manual', requestedBy: null, branch: null });
      const page = await store.scanRuns.list({ repoId: repo.id, offset: 0, limit: 10 });
      expect(page.total).toBe(2);
      expect(page.items.map((r) => r.id)).toEqual([r2.id, r1.id]);
      expect(page.items[1].log).toEqual([]);
      expect((await store.scanRuns.list({ repoId: repo.id, status: 'succeeded', offset: 0, limit: 10 })).total).toBe(1);
      expect((await store.scanRuns.list({ repoId: repo.id, visibleTeamIds: [crypto.randomUUID()], offset: 0, limit: 10 })).total).toBe(0);

      expect(await store.scanRuns.deleteFinishedBefore(new Date(finished.getTime() + 1))).toBeGreaterThanOrEqual(1);
      expect(await store.scanRuns.findById(r1.id)).toBeNull();
      expect(await store.scanRuns.delete(r2.id)).toBe(true);
    });
  });

  describe('pull request scans', () => {
    it('creates, de-duplicates active scans, remembers comments, lists and expires', async () => {
      const store = getStore();
      const s = await store.sources.create(newSource());
      await store.repositories.syncFromSource(s.id, [discovered(1)], defaults());
      const repo = (await store.repositories.findByExternalId(s.id, '1'))!;
      const base = { repoId: repo.id, sourceId: s.id, number: 7, title: 'Add login', url: 'https://github.com/acme/repo-1/pull/7', headBranch: 'feature', baseBranch: 'main', failOn: 'high' as const, comment: true, requestedBy: null };

      const a = await store.prScans.create({ ...base, headSha: 'aaa' });
      expect(a).toMatchObject({ status: 'queued', result: null, log: [], commentId: null, startedAt: null });
      expect((await store.prScans.findActive(repo.id, 7, 'aaa'))?.id).toBe(a.id);
      expect(await store.prScans.findActive(repo.id, 7, 'bbb')).toBeNull();
      expect(await store.prScans.findActive(repo.id, 8, 'aaa')).toBeNull();

      const result = { gate: 'failed' as const, changedFiles: 2, counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, findings: [], truncated: false, existingInChangedFiles: 0, suppressed: 0, scanners: [], commentError: null };
      const done = await store.prScans.update(a.id, { status: 'succeeded', result, commentId: '123', commentUrl: 'https://github.com/x#c', log: ['done'], finishedAt: new Date() });
      expect(done).toMatchObject({ status: 'succeeded', result: { gate: 'failed', counts: { high: 1 } }, commentId: '123', log: ['done'] });
      expect(await store.prScans.findActive(repo.id, 7, 'aaa')).toBeNull();

      const b = await store.prScans.create({ ...base, headSha: 'bbb' });
      expect((await store.prScans.findLastCommented(repo.id, 7))?.id).toBe(a.id);
      expect(await store.prScans.findLastCommented(repo.id, 8)).toBeNull();

      const page = await store.prScans.listForRepo(repo.id, { offset: 0, limit: 10 });
      expect(page.total).toBe(2);
      expect(page.items.map((p) => p.id)).toEqual([b.id, a.id]);

      // Only finished scans expire.
      expect(await store.prScans.deleteFinishedBefore(new Date(Date.now() + 60_000))).toBe(1);
      expect(await store.prScans.findById(a.id)).toBeNull();
      expect(await store.prScans.findById(b.id)).not.toBeNull();
    });
  });

  describe('jobs', () => {
    const type = () => `test.${Math.random().toString(36).slice(2, 8)}`;

    it('deduplicates while a job is active and frees the key afterwards', async () => {
      const store = getStore();
      const t = type();
      const key = `dedupe-${t}`;
      const j1 = await store.jobs.enqueue({ type: t, payload: { a: 1 }, dedupeKey: key });
      expect(j1).toMatchObject({ status: 'queued', attempts: 0, maxAttempts: 3, payload: { a: 1 } });
      expect(await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key })).toBeNull();

      const claimed = (await store.jobs.claim([t], 'w1', 60_000))!;
      expect(claimed.id).toBe(j1!.id);
      expect(await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key })).toBeNull();
      expect(await store.jobs.complete(claimed.id, 'w1')).toBe(true);
      expect((await store.jobs.findById(claimed.id))?.status).toBe('succeeded');
      expect(await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key })).not.toBeNull();
      const counts = (await store.jobs.countByStatus()).filter((c) => c.type === t);
      expect(counts.sort((a, b) => a.status.localeCompare(b.status))).toEqual([
        { type: t, status: 'queued', count: 1 },
        { type: t, status: 'succeeded', count: 1 },
      ]);
    });

    it('claims by priority then age, never twice concurrently, respecting runAt', async () => {
      const store = getStore();
      const t = type();
      const low = await store.jobs.enqueue({ type: t, payload: { n: 'low' } });
      const high = await store.jobs.enqueue({ type: t, payload: { n: 'high' }, priority: 10 });
      await store.jobs.enqueue({ type: t, payload: { n: 'future' }, runAt: new Date(Date.now() + 3600_000) });

      const claims = await Promise.all(Array.from({ length: 5 }, (_, i) => store.jobs.claim([t], `w${i}`, 60_000)));
      const got = claims.filter((c) => c !== null);
      expect(got).toHaveLength(2);
      expect(new Set(got.map((g) => g!.id)).size).toBe(2);
      expect(got.map((g) => g!.id).sort()).toEqual([low!.id, high!.id].sort());
      expect(got.every((g) => g!.attempts === 1 && g!.status === 'running')).toBe(true);
      expect(await store.jobs.claim([t], 'w9', 60_000)).toBeNull();
      expect(await store.jobs.claim([], 'w9', 60_000)).toBeNull();
    });

    it('reclaims expired leases and only lets the lease holder finish', async () => {
      const store = getStore();
      const t = type();
      const j = (await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: `lease-${t}` }))!;
      const first = (await store.jobs.claim([t], 'dead-worker', 1))!;
      await new Promise((r) => setTimeout(r, 20));
      const second = (await store.jobs.claim([t], 'live-worker', 60_000))!;
      expect(second.id).toBe(j.id);
      expect(second.attempts).toBe(2);
      expect(first.lockedBy).toBe('dead-worker');
      expect(await store.jobs.complete(j.id, 'dead-worker')).toBe(false);
      expect(await store.jobs.extendLease(j.id, 'dead-worker', 60_000)).toBe(false);
      expect(await store.jobs.extendLease(j.id, 'live-worker', 60_000)).toBe(true);
      expect(await store.jobs.complete(j.id, 'live-worker')).toBe(true);
    });

    it('retries by re-queueing, then fails permanently and releases the dedupe key', async () => {
      const store = getStore();
      const t = type();
      const key = `retry-${t}`;
      const j = (await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key, maxAttempts: 2 }))!;
      await store.jobs.claim([t], 'w', 60_000);
      expect(await store.jobs.fail(j.id, 'w', 'boom', new Date(Date.now() - 1))).toBe(true);
      const requeued = (await store.jobs.findById(j.id))!;
      expect(requeued).toMatchObject({ status: 'queued', lastError: 'boom', lockedBy: null });
      expect(await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key })).toBeNull();

      await store.jobs.claim([t], 'w', 60_000);
      expect(await store.jobs.fail(j.id, 'w', 'boom again', null)).toBe(true);
      expect((await store.jobs.findById(j.id))?.status).toBe('failed');
      expect(await store.jobs.enqueue({ type: t, payload: {}, dedupeKey: key })).not.toBeNull();
      expect(await store.jobs.deleteFinishedBefore(new Date(Date.now() + 1000))).toBeGreaterThanOrEqual(1);
      expect(await store.jobs.findById(j.id)).toBeNull();
    });
  });

  describe('locks', () => {
    it('grants a lease to one owner at a time, allows renewal, takeover after expiry and release', async () => {
      const store = getStore();
      const name = `lock-${Math.random()}`;
      const results = await Promise.all(['a', 'b', 'c'].map((o) => store.locks.acquire(name, o, 60_000)));
      expect(results.filter(Boolean)).toHaveLength(1);
      const owner = ['a', 'b', 'c'][results.indexOf(true)];
      expect(await store.locks.acquire(name, owner, 60_000)).toBe(true);
      expect(await store.locks.acquire(name, 'other', 60_000)).toBe(false);

      await store.locks.release(name, 'other');
      expect(await store.locks.acquire(name, 'other', 60_000)).toBe(false);
      await store.locks.release(name, owner);
      expect(await store.locks.acquire(name, 'other', 1)).toBe(true);
      await new Promise((r) => setTimeout(r, 20));
      expect(await store.locks.acquire(name, owner, 60_000)).toBe(true);
    });
  });
}
