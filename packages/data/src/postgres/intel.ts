import { randomUUID } from 'node:crypto';
import { type Kysely, type Selectable, sql } from 'kysely';
import { type AdvisorySource, canonicalPackageName, type Ecosystem, INTEL_ITEM_STATUSES, type IntelItemStatus, type Severity } from '@argus/shared';
import {
  type Advisory,
  type AdvisoryListFilter,
  type IntelExtraction,
  type IntelItem,
  type IntelItemListFilter,
  type IntelItemPatch,
  type IntelSource,
  type IntelSourcePatch,
  type NewAdvisory,
  type NewIntelItem,
  type NewIntelSource,
} from '../intel-models';
import { type AdvisoryRepo, type IntelItemRepo, type IntelSourceRepo } from '../store';
import { type AdvisoriesTable, type Database, type IntelItemsTable } from './schema';

type Db = Kysely<Database>;

function likePattern(term: string): string {
  return `%${term.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

export const packageKeyOf = (ecosystem: Ecosystem, name: string) => canonicalPackageName(ecosystem, name);

export class PgIntelSourceRepo implements IntelSourceRepo {
  constructor(private readonly db: Db) {}

  async create(input: NewIntelSource): Promise<IntelSource> {
    const now = new Date();
    const row = { ...input, id: randomUUID(), lastFetchedAt: null, lastError: null, lastNewItems: null, createdAt: now, updatedAt: now };
    await this.db.insertInto('intelSources').values(row).execute();
    return row;
  }

  async findById(id: string): Promise<IntelSource | null> {
    return (await this.db.selectFrom('intelSources').selectAll().where('id', '=', id).executeTakeFirst()) ?? null;
  }

  async list(): Promise<IntelSource[]> {
    return this.db.selectFrom('intelSources').selectAll().orderBy('name').execute();
  }

  async update(id: string, patch: IntelSourcePatch): Promise<IntelSource | null> {
    await this.db
      .updateTable('intelSources')
      .set({ ...patch, updatedAt: new Date() })
      .where('id', '=', id)
      .execute();
    return this.findById(id);
  }

  async delete(id: string): Promise<boolean> {
    const res = await this.db.deleteFrom('intelSources').where('id', '=', id).executeTakeFirst();
    return Number(res.numDeletedRows) > 0;
  }
}

function toItem(r: Selectable<IntelItemsTable>): IntelItem {
  const e = r.extraction as (Omit<IntelExtraction, 'at'> & { at: string }) | null;
  return {
    ...r,
    status: r.status as IntelItemStatus,
    candidates: (r.candidates ?? []) as IntelItem['candidates'],
    extraction: e ? { ...e, at: new Date(e.at) } : null,
    advisoryIds: r.advisoryIds ?? [],
  };
}

export class PgIntelItemRepo implements IntelItemRepo {
  constructor(private readonly db: Db) {}

  async insertNew(items: NewIntelItem[]): Promise<IntelItem[]> {
    if (items.length === 0) return [];
    const now = new Date();
    const rows = await this.db
      .insertInto('intelItems')
      .values(items.map((i) => ({ ...i, id: randomUUID(), status: 'new', candidates: '[]', extraction: null, error: null, advisoryIds: '[]', reviewedBy: null, reviewedAt: null, fetchedAt: now })))
      .onConflict((oc) => oc.columns(['sourceId', 'guid']).doNothing())
      .returningAll()
      .execute();
    return rows.map(toItem);
  }

  async findById(id: string): Promise<IntelItem | null> {
    const r = await this.db.selectFrom('intelItems').selectAll().where('id', '=', id).executeTakeFirst();
    return r ? toItem(r) : null;
  }

  async update(id: string, patch: IntelItemPatch): Promise<IntelItem | null> {
    const { candidates, extraction, advisoryIds, ...rest } = patch;
    await this.db
      .updateTable('intelItems')
      .set({
        ...rest,
        ...(candidates !== undefined ? { candidates: JSON.stringify(candidates) } : {}),
        ...(extraction !== undefined ? { extraction: extraction ? JSON.stringify(extraction) : null } : {}),
        ...(advisoryIds !== undefined ? { advisoryIds: JSON.stringify(advisoryIds) } : {}),
      } as never)
      .where('id', '=', id)
      .execute();
    return this.findById(id);
  }

  async list(f: IntelItemListFilter): Promise<{ items: IntelItem[]; total: number }> {
    let q = this.db.selectFrom('intelItems');
    if (f.statuses?.length) q = q.where('status', 'in', f.statuses);
    if (f.sourceId) q = q.where('sourceId', '=', f.sourceId);
    if (f.search) q = q.where('title', 'ilike', likePattern(f.search));
    const [count, rows] = await Promise.all([
      q.select(sql<number>`count(*)::int`.as('n')).executeTakeFirst(),
      q.selectAll().orderBy(sql`coalesce(published_at, fetched_at)`, 'desc').orderBy('id').offset(f.offset).limit(f.limit).execute(),
    ]);
    return { items: rows.map(toItem), total: count?.n ?? 0 };
  }

  async listByStatus(status: IntelItemStatus, limit: number): Promise<IntelItem[]> {
    return (await this.db.selectFrom('intelItems').selectAll().where('status', '=', status).orderBy('fetchedAt').orderBy('id').limit(limit).execute()).map(toItem);
  }

  async countByStatus(): Promise<Record<IntelItemStatus, number>> {
    const out = Object.fromEntries(INTEL_ITEM_STATUSES.map((s) => [s, 0])) as Record<IntelItemStatus, number>;
    const rows = await this.db.selectFrom('intelItems').select(['status', sql<number>`count(*)::int`.as('n')]).groupBy('status').execute();
    for (const r of rows) out[r.status as IntelItemStatus] = r.n;
    return out;
  }
  async deleteSettledBefore(before: Date): Promise<number> {
    return Number((await this.db.deleteFrom('intelItems').where('fetchedAt', '<', before).where('status', 'not in', ['new', 'review']).executeTakeFirst()).numDeletedRows);
  }

}

function toAdvisory(r: Selectable<AdvisoriesTable>): Advisory {
  const { packageKey: _key, refs, ...rest } = r;
  return {
    ...rest,
    ecosystem: r.ecosystem as Ecosystem,
    severity: r.severity as Severity,
    source: r.source as AdvisorySource,
    cveIds: r.cveIds ?? [],
    references: refs ?? [],
  };
}

export class PgAdvisoryRepo implements AdvisoryRepo {
  constructor(private readonly db: Db) {}

  async create(input: Omit<NewAdvisory, 'key'>): Promise<Advisory> {
    const now = new Date();
    const year = now.getUTCFullYear();
    const counter = await this.db
      .insertInto('counters')
      .values({ name: `advisory:${year}`, value: 1 })
      .onConflict((oc) => oc.column('name').doUpdateSet({ value: sql`counters.value + 1` }))
      .returning('value')
      .executeTakeFirstOrThrow();
    const { references, cveIds, ...rest } = input;
    const id = randomUUID();
    await this.db
      .insertInto('advisories')
      .values({
        ...rest,
        id,
        key: `ARGUS-${year}-${String(counter.value).padStart(4, '0')}`,
        packageKey: packageKeyOf(input.ecosystem, input.packageName),
        cveIds: JSON.stringify(cveIds),
        refs: JSON.stringify(references),
        createdAt: now,
        updatedAt: now,
      })
      .execute();
    return (await this.findById(id))!;
  }

  async findById(id: string): Promise<Advisory | null> {
    const r = await this.db.selectFrom('advisories').selectAll().where('id', '=', id).executeTakeFirst();
    return r ? toAdvisory(r) : null;
  }

  async list(f: AdvisoryListFilter): Promise<{ items: Advisory[]; total: number }> {
    let q = this.db.selectFrom('advisories');
    if (f.withdrawn !== undefined) q = q.where('withdrawn', '=', f.withdrawn);
    if (f.search) {
      const p = likePattern(f.search);
      q = q.where((eb) => eb.or([eb('title', 'ilike', p), eb('packageName', 'ilike', p), eb('key', 'ilike', p), eb(sql`cve_ids::text`, 'ilike', p)]));
    }
    const [count, rows] = await Promise.all([q.select(sql<number>`count(*)::int`.as('n')).executeTakeFirst(), q.selectAll().orderBy('createdAt', 'desc').orderBy('id').offset(f.offset).limit(f.limit).execute()]);
    return { items: rows.map(toAdvisory), total: count?.n ?? 0 };
  }

  async update(id: string, patch: Partial<Pick<Advisory, 'withdrawn'>>): Promise<Advisory | null> {
    await this.db
      .updateTable('advisories')
      .set({ ...patch, updatedAt: new Date() })
      .where('id', '=', id)
      .execute();
    return this.findById(id);
  }

  async listActiveForPackages(packages: { ecosystem: Ecosystem; name: string }[]): Promise<Advisory[]> {
    if (packages.length === 0) return [];
    const keys = [...new Set(packages.map((p) => packageKeyOf(p.ecosystem, p.name)))];
    const rows = await this.db.selectFrom('advisories').selectAll().where('withdrawn', '=', false).where('packageKey', 'in', keys).execute();
    const wanted = new Set(packages.map((p) => `${p.ecosystem}|${packageKeyOf(p.ecosystem, p.name)}`));
    return rows.filter((r) => wanted.has(`${r.ecosystem}|${r.packageKey}`)).map(toAdvisory);
  }

  async countActive(): Promise<number> {
    return (await this.db.selectFrom('advisories').select(sql<number>`count(*)::int`.as('n')).where('withdrawn', '=', false).executeTakeFirst())?.n ?? 0;
  }
}
