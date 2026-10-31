import { randomUUID } from 'node:crypto';
import { type Collection, type Db, type Filter, MongoServerError } from 'mongodb';
import { canonicalPackageName, type Ecosystem, INTEL_ITEM_STATUSES, type IntelItemStatus } from '@argus/shared';
import {
  type Advisory,
  type AdvisoryListFilter,
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

export type IntelSourceDoc = Omit<IntelSource, 'id'> & { _id: string };
export type IntelItemDoc = Omit<IntelItem, 'id'> & { _id: string };
export type AdvisoryDoc = Omit<Advisory, 'id'> & { _id: string; packageKey: string };

function strip<T extends { _id: string }>(d: T): Omit<T, '_id'> & { id: string } {
  const { _id, ...rest } = d;
  return { id: _id, ...rest };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const packageKeyOf = (ecosystem: Ecosystem, name: string) => canonicalPackageName(ecosystem, name);

export class MongoIntelSourceRepo implements IntelSourceRepo {
  constructor(
    private readonly col: Collection<IntelSourceDoc>,
    private readonly items: Collection<IntelItemDoc>,
  ) {}

  async create(input: NewIntelSource): Promise<IntelSource> {
    const now = new Date();
    const doc: IntelSourceDoc = { ...input, _id: randomUUID(), lastFetchedAt: null, lastError: null, lastNewItems: null, createdAt: now, updatedAt: now };
    await this.col.insertOne(doc);
    return strip(doc);
  }

  async findById(id: string): Promise<IntelSource | null> {
    const d = await this.col.findOne({ _id: id });
    return d ? strip(d) : null;
  }

  async list(): Promise<IntelSource[]> {
    return (await this.col.find().sort({ name: 1 }).toArray()).map(strip);
  }

  async update(id: string, patch: IntelSourcePatch): Promise<IntelSource | null> {
    const d = await this.col.findOneAndUpdate({ _id: id }, { $set: { ...patch, updatedAt: new Date() } }, { returnDocument: 'after' });
    return d ? strip(d) : null;
  }

  async delete(id: string): Promise<boolean> {
    const res = await this.col.deleteOne({ _id: id });
    if (res.deletedCount === 0) return false;
    // Mirrors ON DELETE CASCADE in PostgreSQL.
    await this.items.deleteMany({ sourceId: id });
    return true;
  }
}

export class MongoIntelItemRepo implements IntelItemRepo {
  constructor(private readonly col: Collection<IntelItemDoc>) {}

  async insertNew(items: NewIntelItem[]): Promise<IntelItem[]> {
    if (items.length === 0) return [];
    const now = new Date();
    const docs: IntelItemDoc[] = items.map((i) => ({ ...i, _id: randomUUID(), status: 'new', candidates: [], extraction: null, error: null, advisoryIds: [], reviewedBy: null, reviewedAt: null, fetchedAt: now }));
    const inserted = new Set<string>();
    try {
      const res = await this.col.insertMany(docs, { ordered: false });
      for (const id of Object.values(res.insertedIds)) inserted.add(id);
    } catch (err) {
      // Duplicates (already seen entries) are expected; anything else is not.
      if (!(err instanceof MongoServerError) || err.code !== 11000) throw err;
      const ids = (err as MongoServerError & { insertedIds?: Record<string, string> }).insertedIds ?? {};
      for (const id of Object.values(ids)) inserted.add(id);
      if (inserted.size === 0) {
        // Older drivers do not report inserted ids on bulk errors: look them up.
        const found = await this.col.find({ _id: { $in: docs.map((d) => d._id) } }, { projection: { _id: 1 } }).toArray();
        for (const d of found) inserted.add(d._id);
      }
    }
    return docs.filter((d) => inserted.has(d._id)).map(strip);
  }

  async findById(id: string): Promise<IntelItem | null> {
    const d = await this.col.findOne({ _id: id });
    return d ? strip(d) : null;
  }

  async update(id: string, patch: IntelItemPatch): Promise<IntelItem | null> {
    const d = await this.col.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' });
    return d ? strip(d) : null;
  }

  async list(f: IntelItemListFilter): Promise<{ items: IntelItem[]; total: number }> {
    const q: Filter<IntelItemDoc> = {};
    if (f.statuses?.length) q.status = { $in: f.statuses };
    if (f.sourceId) q.sourceId = f.sourceId;
    if (f.search) q.title = new RegExp(escapeRegex(f.search), 'i');
    const [total, docs] = await Promise.all([
      this.col.countDocuments(q),
      this.col
        .aggregate<IntelItemDoc>([{ $match: q }, { $addFields: { _sortAt: { $ifNull: ['$publishedAt', '$fetchedAt'] } } }, { $sort: { _sortAt: -1, _id: 1 } }, { $skip: f.offset }, { $limit: f.limit }, { $project: { _sortAt: 0 } }])
        .toArray(),
    ]);
    return { items: docs.map(strip), total };
  }

  async listByStatus(status: IntelItemStatus, limit: number): Promise<IntelItem[]> {
    return (await this.col.find({ status }).sort({ fetchedAt: 1, _id: 1 }).limit(limit).toArray()).map(strip);
  }

  async countByStatus(): Promise<Record<IntelItemStatus, number>> {
    const out = Object.fromEntries(INTEL_ITEM_STATUSES.map((s) => [s, 0])) as Record<IntelItemStatus, number>;
    for (const r of await this.col.aggregate<{ _id: IntelItemStatus; n: number }>([{ $group: { _id: '$status', n: { $sum: 1 } } }]).toArray()) out[r._id] = r.n;
    return out;
  }
  async deleteSettledBefore(before: Date): Promise<number> {
    return (await this.col.deleteMany({ fetchedAt: { $lt: before }, status: { $nin: ['new', 'review'] } })).deletedCount;
  }

}

export class MongoAdvisoryRepo implements AdvisoryRepo {
  constructor(
    private readonly col: Collection<AdvisoryDoc>,
    private readonly counters: Collection<{ _id: string; value: number }>,
  ) {}

  private toAdvisory(d: AdvisoryDoc): Advisory {
    const { packageKey: _key, ...rest } = strip(d);
    return rest;
  }

  async create(input: Omit<NewAdvisory, 'key'>): Promise<Advisory> {
    const now = new Date();
    const year = now.getUTCFullYear();
    const c = await this.counters.findOneAndUpdate({ _id: `advisory:${year}` }, { $inc: { value: 1 } }, { upsert: true, returnDocument: 'after' });
    const doc: AdvisoryDoc = { ...input, _id: randomUUID(), key: `ARGUS-${year}-${String(c!.value).padStart(4, '0')}`, packageKey: packageKeyOf(input.ecosystem, input.packageName), createdAt: now, updatedAt: now };
    await this.col.insertOne(doc);
    return this.toAdvisory(doc);
  }

  async findById(id: string): Promise<Advisory | null> {
    const d = await this.col.findOne({ _id: id });
    return d ? this.toAdvisory(d) : null;
  }

  async list(f: AdvisoryListFilter): Promise<{ items: Advisory[]; total: number }> {
    const q: Filter<AdvisoryDoc> = {};
    if (f.withdrawn !== undefined) q.withdrawn = f.withdrawn;
    if (f.search) {
      const re = new RegExp(escapeRegex(f.search), 'i');
      q.$or = [{ title: re }, { packageName: re }, { key: re }, { cveIds: re }];
    }
    const [total, docs] = await Promise.all([this.col.countDocuments(q), this.col.find(q).sort({ createdAt: -1, _id: 1 }).skip(f.offset).limit(f.limit).toArray()]);
    return { items: docs.map((d) => this.toAdvisory(d)), total };
  }

  async update(id: string, patch: Partial<Pick<Advisory, 'withdrawn'>>): Promise<Advisory | null> {
    const d = await this.col.findOneAndUpdate({ _id: id }, { $set: { ...patch, updatedAt: new Date() } }, { returnDocument: 'after' });
    return d ? this.toAdvisory(d) : null;
  }

  async listActiveForPackages(packages: { ecosystem: Ecosystem; name: string }[]): Promise<Advisory[]> {
    if (packages.length === 0) return [];
    const wanted = new Set(packages.map((p) => `${p.ecosystem}|${packageKeyOf(p.ecosystem, p.name)}`));
    const docs = await this.col.find({ withdrawn: false, packageKey: { $in: [...new Set(packages.map((p) => packageKeyOf(p.ecosystem, p.name)))] } }).toArray();
    return docs.filter((d) => wanted.has(`${d.ecosystem}|${d.packageKey}`)).map((d) => this.toAdvisory(d));
  }

  async countActive(): Promise<number> {
    return this.col.countDocuments({ withdrawn: false });
  }
}

export async function bootstrapIntelIndexes(db: Db): Promise<void> {
  await db.collection('intel_sources').createIndexes([{ key: { name: 1 }, name: 'name' }]);
  await db.collection('intel_items').createIndexes([
    { key: { sourceId: 1, guid: 1 }, unique: true, name: 'source_guid_unique' },
    { key: { status: 1, fetchedAt: 1 }, name: 'status_fetched' },
  ]);
  await db.collection('advisories').createIndexes([
    { key: { key: 1 }, unique: true, name: 'key_unique' },
    { key: { ecosystem: 1, packageKey: 1 }, name: 'package' },
  ]);
}
