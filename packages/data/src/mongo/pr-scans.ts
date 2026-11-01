import { randomUUID } from 'node:crypto';
import { type Collection, type Db } from 'mongodb';
import { type Page } from '../models';
import { type NewPrScan, type PrScan, type PrScanPatch } from '../scanning-models';
import { type PrScanRepo } from '../store';

export type PrScanDoc = Omit<PrScan, 'id'> & { _id: string };

function strip(d: PrScanDoc): PrScan {
  const { _id, ...rest } = d;
  return { id: _id, ...rest };
}

export class MongoPrScanRepo implements PrScanRepo {
  constructor(private readonly col: Collection<PrScanDoc>) {}

  async create(input: NewPrScan): Promise<PrScan> {
    const doc: PrScanDoc = { ...input, _id: randomUUID(), status: 'queued', result: null, commentId: null, commentUrl: null, error: null, log: [], createdAt: new Date(), startedAt: null, finishedAt: null };
    await this.col.insertOne(doc);
    return strip(doc);
  }

  async findById(id: string): Promise<PrScan | null> {
    const d = await this.col.findOne({ _id: id });
    return d ? strip(d) : null;
  }

  async update(id: string, patch: PrScanPatch): Promise<PrScan | null> {
    const d = await this.col.findOneAndUpdate({ _id: id }, { $set: patch }, { returnDocument: 'after' });
    return d ? strip(d) : null;
  }

  async findActive(repoId: string, number: number, headSha: string | null): Promise<PrScan | null> {
    const d = await this.col.findOne({ repoId, number, headSha, status: { $in: ['queued', 'running'] } }, { sort: { createdAt: -1 } });
    return d ? strip(d) : null;
  }

  async findLastCommented(repoId: string, number: number): Promise<PrScan | null> {
    const d = await this.col.findOne({ repoId, number, commentId: { $ne: null } }, { sort: { createdAt: -1 } });
    return d ? strip(d) : null;
  }

  async listForRepo(repoId: string, page: { offset: number; limit: number }): Promise<Page<PrScan>> {
    const [total, docs] = await Promise.all([this.col.countDocuments({ repoId }), this.col.find({ repoId }).sort({ createdAt: -1, _id: 1 }).skip(page.offset).limit(page.limit).toArray()]);
    return { items: docs.map(strip), total };
  }

  async deleteFinishedBefore(before: Date): Promise<number> {
    return (await this.col.deleteMany({ status: { $in: ['succeeded', 'failed'] }, createdAt: { $lt: before } })).deletedCount;
  }
}

export async function bootstrapPrScanIndexes(db: Db): Promise<void> {
  await db.collection('pr_scans').createIndexes([
    { key: { repoId: 1, number: 1, createdAt: -1 }, name: 'repo_number_created' },
    { key: { repoId: 1, createdAt: -1 }, name: 'repo_created' },
    { key: { createdAt: 1 }, name: 'created' },
  ]);
}
