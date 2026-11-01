import { randomUUID } from 'node:crypto';
import { type Kysely, type Selectable, sql } from 'kysely';
import { type PrScanFailOn, type PrScanStatus } from '@argus/shared';
import { type Page } from '../models';
import { type NewPrScan, type PrScan, type PrScanPatch } from '../scanning-models';
import { type PrScanRepo } from '../store';
import { type Database, type PrScansTable } from './schema';

type Db = Kysely<Database>;

function toPrScan(r: Selectable<PrScansTable>): PrScan {
  return { ...r, status: r.status as PrScanStatus, failOn: r.failOn as PrScanFailOn, result: r.result ?? null, log: r.log ?? [] };
}

export class PgPrScanRepo implements PrScanRepo {
  constructor(private readonly db: Db) {}

  async create(input: NewPrScan): Promise<PrScan> {
    const id = randomUUID();
    await this.db
      .insertInto('prScans')
      .values({ ...input, id, status: 'queued', result: null, commentId: null, commentUrl: null, error: null, log: '[]', createdAt: new Date(), startedAt: null, finishedAt: null })
      .execute();
    return (await this.findById(id))!;
  }

  async findById(id: string): Promise<PrScan | null> {
    const r = await this.db.selectFrom('prScans').selectAll().where('id', '=', id).executeTakeFirst();
    return r ? toPrScan(r) : null;
  }

  async update(id: string, patch: PrScanPatch): Promise<PrScan | null> {
    const { result, log, ...rest } = patch;
    await this.db
      .updateTable('prScans')
      .set({
        ...rest,
        ...(result !== undefined ? { result: result ? JSON.stringify(result) : null } : {}),
        ...(log !== undefined ? { log: JSON.stringify(log) } : {}),
      })
      .where('id', '=', id)
      .execute();
    return this.findById(id);
  }

  async findActive(repoId: string, number: number, headSha: string | null): Promise<PrScan | null> {
    let q = this.db.selectFrom('prScans').selectAll().where('repoId', '=', repoId).where('number', '=', number).where('status', 'in', ['queued', 'running']);
    q = headSha ? q.where('headSha', '=', headSha) : q.where('headSha', 'is', null);
    const r = await q.orderBy('createdAt', 'desc').executeTakeFirst();
    return r ? toPrScan(r) : null;
  }

  async findLastCommented(repoId: string, number: number): Promise<PrScan | null> {
    const r = await this.db.selectFrom('prScans').selectAll().where('repoId', '=', repoId).where('number', '=', number).where('commentId', 'is not', null).orderBy('createdAt', 'desc').executeTakeFirst();
    return r ? toPrScan(r) : null;
  }

  async listForRepo(repoId: string, page: { offset: number; limit: number }): Promise<Page<PrScan>> {
    const q = this.db.selectFrom('prScans').where('repoId', '=', repoId);
    const [{ total }, rows] = await Promise.all([
      q.select(sql<number>`count(*)::int`.as('total')).executeTakeFirstOrThrow(),
      q.selectAll().orderBy('createdAt', 'desc').orderBy('id').offset(page.offset).limit(page.limit).execute(),
    ]);
    return { items: rows.map(toPrScan), total };
  }

  async deleteFinishedBefore(before: Date): Promise<number> {
    const r = await this.db.deleteFrom('prScans').where('status', 'in', ['succeeded', 'failed']).where('createdAt', '<', before).executeTakeFirst();
    return Number(r.numDeletedRows);
  }
}
