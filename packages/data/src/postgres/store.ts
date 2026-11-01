import { randomUUID } from 'node:crypto';
import { CamelCasePlugin, Kysely, Migrator, PostgresDialect, type Selectable, sql } from 'kysely';
import { Pool } from 'pg';
import { type Role, type UserStatus } from '@argus/shared';
import { DuplicateKeyError } from '../errors';
import {
  type AuditEntry,
  type AuditFilter,
  type AuditOutcome,
  type NewAuditEntry,
  type NewSession,
  type NewUser,
  type Page,
  type Session,
  type SettingRecord,
  type Team,
  type TeamWithCount,
  type User,
  type UserListFilter,
  type UserPatch,
} from '../models';
import { type AuditRepo, type DataStore, type SessionRepo, type SettingsRepo, type TeamRepo, type UserRepo } from '../store';
import { migrationProvider } from './migrations';
import { PgCacheRepo, PgDependencyRepo, PgFindingRepo, PgSuppressionRepo } from './findings';
import { PgChannelRepo, PgCounterRepo, PgNotificationRuleRepo, PgTicketRepo } from './tickets';
import { PgAiInsightRepo, PgAiUsageRepo } from './ai';
import { PgPrScanRepo } from './pr-scans';
import { PgApiTokenRepo, PgCredentialRepo, PgInviteRepo, PgLoginLinkRepo, PgSavedViewRepo } from './platform';
import { PgAdvisoryRepo, PgIntelItemRepo, PgIntelSourceRepo } from './intel';
import { PgJobRepo, PgLockRepo, PgRepositoryRepo, PgScanRunRepo, PgSourceRepo } from './scanning';
import { type Database, type UsersTable } from './schema';

type Db = Kysely<Database>;

function isPgError(err: unknown): err is { code: string; constraint?: string } {
  return typeof err === 'object' && err !== null && typeof (err as { code?: unknown }).code === 'string';
}

async function mapDuplicate<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (isPgError(err) && err.code === '23505') {
      const c = err.constraint ?? '';
      const field = c.includes('username') ? 'username' : c.includes('email') ? 'email' : c.includes('name') ? 'name' : c;
      throw new DuplicateKeyError(field);
    }
    throw err;
  }
}

function likePattern(term: string): string {
  return `%${term.replace(/[\\%_]/g, (m) => `\\${m}`)}%`;
}

function toUser(row: Selectable<UsersTable>, teamIds: string[]): User {
  return {
    id: row.id,
    username: row.username,
    email: row.email,
    displayName: row.displayName,
    passwordHash: row.passwordHash,
    role: row.role as Role,
    teamIds,
    status: row.status as UserStatus,
    mustChangePassword: row.mustChangePassword,
    mfaEnabled: row.mfaEnabled,
    mfaSecretEnc: row.mfaSecretEnc,
    mfaPendingSecretEnc: row.mfaPendingSecretEnc,
    mfaRecoveryCodes: row.mfaRecoveryCodes ?? [],
    mfaLastUsedStep: row.mfaLastUsedStep,
    failedLoginCount: row.failedLoginCount,
    lockedUntil: row.lockedUntil,
    lastLoginAt: row.lastLoginAt,
    passwordChangedAt: row.passwordChangedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

class PgUserRepo implements UserRepo {
  constructor(private readonly db: Db) {}

  private async teamIdsFor(userIds: string[]): Promise<Map<string, string[]>> {
    const map = new Map<string, string[]>(userIds.map((id) => [id, []]));
    if (userIds.length === 0) return map;
    const rows = await this.db.selectFrom('teamMembers').select(['userId', 'teamId']).where('userId', 'in', userIds).execute();
    for (const r of rows) map.get(r.userId)?.push(r.teamId);
    return map;
  }

  private async hydrate(row: Selectable<UsersTable> | undefined): Promise<User | null> {
    if (!row) return null;
    const teams = await this.teamIdsFor([row.id]);
    return toUser(row, teams.get(row.id) ?? []);
  }

  async create(input: NewUser): Promise<User> {
    const id = randomUUID();
    const now = new Date();
    await mapDuplicate(() =>
      this.db.transaction().execute(async (trx) => {
        await trx
          .insertInto('users')
          .values({
            id,
            username: input.username,
            usernameLower: input.username.toLowerCase(),
            email: input.email,
            emailLower: input.email?.toLowerCase() ?? null,
            displayName: input.displayName,
            passwordHash: input.passwordHash,
            role: input.role,
            status: 'active',
            mustChangePassword: input.mustChangePassword,
            mfaEnabled: false,
            mfaSecretEnc: null,
            mfaPendingSecretEnc: null,
            mfaRecoveryCodes: '[]',
            mfaLastUsedStep: null,
            failedLoginCount: 0,
            lockedUntil: null,
            lastLoginAt: null,
            passwordChangedAt: now,
            createdAt: now,
            updatedAt: now,
          })
          .execute();
        if (input.teamIds.length > 0) {
          await trx
            .insertInto('teamMembers')
            .values(input.teamIds.map((teamId) => ({ teamId, userId: id })))
            .execute();
        }
      }),
    );
    return (await this.findById(id))!;
  }

  async findById(id: string): Promise<User | null> {
    return this.hydrate(await this.db.selectFrom('users').selectAll().where('id', '=', id).executeTakeFirst());
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.hydrate(await this.db.selectFrom('users').selectAll().where('usernameLower', '=', username.toLowerCase()).executeTakeFirst());
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.hydrate(await this.db.selectFrom('users').selectAll().where('emailLower', '=', email.toLowerCase()).executeTakeFirst());
  }

  async update(id: string, patch: UserPatch): Promise<User | null> {
    const { teamIds, email, mfaRecoveryCodes, ...rest } = patch;
    const updated = await mapDuplicate(() =>
      this.db.transaction().execute(async (trx) => {
        const res = await trx
          .updateTable('users')
          .set({
            ...rest,
            ...(email !== undefined ? { email, emailLower: email?.toLowerCase() ?? null } : {}),
            ...(mfaRecoveryCodes !== undefined ? { mfaRecoveryCodes: JSON.stringify(mfaRecoveryCodes) } : {}),
            updatedAt: new Date(),
          })
          .where('id', '=', id)
          .executeTakeFirst();
        if (res.numUpdatedRows === 0n) return false;
        if (teamIds !== undefined) {
          await trx.deleteFrom('teamMembers').where('userId', '=', id).execute();
          if (teamIds.length > 0) {
            await trx
              .insertInto('teamMembers')
              .values([...new Set(teamIds)].map((teamId) => ({ teamId, userId: id })))
              .execute();
          }
        }
        return true;
      }),
    );
    return updated ? this.findById(id) : null;
  }

  async incrementFailedLogins(id: string): Promise<number> {
    const row = await this.db
      .updateTable('users')
      .set((eb) => ({ failedLoginCount: eb('failedLoginCount', '+', 1) }))
      .where('id', '=', id)
      .returning('failedLoginCount')
      .executeTakeFirst();
    return row?.failedLoginCount ?? 0;
  }

  async list(filter: UserListFilter): Promise<Page<User>> {
    let q = this.db.selectFrom('users');
    if (filter.search) {
      const p = likePattern(filter.search);
      q = q.where((eb) => eb.or([eb('username', 'ilike', p), eb('displayName', 'ilike', p), eb('email', 'ilike', p)]));
    }
    if (filter.role) q = q.where('role', '=', filter.role);
    if (filter.status) q = q.where('status', '=', filter.status);
    if (filter.teamId) {
      const teamId = filter.teamId;
      q = q.where((eb) =>
        eb.exists(eb.selectFrom('teamMembers').select('teamMembers.userId').whereRef('teamMembers.userId', '=', 'users.id').where('teamMembers.teamId', '=', teamId)),
      );
    }
    const [{ total }, rows] = await Promise.all([
      q.select(sql<number>`count(*)::int`.as('total')).executeTakeFirstOrThrow(),
      q.selectAll().orderBy('usernameLower').offset(filter.offset).limit(filter.limit).execute(),
    ]);
    const teams = await this.teamIdsFor(rows.map((r) => r.id));
    return { items: rows.map((r) => toUser(r, teams.get(r.id) ?? [])), total };
  }

  async count(): Promise<number> {
    const { n } = await this.db.selectFrom('users').select(sql<number>`count(*)::int`.as('n')).executeTakeFirstOrThrow();
    return n;
  }
}

class PgTeamRepo implements TeamRepo {
  constructor(private readonly db: Db) {}

  async create(input: { name: string; description: string | null }): Promise<Team> {
    const now = new Date();
    const team: Team = { id: randomUUID(), name: input.name, description: input.description, createdAt: now, updatedAt: now };
    await mapDuplicate(() =>
      this.db
        .insertInto('teams')
        .values({ ...team, nameLower: team.name.toLowerCase() })
        .execute(),
    );
    return team;
  }

  async findById(id: string): Promise<Team | null> {
    return (await this.db.selectFrom('teams').select(['id', 'name', 'description', 'createdAt', 'updatedAt']).where('id', '=', id).executeTakeFirst()) ?? null;
  }

  async findByIds(ids: string[]): Promise<Team[]> {
    if (ids.length === 0) return [];
    return this.db.selectFrom('teams').select(['id', 'name', 'description', 'createdAt', 'updatedAt']).where('id', 'in', ids).execute();
  }

  async update(id: string, patch: { name?: string; description?: string | null }): Promise<Team | null> {
    await mapDuplicate(() =>
      this.db
        .updateTable('teams')
        .set({
          ...(patch.name !== undefined ? { name: patch.name, nameLower: patch.name.toLowerCase() } : {}),
          ...(patch.description !== undefined ? { description: patch.description } : {}),
          updatedAt: new Date(),
        })
        .where('id', '=', id)
        .execute(),
    );
    return this.findById(id);
  }

  async delete(id: string): Promise<boolean> {
    const res = await this.db.deleteFrom('teams').where('id', '=', id).executeTakeFirst();
    return res.numDeletedRows > 0n;
  }

  async list(): Promise<TeamWithCount[]> {
    return this.db
      .selectFrom('teams')
      .select((eb) => [
        'id',
        'name',
        'description',
        'createdAt',
        'updatedAt',
        eb
          .selectFrom('teamMembers')
          .select(sql<number>`count(*)::int`.as('c'))
          .whereRef('teamMembers.teamId', '=', 'teams.id')
          .as('memberCount'),
      ])
      .orderBy('nameLower')
      .execute()
      .then((rows) => rows.map((r) => ({ ...r, memberCount: r.memberCount ?? 0 })));
  }
}

class PgSessionRepo implements SessionRepo {
  constructor(private readonly db: Db) {}

  async create(input: NewSession): Promise<Session> {
    const session: Session = { ...input, id: randomUUID(), revokedAt: null, createdAt: new Date(), lastUsedAt: null };
    await this.db.insertInto('sessions').values(session).execute();
    return session;
  }

  async findByTokenHash(tokenHash: string): Promise<Session | null> {
    return (await this.db.selectFrom('sessions').selectAll().where('tokenHash', '=', tokenHash).executeTakeFirst()) ?? null;
  }

  async revokeIfActive(id: string): Promise<boolean> {
    const res = await this.db.updateTable('sessions').set({ revokedAt: new Date(), lastUsedAt: new Date() }).where('id', '=', id).where('revokedAt', 'is', null).executeTakeFirst();
    return res.numUpdatedRows > 0n;
  }

  async revokeFamily(familyId: string): Promise<number> {
    const res = await this.db.updateTable('sessions').set({ revokedAt: new Date() }).where('familyId', '=', familyId).where('revokedAt', 'is', null).executeTakeFirst();
    return Number(res.numUpdatedRows);
  }

  async revokeAllForUser(userId: string, exceptId?: string): Promise<number> {
    let q = this.db.updateTable('sessions').set({ revokedAt: new Date() }).where('userId', '=', userId).where('revokedAt', 'is', null);
    if (exceptId) q = q.where('id', '!=', exceptId);
    const res = await q.executeTakeFirst();
    return Number(res.numUpdatedRows);
  }

  async deleteExpired(before: Date): Promise<number> {
    const res = await this.db.deleteFrom('sessions').where('expiresAt', '<', before).executeTakeFirst();
    return Number(res.numDeletedRows);
  }
}

class PgAuditRepo implements AuditRepo {
  constructor(private readonly db: Db) {}

  async append(entry: NewAuditEntry): Promise<AuditEntry> {
    const record: AuditEntry = { ...entry, id: randomUUID(), at: entry.at ?? new Date() };
    await this.db
      .insertInto('auditLogs')
      .values({ ...record, details: record.details ? JSON.stringify(record.details) : null })
      .execute();
    return record;
  }
  async deleteBefore(before: Date): Promise<number> {
    return Number((await this.db.deleteFrom('auditLogs').where('at', '<', before).executeTakeFirst()).numDeletedRows);
  }


  async list(filter: AuditFilter): Promise<Page<AuditEntry>> {
    let q = this.db.selectFrom('auditLogs');
    if (filter.actorId) q = q.where('actorId', '=', filter.actorId);
    if (filter.action) q = q.where('action', '=', filter.action);
    if (filter.targetType) q = q.where('targetType', '=', filter.targetType);
    if (filter.targetId) q = q.where('targetId', '=', filter.targetId);
    if (filter.outcome) q = q.where('outcome', '=', filter.outcome);
    if (filter.from) q = q.where('at', '>=', filter.from);
    if (filter.to) q = q.where('at', '<=', filter.to);
    const [{ total }, rows] = await Promise.all([
      q.select(sql<number>`count(*)::int`.as('total')).executeTakeFirstOrThrow(),
      q.selectAll().orderBy('at', 'desc').offset(filter.offset).limit(filter.limit).execute(),
    ]);
    return { items: rows.map((r) => ({ ...r, outcome: r.outcome as AuditOutcome, details: r.details ?? null })), total };
  }
}

class PgSettingsRepo implements SettingsRepo {
  constructor(private readonly db: Db) {}

  async get<T>(key: string): Promise<SettingRecord<T> | null> {
    const row = await this.db.selectFrom('settings').selectAll().where('key', '=', key).executeTakeFirst();
    return row ? { ...row, value: row.value as T } : null;
  }

  async set<T>(key: string, value: T, updatedBy: string | null): Promise<SettingRecord<T>> {
    const record = { key, value: JSON.stringify(value), updatedAt: new Date(), updatedBy };
    await this.db
      .insertInto('settings')
      .values(record)
      .onConflict((oc) => oc.column('key').doUpdateSet({ value: record.value, updatedAt: record.updatedAt, updatedBy }))
      .execute();
    return { key, value, updatedAt: record.updatedAt, updatedBy };
  }
}

export function createPostgresStore(url: string): DataStore {
  const db: Db = new Kysely<Database>({
    dialect: new PostgresDialect({ pool: new Pool({ connectionString: url, max: 10 }) }),
    // Column names map snake_case <-> camelCase; keys inside jsonb values are stored and returned exactly as written.
    plugins: [new CamelCasePlugin({ maintainNestedObjectKeys: true })],
  });
  return {
    kind: 'postgres',
    users: new PgUserRepo(db),
    teams: new PgTeamRepo(db),
    sessions: new PgSessionRepo(db),
    audit: new PgAuditRepo(db),
    settings: new PgSettingsRepo(db),
    sources: new PgSourceRepo(db),
    repositories: new PgRepositoryRepo(db),
    scanRuns: new PgScanRunRepo(db),
    prScans: new PgPrScanRepo(db),
    jobs: new PgJobRepo(db),
    locks: new PgLockRepo(db),
    findings: new PgFindingRepo(db),
    dependencies: new PgDependencyRepo(db),
    suppressions: new PgSuppressionRepo(db),
    cache: new PgCacheRepo(db),
    tickets: new PgTicketRepo(db),
    counters: new PgCounterRepo(db),
    channels: new PgChannelRepo(db),
    notificationRules: new PgNotificationRuleRepo(db),
    aiUsage: new PgAiUsageRepo(db),
    aiInsights: new PgAiInsightRepo(db),
    intelSources: new PgIntelSourceRepo(db),
    intelItems: new PgIntelItemRepo(db),
    advisories: new PgAdvisoryRepo(db),
    apiTokens: new PgApiTokenRepo(db),
    credentials: new PgCredentialRepo(db),
    savedViews: new PgSavedViewRepo(db),
    invites: new PgInviteRepo(db),
    loginLinks: new PgLoginLinkRepo(db),
    async migrate() {
      const { error, results } = await new Migrator({ db, provider: migrationProvider }).migrateToLatest();
      const failed = results?.find((r) => r.status === 'Error');
      if (error || failed) {
        throw new Error(`PostgreSQL migration failed${failed ? ` at ${failed.migrationName}` : ''}: ${String(error)}`);
      }
    },
    async ping() {
      try {
        await sql`select 1`.execute(db);
        return true;
      } catch {
        return false;
      }
    },
    async close() {
      await db.destroy();
    },
  };
}
