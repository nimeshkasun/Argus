import { randomUUID } from 'node:crypto';
import { type Collection, type Db, type Filter, MongoClient, MongoServerError } from 'mongodb';
import { DuplicateKeyError } from '../errors';
import { bootstrapPrScanIndexes, MongoPrScanRepo, type PrScanDoc } from './pr-scans';
import {
  type AuditEntry,
  type AuditFilter,
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
import {
  bootstrapScanningIndexes,
  type JobDoc,
  type LockDoc,
  MongoJobRepo,
  MongoLockRepo,
  MongoRepositoryRepo,
  MongoScanRunRepo,
  MongoSourceRepo,
  type RepositoryDoc,
  type ScanRunDoc,
  type SourceDoc,
} from './scanning';
import {
  bootstrapFindingIndexes,
  type CacheDoc,
  type DependencyDoc,
  type FindingDoc,
  MongoCacheRepo,
  MongoDependencyRepo,
  MongoFindingRepo,
  MongoSuppressionRepo,
  type SuppressionDoc,
} from './findings';
import {
  bootstrapTicketIndexes,
  type ChannelDoc,
  type CounterDoc,
  MongoChannelRepo,
  MongoCounterRepo,
  MongoNotificationRuleRepo,
  MongoTicketRepo,
  type RuleDoc,
  type TicketDoc,
  type TicketEventDoc,
} from './tickets';
import { type ApiTokenDoc, bootstrapPlatformIndexes, type CredentialDoc, type InviteDoc, type LoginLinkDoc, MongoApiTokenRepo, MongoCredentialRepo, MongoInviteRepo, MongoLoginLinkRepo, MongoSavedViewRepo, type SavedViewDoc } from './platform';
import { type AdvisoryDoc, bootstrapIntelIndexes, type IntelItemDoc, type IntelSourceDoc, MongoAdvisoryRepo, MongoIntelItemRepo, MongoIntelSourceRepo } from './intel';
import { type AiInsightDoc, type AiUsageDoc, bootstrapAiIndexes, MongoAiInsightRepo, MongoAiUsageRepo } from './ai';

type UserDoc = Omit<User, 'id'> & { _id: string; usernameLower: string; emailLower: string | null };
type TeamDoc = Omit<Team, 'id'> & { _id: string; nameLower: string };
type SessionDoc = Omit<Session, 'id'> & { _id: string };
type AuditDoc = Omit<AuditEntry, 'id'> & { _id: string };
type SettingDoc = { _id: string; value: unknown; updatedAt: Date; updatedBy: string | null };
type MetaDoc = { _id: string; version: number; updatedAt: Date };

/** Bump when index/bootstrap definitions below change. */
const SCHEMA_VERSION = 12;

async function mapDuplicate<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof MongoServerError && err.code === 11000) {
      const key = Object.keys(err.keyPattern ?? {})[0] ?? '';
      const field = key.startsWith('username') ? 'username' : key.startsWith('email') ? 'email' : key.startsWith('name') ? 'name' : key;
      throw new DuplicateKeyError(field);
    }
    throw err;
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fromUserDoc(doc: UserDoc | null): User | null {
  if (!doc) return null;
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { _id, usernameLower, emailLower, ...rest } = doc;
  return { id: _id, ...rest, teamIds: rest.teamIds ?? [], mfaRecoveryCodes: rest.mfaRecoveryCodes ?? [], mfaLastUsedStep: rest.mfaLastUsedStep ?? null };
}

function fromTeamDoc(doc: TeamDoc | null): Team | null {
  if (!doc) return null;
  return { id: doc._id, name: doc.name, description: doc.description, createdAt: doc.createdAt, updatedAt: doc.updatedAt };
}

class MongoUserRepo implements UserRepo {
  constructor(private readonly col: Collection<UserDoc>) {}

  async create(input: NewUser): Promise<User> {
    const now = new Date();
    const doc: UserDoc = {
      _id: randomUUID(),
      username: input.username,
      usernameLower: input.username.toLowerCase(),
      email: input.email,
      emailLower: input.email?.toLowerCase() ?? null,
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      role: input.role,
      teamIds: [...new Set(input.teamIds)],
      status: 'active',
      mustChangePassword: input.mustChangePassword,
      mfaEnabled: false,
      mfaSecretEnc: null,
      mfaPendingSecretEnc: null,
      mfaRecoveryCodes: [],
      mfaLastUsedStep: null,
      failedLoginCount: 0,
      lockedUntil: null,
      lastLoginAt: null,
      passwordChangedAt: now,
      createdAt: now,
      updatedAt: now,
    };
    await mapDuplicate(() => this.col.insertOne(doc));
    return fromUserDoc(doc)!;
  }

  async findById(id: string): Promise<User | null> {
    return fromUserDoc(await this.col.findOne({ _id: id }));
  }

  async findByUsername(username: string): Promise<User | null> {
    return fromUserDoc(await this.col.findOne({ usernameLower: username.toLowerCase() }));
  }

  async findByEmail(email: string): Promise<User | null> {
    return fromUserDoc(await this.col.findOne({ emailLower: email.toLowerCase() }));
  }

  async update(id: string, patch: UserPatch): Promise<User | null> {
    const set: Partial<UserDoc> = { ...patch, updatedAt: new Date() };
    if (patch.email !== undefined) set.emailLower = patch.email?.toLowerCase() ?? null;
    if (patch.teamIds !== undefined) set.teamIds = [...new Set(patch.teamIds)];
    const doc = await mapDuplicate(() => this.col.findOneAndUpdate({ _id: id }, { $set: set }, { returnDocument: 'after' }));
    return fromUserDoc(doc);
  }

  async incrementFailedLogins(id: string): Promise<number> {
    const doc = await this.col.findOneAndUpdate({ _id: id }, { $inc: { failedLoginCount: 1 } }, { returnDocument: 'after', projection: { failedLoginCount: 1 } });
    return doc?.failedLoginCount ?? 0;
  }

  async list(filter: UserListFilter): Promise<Page<User>> {
    const q: Filter<UserDoc> = {};
    if (filter.search) {
      const re = new RegExp(escapeRegex(filter.search), 'i');
      q.$or = [{ username: re }, { displayName: re }, { email: re }];
    }
    if (filter.role) q.role = filter.role;
    if (filter.status) q.status = filter.status;
    if (filter.teamId) q.teamIds = filter.teamId;
    const [total, docs] = await Promise.all([
      this.col.countDocuments(q),
      this.col.find(q).sort({ usernameLower: 1 }).skip(filter.offset).limit(filter.limit).toArray(),
    ]);
    return { items: docs.map((d) => fromUserDoc(d)!), total };
  }

  count(): Promise<number> {
    return this.col.countDocuments();
  }
}

class MongoTeamRepo implements TeamRepo {
  constructor(
    private readonly col: Collection<TeamDoc>,
    private readonly users: Collection<UserDoc>,
    private readonly db: Db,
  ) {}

  async create(input: { name: string; description: string | null }): Promise<Team> {
    const now = new Date();
    const doc: TeamDoc = { _id: randomUUID(), name: input.name, nameLower: input.name.toLowerCase(), description: input.description, createdAt: now, updatedAt: now };
    await mapDuplicate(() => this.col.insertOne(doc));
    return fromTeamDoc(doc)!;
  }

  async findById(id: string): Promise<Team | null> {
    return fromTeamDoc(await this.col.findOne({ _id: id }));
  }

  async findByIds(ids: string[]): Promise<Team[]> {
    if (ids.length === 0) return [];
    return (await this.col.find({ _id: { $in: ids } }).toArray()).map((d) => fromTeamDoc(d)!);
  }

  async update(id: string, patch: { name?: string; description?: string | null }): Promise<Team | null> {
    const set: Partial<TeamDoc> = { updatedAt: new Date() };
    if (patch.name !== undefined) Object.assign(set, { name: patch.name, nameLower: patch.name.toLowerCase() });
    if (patch.description !== undefined) set.description = patch.description;
    return fromTeamDoc(await mapDuplicate(() => this.col.findOneAndUpdate({ _id: id }, { $set: set }, { returnDocument: 'after' })));
  }

  async delete(id: string): Promise<boolean> {
    const res = await this.col.deleteOne({ _id: id });
    if (res.deletedCount === 0) return false;
    await this.users.updateMany({ teamIds: id }, { $pull: { teamIds: id } });
    // Mirrors the ON DELETE SET NULL foreign keys of the PostgreSQL schema.
    await this.db.collection('repositories').updateMany({ teamId: id }, { $set: { teamId: null } });
    await this.db.collection('sources').updateMany({ defaultTeamId: id }, { $set: { defaultTeamId: null } });
    await this.db.collection('credentials').updateMany({ teamId: id }, { $set: { teamId: null } });
    return true;
  }

  async list(): Promise<TeamWithCount[]> {
    const docs = await this.col.find().sort({ nameLower: 1 }).toArray();
    const counts = await this.users
      .aggregate<{ _id: string; n: number }>([
        { $match: { teamIds: { $in: docs.map((d) => d._id) } } },
        { $unwind: '$teamIds' },
        { $group: { _id: '$teamIds', n: { $sum: 1 } } },
      ])
      .toArray();
    const byTeam = new Map(counts.map((c) => [c._id, c.n]));
    return docs.map((d) => ({ ...fromTeamDoc(d)!, memberCount: byTeam.get(d._id) ?? 0 }));
  }
}

class MongoSessionRepo implements SessionRepo {
  constructor(private readonly col: Collection<SessionDoc>) {}

  async create(input: NewSession): Promise<Session> {
    const session: Session = { ...input, id: randomUUID(), revokedAt: null, createdAt: new Date(), lastUsedAt: null };
    const { id, ...rest } = session;
    await this.col.insertOne({ _id: id, ...rest });
    return session;
  }

  async findByTokenHash(tokenHash: string): Promise<Session | null> {
    const doc = await this.col.findOne({ tokenHash });
    if (!doc) return null;
    const { _id, ...rest } = doc;
    return { id: _id, ...rest };
  }

  async revokeIfActive(id: string): Promise<boolean> {
    const now = new Date();
    const res = await this.col.updateOne({ _id: id, revokedAt: null }, { $set: { revokedAt: now, lastUsedAt: now } });
    return res.modifiedCount > 0;
  }

  async revokeFamily(familyId: string): Promise<number> {
    return (await this.col.updateMany({ familyId, revokedAt: null }, { $set: { revokedAt: new Date() } })).modifiedCount;
  }

  async revokeAllForUser(userId: string, exceptId?: string): Promise<number> {
    const q: Filter<SessionDoc> = { userId, revokedAt: null };
    if (exceptId) q._id = { $ne: exceptId };
    return (await this.col.updateMany(q, { $set: { revokedAt: new Date() } })).modifiedCount;
  }

  async deleteExpired(before: Date): Promise<number> {
    return (await this.col.deleteMany({ expiresAt: { $lt: before } })).deletedCount;
  }
}

class MongoAuditRepo implements AuditRepo {
  constructor(private readonly col: Collection<AuditDoc>) {}

  async append(entry: NewAuditEntry): Promise<AuditEntry> {
    const record: AuditEntry = { ...entry, id: randomUUID(), at: entry.at ?? new Date() };
    const { id, ...rest } = record;
    await this.col.insertOne({ _id: id, ...rest });
    return record;
  }
  async deleteBefore(before: Date): Promise<number> {
    return (await this.col.deleteMany({ at: { $lt: before } })).deletedCount;
  }


  async list(filter: AuditFilter): Promise<Page<AuditEntry>> {
    const q: Filter<AuditDoc> = {};
    if (filter.actorId) q.actorId = filter.actorId;
    if (filter.action) q.action = filter.action;
    if (filter.targetType) q.targetType = filter.targetType;
    if (filter.targetId) q.targetId = filter.targetId;
    if (filter.outcome) q.outcome = filter.outcome;
    if (filter.from || filter.to) q.at = { ...(filter.from ? { $gte: filter.from } : {}), ...(filter.to ? { $lte: filter.to } : {}) };
    const [total, docs] = await Promise.all([
      this.col.countDocuments(q),
      this.col.find(q).sort({ at: -1 }).skip(filter.offset).limit(filter.limit).toArray(),
    ]);
    return { items: docs.map(({ _id, ...rest }) => ({ id: _id, ...rest })), total };
  }
}

class MongoSettingsRepo implements SettingsRepo {
  constructor(private readonly col: Collection<SettingDoc>) {}

  async get<T>(key: string): Promise<SettingRecord<T> | null> {
    const doc = await this.col.findOne({ _id: key });
    return doc ? { key, value: doc.value as T, updatedAt: doc.updatedAt, updatedBy: doc.updatedBy } : null;
  }

  async set<T>(key: string, value: T, updatedBy: string | null): Promise<SettingRecord<T>> {
    const updatedAt = new Date();
    await this.col.updateOne({ _id: key }, { $set: { value, updatedAt, updatedBy } }, { upsert: true });
    return { key, value, updatedAt, updatedBy };
  }
}

async function bootstrap(db: Db): Promise<void> {
  const meta = db.collection<MetaDoc>('_meta');
  const current = await meta.findOne({ _id: 'schema' });
  if (current && current.version >= SCHEMA_VERSION) return;

  // createIndex is idempotent, so concurrent bootstraps from several instances are safe.
  await db.collection('users').createIndexes([
    { key: { usernameLower: 1 }, unique: true, name: 'username_unique' },
    { key: { emailLower: 1 }, unique: true, name: 'email_unique', partialFilterExpression: { emailLower: { $type: 'string' } } },
    { key: { teamIds: 1 }, name: 'team_ids' },
    { key: { role: 1, status: 1 }, name: 'role_status' },
  ]);
  await db.collection('teams').createIndexes([{ key: { nameLower: 1 }, unique: true, name: 'name_unique' }]);
  await db.collection('sessions').createIndexes([
    { key: { tokenHash: 1 }, unique: true, name: 'token_hash_unique' },
    { key: { userId: 1 }, name: 'user' },
    { key: { familyId: 1 }, name: 'family' },
    { key: { expiresAt: 1 }, name: 'expires_ttl', expireAfterSeconds: 0 },
  ]);
  await db.collection('audit_logs').createIndexes([
    { key: { at: -1 }, name: 'at' },
    { key: { actorId: 1, at: -1 }, name: 'actor_at' },
    { key: { action: 1, at: -1 }, name: 'action_at' },
    { key: { targetType: 1, targetId: 1 }, name: 'target' },
  ]);
  await bootstrapScanningIndexes(db);
  await bootstrapPrScanIndexes(db);
  await bootstrapFindingIndexes(db);
  await bootstrapTicketIndexes(db);
  await bootstrapAiIndexes(db);
  await bootstrapIntelIndexes(db);
  await bootstrapPlatformIndexes(db);
  await meta.updateOne({ _id: 'schema' }, { $set: { version: SCHEMA_VERSION, updatedAt: new Date() } }, { upsert: true });
}

export async function createMongoStore(url: string, dbName?: string): Promise<DataStore> {
  const client = new MongoClient(url, { appName: 'argus' });
  await client.connect();
  const fromUrl = client.options.dbName;
  const db = client.db(dbName ?? (fromUrl && fromUrl !== 'test' ? fromUrl : 'argus'));
  const users = db.collection<UserDoc>('users');
  const repositories = db.collection<RepositoryDoc>('repositories');
  const scanRuns = db.collection<ScanRunDoc>('scan_runs');
  return {
    kind: 'mongodb',
    users: new MongoUserRepo(users),
    teams: new MongoTeamRepo(db.collection<TeamDoc>('teams'), users, db),
    sessions: new MongoSessionRepo(db.collection<SessionDoc>('sessions')),
    audit: new MongoAuditRepo(db.collection<AuditDoc>('audit_logs')),
    settings: new MongoSettingsRepo(db.collection<SettingDoc>('settings')),
    sources: new MongoSourceRepo(db.collection<SourceDoc>('sources'), repositories, scanRuns, db),
    repositories: new MongoRepositoryRepo(repositories),
    scanRuns: new MongoScanRunRepo(scanRuns),
    prScans: new MongoPrScanRepo(db.collection<PrScanDoc>('pr_scans')),
    jobs: new MongoJobRepo(db.collection<JobDoc>('jobs')),
    locks: new MongoLockRepo(db.collection<LockDoc>('locks')),
    findings: new MongoFindingRepo(db.collection<FindingDoc>('findings')),
    dependencies: new MongoDependencyRepo(db.collection<DependencyDoc>('dependencies')),
    suppressions: new MongoSuppressionRepo(db.collection<SuppressionDoc>('suppressions')),
    cache: new MongoCacheRepo(db.collection<CacheDoc>('intel_cache')),
    tickets: new MongoTicketRepo(db.collection<TicketDoc>('tickets'), db.collection<TicketEventDoc>('ticket_events')),
    counters: new MongoCounterRepo(db.collection<CounterDoc>('counters')),
    channels: new MongoChannelRepo(db.collection<ChannelDoc>('notification_channels')),
    notificationRules: new MongoNotificationRuleRepo(db.collection<RuleDoc>('notification_rules')),
    aiUsage: new MongoAiUsageRepo(db.collection<AiUsageDoc>('ai_usage')),
    aiInsights: new MongoAiInsightRepo(db.collection<AiInsightDoc>('ai_insights')),
    intelSources: new MongoIntelSourceRepo(db.collection<IntelSourceDoc>('intel_sources'), db.collection<IntelItemDoc>('intel_items')),
    intelItems: new MongoIntelItemRepo(db.collection<IntelItemDoc>('intel_items')),
    apiTokens: new MongoApiTokenRepo(db.collection<ApiTokenDoc>('api_tokens')),
    credentials: new MongoCredentialRepo(db.collection<CredentialDoc>('credentials')),
    savedViews: new MongoSavedViewRepo(db.collection<SavedViewDoc>('saved_views')),
    invites: new MongoInviteRepo(db.collection<InviteDoc>('invites')),
    loginLinks: new MongoLoginLinkRepo(db.collection<LoginLinkDoc>('login_links')),
    advisories: new MongoAdvisoryRepo(db.collection<AdvisoryDoc>('advisories'), db.collection<{ _id: string; value: number }>('counters')),
    migrate: () => bootstrap(db),
    async ping() {
      try {
        await db.command({ ping: 1 });
        return true;
      } catch {
        return false;
      }
    },
    async close() {
      await client.close();
    },
  };
}
