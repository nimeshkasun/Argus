import { type PrScanResult } from '@argus/shared';
import { type ColumnType } from 'kysely';

/** jsonb columns: read as parsed JSON, written as a JSON string (node-postgres would mangle JS arrays). */
type Json<T> = ColumnType<T, string, string>;

export interface UsersTable {
  id: string;
  username: string;
  usernameLower: string;
  email: string | null;
  emailLower: string | null;
  displayName: string;
  passwordHash: string;
  role: string;
  status: string;
  mustChangePassword: boolean;
  mfaEnabled: boolean;
  mfaSecretEnc: string | null;
  mfaPendingSecretEnc: string | null;
  mfaRecoveryCodes: Json<string[]>;
  mfaLastUsedStep: number | null;
  failedLoginCount: number;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  passwordChangedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TeamsTable {
  id: string;
  name: string;
  nameLower: string;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface TeamMembersTable {
  teamId: string;
  userId: string;
}

export interface SessionsTable {
  id: string;
  userId: string;
  tokenHash: string;
  familyId: string;
  expiresAt: Date;
  revokedAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  userAgent: string | null;
  ip: string | null;
}

export interface AuditLogsTable {
  id: string;
  at: Date;
  actorId: string | null;
  actorName: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  ip: string | null;
  outcome: string;
  details: Json<Record<string, unknown> | null> | null;
}

export interface SettingsTable {
  key: string;
  value: Json<unknown>;
  updatedAt: Date;
  updatedBy: string | null;
}

export interface SourcesTable {
  id: string;
  name: string;
  provider: string;
  baseUrl: string | null;
  scope: string | null;
  username: string | null;
  tokenEnc: string;
  tokenLast4: string;
  webhookSecretEnc: string;
  autoActivatePattern: string | null;
  defaultTeamId: string | null;
  status: string;
  lastSyncAt: Date | null;
  lastSyncError: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface RepositoriesTable {
  id: string;
  sourceId: string;
  externalId: string;
  fullName: string;
  name: string;
  htmlUrl: string | null;
  cloneUrl: string;
  defaultBranch: string | null;
  visibility: string;
  language: string | null;
  description: string | null;
  archived: boolean;
  lastPushedAt: Date | null;
  removedAt: Date | null;
  active: boolean;
  teamId: string | null;
  criticality: string;
  branch: string | null;
  schedule: Json<{ preset: string; cron?: string | null }>;
  scanOnPush: boolean;
  jiraProjectKey: string | null;
  notifyEmails: Json<string[]>;
  disabledScanners: Json<string[]>;
  aiEnabled: boolean;
  nextScanAt: Date | null;
  lastScanAt: Date | null;
  lastScanStatus: string | null;
  lastScanRunId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScanRunsTable {
  id: string;
  repoId: string;
  sourceId: string;
  teamId: string | null;
  trigger: string;
  status: string;
  requestedBy: string | null;
  branch: string | null;
  commitSha: string | null;
  attempts: number;
  queuedAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
  durationMs: number | null;
  error: string | null;
  stats: Json<{ files: number; bytes: number; ecosystems: string[]; manifests: string[] } | null> | null;
  log: Json<string[]>;
}

export interface PrScansTable {
  id: string;
  repoId: string;
  sourceId: string;
  number: number;
  title: string | null;
  url: string | null;
  headSha: string | null;
  headBranch: string | null;
  baseBranch: string | null;
  status: string;
  failOn: string;
  comment: boolean;
  requestedBy: string | null;
  result: Json<PrScanResult | null> | null;
  commentId: string | null;
  commentUrl: string | null;
  error: string | null;
  log: Json<string[]>;
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
}

export interface JobsTable {
  id: string;
  type: string;
  payload: Json<Record<string, unknown>>;
  status: string;
  priority: number;
  runAt: Date;
  attempts: number;
  maxAttempts: number;
  lockedBy: string | null;
  lockedUntil: Date | null;
  lastError: string | null;
  dedupeKey: string | null;
  /** Equals dedupeKey while the job is queued/running, null afterwards; uniquely indexed. */
  activeDedupeKey: string | null;
  createdAt: Date;
  updatedAt: Date;
  finishedAt: Date | null;
}

export interface LocksTable {
  name: string;
  owner: string;
  expiresAt: Date;
}

export interface FindingsTable {
  id: string;
  repoId: string;
  sourceId: string;
  teamId: string | null;
  scanner: string;
  ruleId: string;
  fingerprint: string;
  title: string;
  description: string | null;
  severity: string;
  riskScore: number;
  riskFactors: Json<unknown[]>;
  status: string;
  path: string | null;
  line: number | null;
  packageEcosystem: string | null;
  packageName: string | null;
  package: Json<Record<string, unknown> | null> | null;
  advisory: Json<Record<string, unknown> | null> | null;
  secret: Json<Record<string, unknown> | null> | null;
  details: Json<Record<string, unknown> | null> | null;
  remediation: string | null;
  suppressionId: string | null;
  ticketId: string | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  firstRunId: string;
  lastRunId: string;
  fixedAt: Date | null;
}

export interface DependenciesTable {
  id: string;
  repoId: string;
  teamId: string | null;
  ecosystem: string;
  name: string;
  nameLower: string;
  version: string;
  direct: boolean;
  dev: boolean;
  license: string | null;
  manifestPath: string;
  latestVersion: string | null;
  deprecated: string | null;
  vulnerabilities: number;
}

export interface SuppressionsTable {
  id: string;
  repoId: string | null;
  scanner: string | null;
  ruleId: string | null;
  pathPattern: string | null;
  packageName: string | null;
  groupKey: string | null;
  ticketId: string | null;
  reason: string;
  expiresAt: Date | null;
  createdBy: string | null;
  createdByName: string | null;
  createdAt: Date;
}

export interface IntelCacheTable {
  key: string;
  value: Json<unknown>;
  fetchedAt: Date;
  expiresAt: Date;
}

export interface TicketsTable {
  id: string;
  key: string;
  repoId: string;
  sourceId: string;
  teamId: string | null;
  scanner: string;
  groupKey: string;
  title: string;
  description: string | null;
  severity: string;
  riskScore: number;
  status: string;
  assigneeId: string | null;
  watcherIds: Json<string[]>;
  labels: Json<string[]>;
  findingIds: Json<string[]>;
  openFindings: number;
  remediation: string | null;
  dueAt: Date | null;
  slaBreachedAt: Date | null;
  suppressionId: string | null;
  jira: Json<Record<string, unknown> | null> | null;
  resolvedAt: Date | null;
  closedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  lastActivityAt: Date;
}

export interface TicketEventsTable {
  id: string;
  ticketId: string;
  type: string;
  actorId: string | null;
  actorName: string | null;
  body: string | null;
  data: Json<Record<string, unknown> | null> | null;
  createdAt: Date;
}

export interface CountersTable {
  name: string;
  value: number;
}

export interface NotificationChannelsTable {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  config: Json<Record<string, unknown>>;
  secretEnc: string | null;
  secretHint: string | null;
  lastUsedAt: Date | null;
  lastError: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface NotificationRulesTable {
  id: string;
  name: string;
  enabled: boolean;
  events: Json<string[]>;
  minSeverity: string;
  teamIds: Json<string[]>;
  channelIds: Json<string[]>;
  recipients: Json<string[]>;
  includeRepoRecipients: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface AiUsageTable {
  id: string;
  at: Date;
  provider: string;
  model: string;
  useCase: string;
  userId: string | null;
  repoId: string | null;
  inputTokens: number;
  outputTokens: number;
  costUsd: ColumnType<number, number, number>;
  outcome: string;
}

export interface AiInsightsTable {
  id: string;
  subjectType: string;
  subjectId: string;
  repoId: string;
  useCase: string;
  provider: string;
  model: string;
  output: Json<Record<string, unknown>>;
  redactions: number;
  createdBy: string | null;
  createdAt: Date;
}

export interface IntelSourcesTable {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  intervalMinutes: number;
  lastFetchedAt: Date | null;
  lastError: string | null;
  lastNewItems: number | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface IntelItemsTable {
  id: string;
  sourceId: string;
  guid: string;
  title: string;
  link: string | null;
  publishedAt: Date | null;
  summary: string;
  status: string;
  candidates: Json<unknown[]>;
  extraction: ColumnType<Record<string, unknown> | null, string | null, string | null>;
  error: string | null;
  advisoryIds: Json<string[]>;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  fetchedAt: Date;
}

export interface AdvisoriesTable {
  id: string;
  key: string;
  ecosystem: string;
  packageName: string;
  /** Lower-cased for NuGet, as-is for npm. */
  packageKey: string;
  affectedRange: string;
  fixedVersion: string | null;
  severity: string;
  cvssScore: number | null;
  cveIds: Json<string[]>;
  title: string;
  summary: string;
  refs: Json<string[]>;
  source: string;
  sourceItemId: string | null;
  withdrawn: boolean;
  autoApproved: boolean;
  createdBy: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiTokensTable {
  id: string;
  userId: string;
  name: string;
  tokenHash: string;
  prefix: string;
  scopes: Json<string[]>;
  expiresAt: Date;
  lastUsedAt: Date | null;
  lastUsedIp: string | null;
  revokedAt: Date | null;
  createdAt: Date;
}

export interface CredentialsTable {
  id: string;
  name: string;
  kind: string;
  system: string;
  owner: string;
  teamId: string | null;
  expiresAt: Date;
  notes: string;
  notifyEmails: Json<string[]>;
  source: string;
  externalId: string | null;
  archived: boolean;
  lastNoticeDays: number | null;
  createdBy: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface SavedViewsTable {
  id: string;
  userId: string;
  page: string;
  name: string;
  query: string;
  shared: boolean;
  createdAt: Date;
}

export interface InvitesTable {
  id: string;
  tokenHash: string;
  role: string;
  teamIds: Json<string[]>;
  emails: Json<string[]>;
  usedEmails: Json<string[]>;
  maxUses: number;
  uses: number;
  expiresAt: Date;
  note: string;
  createdBy: string | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}

export interface LoginLinksTable {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
  requestedIp: string | null;
}

export interface Database {
  users: UsersTable;
  teams: TeamsTable;
  teamMembers: TeamMembersTable;
  sessions: SessionsTable;
  auditLogs: AuditLogsTable;
  settings: SettingsTable;
  sources: SourcesTable;
  repositories: RepositoriesTable;
  scanRuns: ScanRunsTable;
  prScans: PrScansTable;
  jobs: JobsTable;
  locks: LocksTable;
  findings: FindingsTable;
  dependencies: DependenciesTable;
  suppressions: SuppressionsTable;
  intelCache: IntelCacheTable;
  tickets: TicketsTable;
  ticketEvents: TicketEventsTable;
  counters: CountersTable;
  notificationChannels: NotificationChannelsTable;
  notificationRules: NotificationRulesTable;
  aiUsage: AiUsageTable;
  aiInsights: AiInsightsTable;
  intelSources: IntelSourcesTable;
  intelItems: IntelItemsTable;
  advisories: AdvisoriesTable;
  apiTokens: ApiTokensTable;
  credentials: CredentialsTable;
  savedViews: SavedViewsTable;
  invites: InvitesTable;
  loginLinks: LoginLinksTable;
}
