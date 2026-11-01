import { type PrScanFailOn, type PrScanResult, type PrScanStatus, type ScanStats, type ScannerName } from '@argus/shared';
import { type Page } from './models';

// ---------------------------------------------------------------- sources & repositories

export type Provider = 'github' | 'bitbucket_cloud' | 'bitbucket_server';
export type SourceStatus = 'pending' | 'ok' | 'error';

export interface Source {
  id: string;
  name: string;
  provider: Provider;
  baseUrl: string | null;
  scope: string | null;
  username: string | null;
  /** Access token, encrypted by the application. */
  tokenEnc: string;
  tokenLast4: string;
  /** Push-webhook HMAC secret, encrypted by the application. */
  webhookSecretEnc: string;
  autoActivatePattern: string | null;
  defaultTeamId: string | null;
  status: SourceStatus;
  lastSyncAt: Date | null;
  lastSyncError: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type NewSource = Omit<Source, 'id' | 'status' | 'lastSyncAt' | 'lastSyncError' | 'createdAt' | 'updatedAt'>;
export type SourcePatch = Partial<Omit<Source, 'id' | 'provider' | 'createdAt' | 'updatedAt'>>;

export interface SourceWithCounts extends Source {
  repoCount: number;
  activeRepoCount: number;
}

export type Visibility = 'public' | 'private' | 'internal';
export type Criticality = 'low' | 'medium' | 'high' | 'critical';
export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface RepoSchedule {
  preset: 'hourly' | 'daily' | 'weekly' | 'manual' | 'custom';
  cron?: string | null;
}

/** Repository metadata as reported by the source provider. */
export interface DiscoveredRepo {
  externalId: string;
  fullName: string;
  name: string;
  htmlUrl: string | null;
  cloneUrl: string;
  defaultBranch: string | null;
  visibility: Visibility;
  language: string | null;
  description: string | null;
  archived: boolean;
  lastPushedAt: Date | null;
}

export interface Repository extends DiscoveredRepo {
  id: string;
  sourceId: string;
  /** Set when the repository disappeared from the source (deleted, or the token lost access). */
  removedAt: Date | null;
  active: boolean;
  teamId: string | null;
  criticality: Criticality;
  branch: string | null;
  schedule: RepoSchedule;
  scanOnPush: boolean;
  jiraProjectKey: string | null;
  notifyEmails: string[];
  disabledScanners: ScannerName[];
  /** false excludes the repository from every AI feature. */
  aiEnabled: boolean;
  nextScanAt: Date | null;
  lastScanAt: Date | null;
  lastScanStatus: ScanStatus | null;
  lastScanRunId: string | null;
  createdAt: Date;
  updatedAt: Date;
}

export type RepositoryPatch = Partial<
  Pick<
    Repository,
    'active' | 'teamId' | 'criticality' | 'branch' | 'schedule' | 'scanOnPush' | 'jiraProjectKey' | 'notifyEmails' | 'disabledScanners' | 'aiEnabled' | 'nextScanAt' | 'lastScanAt' | 'lastScanStatus' | 'lastScanRunId'
  >
>;

/** Settings applied to repositories the first time they are discovered. */
export interface DiscoveryDefaults {
  /** Whether a newly discovered repository should start active (auto-activation pattern). */
  activate: (repo: DiscoveredRepo) => boolean;
  teamId: string | null;
  schedule: RepoSchedule;
  /** nextScanAt for newly activated repositories. */
  firstScanAt: Date;
}

export interface SyncResult {
  added: number;
  updated: number;
  removed: number;
  /** Ids of repositories activated by this sync. */
  activated: string[];
}

export interface RepositoryListFilter {
  search?: string;
  sourceId?: string;
  teamId?: string;
  active?: boolean;
  /** Restricts results to these teams (team-scoped roles). Undefined means no restriction. */
  visibleTeamIds?: string[];
  includeRemoved?: boolean;
  offset: number;
  limit: number;
}

// ---------------------------------------------------------------- scan runs

export type ScanTrigger = 'schedule' | 'manual' | 'push' | 'activation';

export type ScanStatsRecord = ScanStats;

export interface ScanRun {
  id: string;
  repoId: string;
  sourceId: string;
  /** Owning team at queue time, for team-scoped listing. */
  teamId: string | null;
  trigger: ScanTrigger;
  status: ScanStatus;
  requestedBy: string | null;
  branch: string | null;
  commitSha: string | null;
  attempts: number;
  queuedAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
  durationMs: number | null;
  error: string | null;
  stats: ScanStatsRecord | null;
  log: string[];
}

export type NewScanRun = Pick<ScanRun, 'repoId' | 'sourceId' | 'teamId' | 'trigger' | 'requestedBy' | 'branch'>;
export type ScanRunPatch = Partial<Omit<ScanRun, 'id' | 'repoId' | 'sourceId' | 'trigger' | 'requestedBy' | 'queuedAt'>>;

export interface ScanRunListFilter {
  repoId?: string;
  status?: ScanStatus;
  visibleTeamIds?: string[];
  offset: number;
  limit: number;
}

export type ScanRunPage = Page<ScanRun>;

// ---------------------------------------------------------------- pull request scans

/** A scan of a pull request requested from CI. Its findings are a preview: they never become repository findings. */
export interface PrScan {
  id: string;
  repoId: string;
  sourceId: string;
  number: number;
  title: string | null;
  url: string | null;
  headSha: string | null;
  headBranch: string | null;
  baseBranch: string | null;
  status: PrScanStatus;
  failOn: PrScanFailOn;
  /** Post the summary comment on the pull request. */
  comment: boolean;
  requestedBy: string | null;
  result: PrScanResult | null;
  /** The summary comment this scan posted or updated, so later scans of the pull request update it. */
  commentId: string | null;
  commentUrl: string | null;
  error: string | null;
  log: string[];
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
}

export type NewPrScan = Pick<PrScan, 'repoId' | 'sourceId' | 'number' | 'title' | 'url' | 'headSha' | 'headBranch' | 'baseBranch' | 'failOn' | 'comment' | 'requestedBy'>;
export type PrScanPatch = Partial<Pick<PrScan, 'status' | 'headSha' | 'result' | 'commentId' | 'commentUrl' | 'error' | 'log' | 'startedAt' | 'finishedAt'>>;

// ---------------------------------------------------------------- jobs

export type JobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';

export interface Job<P = Record<string, unknown>> {
  id: string;
  type: string;
  payload: P;
  status: JobStatus;
  priority: number;
  runAt: Date;
  attempts: number;
  maxAttempts: number;
  lockedBy: string | null;
  lockedUntil: Date | null;
  lastError: string | null;
  /** At most one queued/running job may hold a given dedupe key. */
  dedupeKey: string | null;
  createdAt: Date;
  updatedAt: Date;
  finishedAt: Date | null;
}

export interface NewJob {
  type: string;
  payload: Record<string, unknown>;
  priority?: number;
  runAt?: Date;
  maxAttempts?: number;
  dedupeKey?: string | null;
}
