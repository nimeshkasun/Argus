import { type Ecosystem, type FindingAdvisory, type FindingPackage, type FindingSecret, type FindingStatus, type RiskFactor, type ScannerName, type Severity } from '@argus/shared';

export interface Finding {
  id: string;
  repoId: string;
  sourceId: string;
  /** Owning team of the repository (kept in sync when the repository moves team), for scoped queries. */
  teamId: string | null;
  scanner: ScannerName;
  ruleId: string;
  /** Stable identity of the issue within the repository; the same issue in later scans maps to the same finding. */
  fingerprint: string;
  title: string;
  description: string | null;
  severity: Severity;
  riskScore: number;
  riskFactors: RiskFactor[];
  status: FindingStatus;
  path: string | null;
  line: number | null;
  package: FindingPackage | null;
  advisory: FindingAdvisory | null;
  secret: FindingSecret | null;
  details: Record<string, unknown> | null;
  remediation: string | null;
  suppressionId: string | null;
  /** Ticket tracking this finding, once one exists. */
  ticketId: string | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
  firstRunId: string;
  lastRunId: string;
  fixedAt: Date | null;
}

/** A finding as produced by a scan, before reconciliation with stored state. */
export type ObservedFinding = Omit<Finding, 'id' | 'repoId' | 'sourceId' | 'teamId' | 'status' | 'ticketId' | 'firstSeenAt' | 'lastSeenAt' | 'firstRunId' | 'lastRunId' | 'fixedAt'>;

export interface ReconcileContext {
  repoId: string;
  sourceId: string;
  teamId: string | null;
  runId: string;
  /** Scanners that completed in this run. Only their unseen findings are marked fixed. */
  scanners: ScannerName[];
  now: Date;
}

export interface ReconcileResult {
  opened: number;
  reopened: number;
  fixed: number;
  unchanged: number;
}

export interface FindingListFilter {
  repoId?: string;
  scanner?: ScannerName;
  severities?: Severity[];
  status?: FindingStatus;
  /** Matches title, rule id, path or package name. */
  search?: string;
  visibleTeamIds?: string[];
  offset: number;
  limit: number;
}

export interface FindingSummaryRecord {
  open: Record<Severity, number>;
  suppressed: number;
  fixedSince: number;
  byScanner: Record<ScannerName, number>;
}

export interface Dependency {
  repoId: string;
  teamId: string | null;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  license: string | null;
  manifestPath: string;
  latestVersion: string | null;
  deprecated: string | null;
  vulnerabilities: number;
}

export interface DependencyListFilter {
  search?: string;
  ecosystem?: Ecosystem;
  vulnerableOnly?: boolean;
  offset: number;
  limit: number;
}

export interface DependencySearchFilter {
  /** Exact package name, case-insensitive. */
  name: string;
  ecosystem?: Ecosystem;
  visibleTeamIds?: string[];
  limit: number;
}

export interface Suppression {
  id: string;
  repoId: string | null;
  scanner: ScannerName | null;
  ruleId: string | null;
  pathPattern: string | null;
  packageName: string | null;
  /** Matches findings of one ticket's issue (set when a ticket is risk-accepted or marked a false positive). */
  groupKey: string | null;
  ticketId: string | null;
  reason: string;
  expiresAt: Date | null;
  createdBy: string | null;
  createdByName: string | null;
  createdAt: Date;
}

export type NewSuppression = Omit<Suppression, 'id' | 'createdAt'>;

export interface CacheEntry<T = unknown> {
  key: string;
  value: T;
  fetchedAt: Date;
  expiresAt: Date;
}
