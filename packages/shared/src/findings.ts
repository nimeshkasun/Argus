import { z } from 'zod';
import { type FindingAiHintDto } from './ai';
import { pageFields } from './schemas';

export const SCANNERS = ['secrets', 'dependencies', 'frameworks', 'certificates', 'licenses', 'code', 'iac', 'containers'] as const;
export type ScannerName = (typeof SCANNERS)[number];

export const SCANNER_LABELS: Record<ScannerName, string> = {
  secrets: 'Leaked secrets',
  dependencies: 'Vulnerable & deprecated packages',
  frameworks: 'End-of-life frameworks & runtimes',
  certificates: 'Certificates & credential expiry',
  licenses: 'License policy',
  code: 'Code weaknesses (static analysis)',
  iac: 'Infrastructure-as-code misconfigurations',
  containers: 'Container image vulnerabilities',
};

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = ['open', 'suppressed', 'fixed'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const ECOSYSTEMS = ['npm', 'nuget', 'pypi', 'maven', 'go', 'cargo'] as const;
export type Ecosystem = (typeof ECOSYSTEMS)[number];

export const ECOSYSTEM_LABELS: Record<Ecosystem, string> = {
  npm: 'npm',
  nuget: 'NuGet',
  pypi: 'PyPI',
  maven: 'Maven',
  go: 'Go',
  cargo: 'Cargo',
};

/**
 * Name used to compare packages: NuGet ids and Cargo crate names are case-insensitive, and PyPI names are
 * normalised per PEP 503 ("Django_REST.framework" and "django-rest-framework" are the same project).
 * Maven ("group:artifact"), Go module paths and npm names are compared as written.
 */
export function canonicalPackageName(ecosystem: Ecosystem, name: string): string {
  switch (ecosystem) {
    case 'nuget':
    case 'cargo':
      return name.toLowerCase();
    case 'pypi':
      return name.toLowerCase().replace(/[-_.]+/g, '-');
    default:
      return name;
  }
}

/** Score (0-100) to severity band. */
export function severityForScore(score: number): Severity {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
}

export interface RiskFactor {
  /** Machine-readable key, e.g. "kev", "dev_dependency". */
  key: string;
  label: string;
  /** Points added to (or removed from) the score. The base factor carries the starting score. */
  points: number;
}

export interface FindingPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  /** Smallest version that fixes the issue, when known. */
  fixedVersion: string | null;
  latestVersion?: string | null;
}

export interface FindingAdvisory {
  id: string;
  aliases: string[];
  summary: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  epss: number | null;
  kev: boolean;
  url: string | null;
  published: string | null;
}

export interface FindingSecret {
  /** Rule or detector that matched, e.g. "aws-access-token". */
  type: string;
  /** Masked preview such as "AKIA…MPLE"; the full value is never stored. */
  preview: string;
  /** Keyed hash of the value, so the same secret is recognised across files and scans. */
  hash: string;
}

export interface FindingDto {
  id: string;
  repoId: string;
  repoFullName: string | null;
  scanner: ScannerName;
  ruleId: string;
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
  /** Scanner-specific facts, e.g. certificate subject and expiry, framework cycle and EOL date. */
  details: Record<string, unknown> | null;
  remediation: string | null;
  suppressionId: string | null;
  /** Ticket tracking this finding, if one has been opened. */
  ticketId: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  fixedAt: string | null;
  /** AI assessment of this finding, if one was made. Never changes status or score. */
  aiHint: FindingAiHintDto | null;
}

export interface FindingSummary {
  open: Record<Severity, number>;
  openTotal: number;
  suppressed: number;
  fixedLast30Days: number;
  byScanner: Record<ScannerName, number>;
}

const csv = <T extends z.ZodType>(item: T) =>
  z.preprocess((v) => (typeof v === 'string' ? v.split(',').filter(Boolean) : v), z.array(item).max(20)).optional();

export const listFindingsQuerySchema = z.object({
  repoId: z.uuid().optional(),
  scanner: z.enum(SCANNERS).optional(),
  severity: csv(z.enum(SEVERITIES)),
  status: z.enum(FINDING_STATUSES).optional(),
  search: z.string().trim().max(200).optional(),
  ...pageFields,
});
export type ListFindingsQuery = z.infer<typeof listFindingsQuerySchema>;

export const findingSummaryQuerySchema = z.object({ repoId: z.uuid().optional() });

export interface DependencyDto {
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

export const listDependenciesQuerySchema = z.object({
  search: z.string().trim().max(200).optional(),
  ecosystem: z.enum(ECOSYSTEMS).optional(),
  vulnerableOnly: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
  ...pageFields,
});
export type ListDependenciesQuery = z.infer<typeof listDependenciesQuerySchema>;

export const packageSearchQuerySchema = z.object({
  name: z.string().trim().min(1).max(214),
  ecosystem: z.enum(ECOSYSTEMS).optional(),
  /** Optional semver range, e.g. "<4.17.21". */
  version: z.string().trim().max(100).optional(),
  ...pageFields,
});
export type PackageSearchQuery = z.infer<typeof packageSearchQuerySchema>;

export interface PackageUsageDto {
  repoId: string;
  repoFullName: string;
  ecosystem: Ecosystem;
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  manifestPath: string;
}

export const suppressionSchema = z
  .object({
    /** Null means every repository the creator can manage (global). */
    repoId: z.uuid().nullable(),
    scanner: z.enum(SCANNERS).nullable().optional(),
    /** Advisory id, secret rule or other rule id. */
    ruleId: z.string().trim().min(1).max(200).nullable().optional(),
    /** Glob, e.g. "test/fixtures/**". */
    pathPattern: z.string().trim().min(1).max(500).nullable().optional(),
    packageName: z.string().trim().min(1).max(214).nullable().optional(),
    reason: z.string().trim().min(5).max(1000),
    expiresAt: z.coerce.date().nullable().optional(),
  })
  .refine((s) => s.scanner || s.ruleId || s.pathPattern || s.packageName, { message: 'Narrow the suppression with at least a scanner, rule, path or package.' });
export type SuppressionInput = z.infer<typeof suppressionSchema>;

export interface SuppressionDto {
  id: string;
  repoId: string | null;
  repoFullName: string | null;
  scanner: ScannerName | null;
  ruleId: string | null;
  pathPattern: string | null;
  packageName: string | null;
  reason: string;
  expiresAt: string | null;
  createdBy: string | null;
  createdByName: string | null;
  createdAt: string;
  /** Set when the suppression was created by risk-accepting a ticket. */
  ticketId: string | null;
  matchedFindings?: number;
}

export const riskWeightsSchema = z.object({
  kev: z.number().min(0).max(50),
  epssMax: z.number().min(0).max(50),
  publicRepo: z.number().min(0).max(50),
  devDependency: z.number().min(-50).max(0),
  transitiveDependency: z.number().min(-50).max(0),
  testPath: z.number().min(-50).max(0),
  criticalityLow: z.number().min(-50).max(50),
  criticalityHigh: z.number().min(-50).max(50),
  criticalityCritical: z.number().min(-50).max(50),
  /** Secret verified as working by its issuer (opt-in live verification). */
  verifiedActive: z.number().min(0).max(50).default(15),
  /** Secret rejected by its issuer: revoked or invalid. */
  verifiedInactive: z.number().min(-50).max(0).default(-30),
});
export type RiskWeights = z.infer<typeof riskWeightsSchema>;

export const scanningSettingsSchema = z.object({
  riskWeights: riskWeightsSchema,
  /** SPDX ids or prefixes (ending in "*") that are not allowed. */
  licenseDeny: z.array(z.string().trim().min(1).max(100)).max(200),
  /** SPDX ids or prefixes that are allowed but flagged for review. */
  licenseReview: z.array(z.string().trim().min(1).max(100)).max(200),
  /** Warn this many days before a framework/runtime reaches end of life. */
  eolWarningDays: z.number().int().min(0).max(730),
  /** Warn this many days before a certificate or token expires. */
  expiryWarningDays: z.number().int().min(1).max(365),
  /**
   * Check detected GitHub, GitLab, Slack and npm tokens with their issuer (one read-only request each) to tell
   * whether they still work. Off by default: it sends the detected secret to its own issuer.
   */
  verifySecrets: z.boolean().default(false),
  /**
   * Also scan this many recent commits of the scanned branch for secrets that were committed and later removed
   * (0 = only the current code). The clone then fetches that much history.
   */
  secretHistoryCommits: z.number().int().min(0).max(1000).default(0),
  /**
   * Scan the container images a repository references (Dockerfile FROM, Compose and Kubernetes manifests) for
   * vulnerable packages. Off by default: images are pulled from their registries.
   */
  containerImages: z
    .object({
      enabled: z.boolean(),
      /** Images scanned per repository scan; the rest are reported as skipped. */
      maxImages: z.number().int().min(1).max(50),
      /** Lowest severity reported. */
      minSeverity: z.enum(['critical', 'high', 'medium', 'low']),
      /** Only report vulnerabilities that have a fixed package version. */
      fixableOnly: z.boolean(),
    })
    .default({ enabled: false, maxImages: 10, minSeverity: 'high', fixableOnly: true }),
});
export type ScanningSettings = z.infer<typeof scanningSettingsSchema>;

export const DEFAULT_SCANNING_SETTINGS: ScanningSettings = {
  riskWeights: {
    kev: 15,
    epssMax: 15,
    publicRepo: 10,
    devDependency: -20,
    transitiveDependency: -5,
    testPath: -25,
    criticalityLow: -10,
    criticalityHigh: 5,
    criticalityCritical: 10,
    verifiedActive: 15,
    verifiedInactive: -30,
  },
  licenseDeny: ['AGPL-*', 'GPL-2.0*', 'GPL-3.0*', 'SSPL-1.0', 'CPAL-1.0', 'OSL-3.0'],
  licenseReview: ['LGPL-*', 'MPL-2.0', 'EPL-*', 'CDDL-*', 'UNLICENSED'],
  eolWarningDays: 180,
  expiryWarningDays: 30,
  verifySecrets: false,
  secretHistoryCommits: 0,
  containerImages: { enabled: false, maxImages: 10, minSeverity: 'high', fixableOnly: true },
};

export interface ToolStatus {
  available: boolean;
  version: string | null;
}

export interface IntelStatusDto {
  feeds: { key: string; label: string; fetchedAt: string | null; entries: number | null; error: string | null }[];
  gitleaks: ToolStatus;
  /** Opengrep (or Semgrep) for code analysis; `rules` is false when no rules directory is configured. */
  opengrep: ToolStatus & { rules: boolean };
  /** Trivy for infrastructure-as-code and container image scanning. */
  trivy: ToolStatus;
}
