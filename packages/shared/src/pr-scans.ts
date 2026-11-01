import { z } from 'zod';
import { type ScannerName, type Severity } from './findings';
import { type Permission } from './permissions';
import { pageFields } from './schemas';
import { type ScannerRunResult } from './sources';

/** Severity at which a pull request scan fails its gate ("never" only reports). */
export const PR_SCAN_FAIL_ON = ['critical', 'high', 'medium', 'low', 'never'] as const;
export type PrScanFailOn = (typeof PR_SCAN_FAIL_ON)[number];

export const PR_SCAN_STATUSES = ['queued', 'running', 'succeeded', 'failed'] as const;
export type PrScanStatus = (typeof PR_SCAN_STATUSES)[number];

/** Scopes an API token needs to request pull request scans from a CI pipeline. */
export const CI_PR_SCAN_SCOPES: Permission[] = ['scans:run', 'repos:read'];

export const prScanRequestSchema = z.object({
  /** Repository as Argus names it: "owner/repo" (GitHub), "workspace/repo" (Bitbucket Cloud) or "PROJECT/repo" (Bitbucket Data Center). */
  repository: z.string().trim().min(3).max(300),
  pullRequest: z.coerce.number().int().positive().max(100_000_000),
  /** Fail the gate when a new issue reaches this severity. */
  failOn: z.enum(PR_SCAN_FAIL_ON).default('high'),
  /** Post (or update) the summary comment on the pull request. */
  comment: z.boolean().default(true),
  /** Chooses between repositories with the same name in different sources. */
  sourceId: z.uuid().optional(),
});
export type PrScanRequest = z.infer<typeof prScanRequestSchema>;

export const listPrScansQuerySchema = z.object({
  repoId: z.uuid(),
  ...pageFields,
});

/** An AI-written fix for a finding, shown in the comment as a suggestion to review. */
export interface PrFixSuggestion {
  summary: string;
  /** Replacement code for the flagged lines, when the fix is a code change. */
  code: string | null;
  language: string | null;
  provider: string;
  model: string;
}

export interface PrFindingDto {
  scanner: ScannerName;
  ruleId: string;
  title: string;
  severity: Severity;
  riskScore: number;
  path: string | null;
  line: number | null;
  remediation: string | null;
  /** Command that applies the fix, e.g. "npm install lodash@4.17.21". */
  fixCommand: string | null;
  url: string | null;
  ai: PrFixSuggestion | null;
}

export interface PrScanResult {
  gate: 'passed' | 'failed';
  /** Files the pull request adds or changes. */
  changedFiles: number;
  /** New, unsuppressed issues by severity. */
  counts: Record<Severity, number>;
  /** New issues, most severe first (capped). */
  findings: PrFindingDto[];
  /** More new issues than are listed. */
  truncated: boolean;
  /** Issues already known before this pull request, in files it changes. */
  existingInChangedFiles: number;
  /** New issues covered by a suppression (not counted). */
  suppressed: number;
  scanners: ScannerRunResult[];
  /** Why the comment could not be posted, if it could not. */
  commentError: string | null;
}

export interface PrScanDto {
  id: string;
  repoId: string;
  repoFullName: string | null;
  number: number;
  title: string | null;
  /** The pull request on the provider. */
  url: string | null;
  headSha: string | null;
  headBranch: string | null;
  baseBranch: string | null;
  status: PrScanStatus;
  failOn: PrScanFailOn;
  /** null until the scan has finished. */
  gate: 'passed' | 'failed' | null;
  result: PrScanResult | null;
  commentUrl: string | null;
  error: string | null;
  /** This scan in Argus. */
  argusUrl: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}
