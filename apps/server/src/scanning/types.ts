import { type Repository } from '@argus/data';
import { type FindingAdvisory, type FindingPackage, type FindingSecret, type ScannerName, type ScanningSettings } from '@argus/shared';
import { type RiskInput } from './risk';
import { type ParsedDependency } from './parsers/types';

export interface RepoFile {
  /** Repository-relative, "/"-separated. */
  path: string;
  abs: string;
  size: number;
}

export interface ScanInput {
  workdir: string;
  /** Files after `.argus.yml` ignore rules (vendored folders are never included). */
  files: RepoFile[];
  repo: Repository;
  settings: ScanningSettings;
  log(message: string): void;
  /** Keyed hash for secret values; the raw value never leaves the scanner. */
  hashSecret(value: string): string;
  /** UTF-8 content of a text file, or null for binary/oversized files. */
  readText(file: RepoFile, maxBytes?: number): Promise<string | null>;
  /** Whether a path is excluded from scanning (vendored folders and `.argus.yml` ignore rules); used for git history. */
  excluded(path: string): boolean;
  /** Runs a read-only git command in the checkout (isolated configuration, no network). */
  git(args: string[]): Promise<string>;
}

/** A scanner's view of a finding. The pipeline adds fingerprint, risk score and suppression state. */
export interface DraftFinding {
  ruleId: string;
  /** Values that identify the issue across scans (never include line numbers, which shift). */
  identity: string[];
  title: string;
  description: string | null;
  path: string | null;
  line: number | null;
  package: FindingPackage | null;
  advisory: FindingAdvisory | null;
  secret: FindingSecret | null;
  details: Record<string, unknown> | null;
  remediation: string | null;
  risk: Omit<RiskInput, 'publicRepo' | 'criticality'>;
  /** The detected secret, kept in memory for this scan only (AI triage redacts it); never stored. */
  secretValue?: string;
}

export interface InventoryItem extends ParsedDependency {
  latestVersion: string | null;
  deprecated: string | null;
  vulnerabilities: number;
}

/** State passed between scanners within one scan (the license scanner reuses the dependency inventory). */
export interface SharedScanState {
  inventory: InventoryItem[] | null;
}

export interface ScannerOutput {
  /**
   * "partial" means some data could not be obtained (e.g. a feed was unreachable); unseen findings are then not marked fixed.
   * "skipped" means the scanner could not run at all (its tool is not installed, or it is turned off); nothing changes.
   */
  status: 'ok' | 'partial' | 'skipped';
  message: string | null;
  findings: DraftFinding[];
}

export interface Scanner {
  readonly name: ScannerName;
  run(input: ScanInput, shared: SharedScanState): Promise<ScannerOutput>;
}
