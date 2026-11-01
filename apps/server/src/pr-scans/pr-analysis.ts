import { type Finding, type ObservedFinding } from '@argus/data';
import { type PrFindingDto, type PrScanFailOn, type PrScanResult, type ScannerRunResult, type Severity, SEVERITIES } from '@argus/shared';

/** Issues listed in a result (and so in the comment); the counts still cover all of them. */
export const MAX_LISTED_FINDINGS = 50;

/**
 * The command that applies a dependency fix, for direct dependencies with a fixed version. Transitive dependencies
 * are upgraded through the package that pulls them in, so they get no one-line command.
 */
export function fixCommandFor(f: Pick<ObservedFinding, 'scanner' | 'package'>): string | null {
  const p = f.package;
  if (f.scanner !== 'dependencies' || !p?.fixedVersion || !p.direct) return null;
  const v = p.fixedVersion;
  switch (p.ecosystem) {
    case 'npm':
      return `npm install ${p.name}@${v}${p.dev ? ' --save-dev' : ''}`;
    case 'nuget':
      return `dotnet add package ${p.name} --version ${v}`;
    case 'pypi':
      return `pip install "${p.name}>=${v}"  # then update your requirements or lock file`;
    case 'maven':
      return `Set the version of ${p.name} to ${v} in pom.xml or build.gradle`;
    case 'go':
      return `go get ${p.name}@${v.startsWith('v') ? v : `v${v}`} && go mod tidy`;
    case 'cargo':
      return `cargo update -p ${p.name} --precise ${v}`;
  }
}

export interface PrDelta {
  /** Issues this pull request introduces, not suppressed, most severe first. */
  introduced: ObservedFinding[];
  /** Introduced issues that a suppression covers. */
  suppressed: number;
  /** Issues already known on the repository in files the pull request changes. */
  existingInChangedFiles: number;
}

/**
 * Which findings a pull request introduces: findings in files it adds or changes that the repository did not already
 * have (or had fixed). A file-less finding counts when the repository has no record of it. With `changedFiles` null
 * (the provider did not say), every file counts as changed.
 */
export function pullRequestDelta(observed: ObservedFinding[], baseline: Finding[], changedFiles: Set<string> | null): PrDelta {
  const known = new Map(baseline.map((f) => [f.fingerprint, f.status]));
  const changed = (path: string | null) => !changedFiles || path === null || changedFiles.has(path);
  const introduced: ObservedFinding[] = [];
  let suppressed = 0;
  let existing = 0;
  for (const o of observed) {
    if (!changed(o.path)) continue;
    const status = known.get(o.fingerprint);
    if (status && status !== 'fixed') {
      existing++;
      continue;
    }
    if (o.suppressionId) suppressed++;
    else introduced.push(o);
  }
  introduced.sort((a, b) => b.riskScore - a.riskScore || (a.path ?? '').localeCompare(b.path ?? '') || (a.line ?? 0) - (b.line ?? 0));
  return { introduced, suppressed, existingInChangedFiles: existing };
}

const rank = (s: Severity) => SEVERITIES.length - SEVERITIES.indexOf(s);

/** Whether the gate fails: a new issue at or above the chosen severity. */
export function gateFails(counts: Record<Severity, number>, failOn: PrScanFailOn): boolean {
  if (failOn === 'never') return false;
  return SEVERITIES.some((s) => counts[s] > 0 && rank(s) >= rank(failOn));
}

export function buildResult(delta: PrDelta, opts: { changedFiles: number; failOn: PrScanFailOn; scanners: ScannerRunResult[]; ai?: Map<string, PrFindingDto['ai']> }): PrScanResult {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of delta.introduced) counts[f.severity]++;
  const findings: PrFindingDto[] = delta.introduced.slice(0, MAX_LISTED_FINDINGS).map((f) => ({
    scanner: f.scanner,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    riskScore: f.riskScore,
    path: f.path,
    line: f.line,
    remediation: f.remediation,
    fixCommand: fixCommandFor(f),
    url: f.advisory?.url ?? (typeof f.details?.reference === 'string' ? f.details.reference : null),
    ai: opts.ai?.get(f.fingerprint) ?? null,
  }));
  return {
    gate: gateFails(counts, opts.failOn) ? 'failed' : 'passed',
    changedFiles: opts.changedFiles,
    counts,
    findings,
    truncated: delta.introduced.length > findings.length,
    existingInChangedFiles: delta.existingInChangedFiles,
    suppressed: delta.suppressed,
    scanners: opts.scanners,
    commentError: null,
  };
}
