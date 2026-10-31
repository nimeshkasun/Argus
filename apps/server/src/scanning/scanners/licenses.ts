import { canonicalPackageName, type LicenseException } from '@argus/shared';
import { type DraftFinding, type InventoryItem, type ScanInput, type Scanner, type ScannerOutput, type SharedScanState } from '../types';

/** "GPL-3.0*" matches "GPL-3.0-only"; matching ignores case. */
function matchesAny(id: string, patterns: string[]): boolean {
  const lid = id.toLowerCase();
  return patterns.some((p) => {
    const lp = p.toLowerCase();
    return lp.endsWith('*') ? lid.startsWith(lp.slice(0, -1)) : lid === lp;
  });
}

type Verdict = 'ok' | 'review' | 'deny';

/** The license ids in an SPDX expression ("(MIT OR GPL-2.0 WITH Classpath-exception-2.0)" -> MIT, GPL-2.0). */
function licenseIds(expression: string): string[] {
  return expression
    .replace(/[()]/g, ' ')
    .replace(/\s+WITH\s+\S+/gi, ' ')
    .split(/\s+(?:OR|AND)\s+|\s+/i)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Evaluates a (possibly compound) SPDX expression. "A OR B" is acceptable if any option is;
 * "A AND B" requires every part. Returns the worst verdict and the offending identifiers.
 * An allowed license is always acceptable; with `allowOnly`, a license that is not allowed needs review.
 */
export function evaluateLicense(expression: string, deny: string[], review: string[], allow: string[] = [], allowOnly = false): { verdict: Verdict; offending: string[] } {
  const rank: Record<Verdict, number> = { ok: 0, review: 1, deny: 2 };
  const verdictOf = (id: string): Verdict => (matchesAny(id, allow) ? 'ok' : matchesAny(id, deny) ? 'deny' : matchesAny(id, review) || allowOnly ? 'review' : 'ok');
  const alternatives = expression
    .replace(/[()]/g, ' ')
    .split(/\s+OR\s+/i)
    .map((alt) =>
      alt
        .split(/\s+AND\s+/i)
        .map((s) => s.trim().replace(/\s+WITH\s+.*$/i, ''))
        .filter(Boolean),
    );
  let best: { verdict: Verdict; offending: string[] } | null = null;
  for (const parts of alternatives) {
    const verdicts = parts.map((p) => ({ id: p, v: verdictOf(p) }));
    const worst = verdicts.reduce<Verdict>((w, x) => (rank[x.v] > rank[w] ? x.v : w), 'ok');
    const candidate = { verdict: worst, offending: verdicts.filter((x) => x.v === worst && worst !== 'ok').map((x) => x.id) };
    if (!best || rank[candidate.verdict] < rank[best.verdict]) best = candidate;
  }
  return best ?? { verdict: 'ok', offending: [] };
}

/** The policy exception that approves this package version, if any. */
export function licenseExceptionFor(dep: Pick<InventoryItem, 'ecosystem' | 'name' | 'license'>, exceptions: LicenseException[]): LicenseException | null {
  const name = canonicalPackageName(dep.ecosystem, dep.name);
  for (const e of exceptions) {
    if (e.ecosystem && e.ecosystem !== dep.ecosystem) continue;
    const pattern = e.package.endsWith('*') ? canonicalPackageName(dep.ecosystem, e.package.slice(0, -1)) : canonicalPackageName(dep.ecosystem, e.package);
    if (e.package.endsWith('*') ? !name.startsWith(pattern) : name !== pattern) continue;
    if (e.license && !licenseIds(dep.license ?? '').some((id) => matchesAny(id, [e.license!]))) continue;
    return e;
  }
  return null;
}

/** Flags dependencies whose declared license is denied or needs review under the organisation's policy. */
export class LicensesScanner implements Scanner {
  readonly name = 'licenses' as const;

  async run(input: ScanInput, shared: SharedScanState): Promise<ScannerOutput> {
    if (!shared.inventory) return { status: 'partial', message: 'The dependency scanner did not run, so there is no inventory to check.', findings: [] };
    const { licenseDeny, licenseReview, licenseAllow, licenseAllowOnly, licenseExceptions } = input.settings;
    const findings: DraftFinding[] = [];
    let unknown = 0;
    let excepted = 0;
    for (const dep of shared.inventory) {
      if (!dep.license) {
        unknown++;
        continue;
      }
      const { verdict, offending } = evaluateLicense(dep.license, licenseDeny, licenseReview, licenseAllow, licenseAllowOnly);
      if (verdict === 'ok') continue;
      if (licenseExceptionFor(dep, licenseExceptions)) {
        excepted++;
        continue;
      }
      findings.push({
        ruleId: verdict === 'deny' ? 'license-denied' : 'license-review',
        identity: [dep.manifestPath, dep.ecosystem, dep.name],
        title: `${dep.name}@${dep.version} is licensed ${dep.license}${verdict === 'deny' ? ', which is not allowed' : ', which needs review'}`,
        description: `License policy ${verdict === 'deny' ? 'denies' : 'flags for review'}: ${offending.join(', ')}.`,
        path: dep.manifestPath,
        line: null,
        package: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, direct: dep.direct, dev: dep.dev, fixedVersion: null },
        advisory: null,
        secret: null,
        details: { license: dep.license, verdict, offending },
        remediation:
          verdict === 'deny'
            ? 'Replace the package with an alternative under an approved license, or obtain a legal exception and record it as a suppression.'
            : 'Have the license reviewed for this use. If it is acceptable, approve the package under Administration → Scanning settings → License policy (or from this finding), so it is not flagged again.',
        risk: { base: verdict === 'deny' ? 50 : 25, baseLabel: verdict === 'deny' ? 'Denied license' : 'License needs review', dev: dep.dev, transitive: !dep.direct },
      });
    }
    const notes = [unknown ? `${unknown} package(s) without license data (license data comes from npm lockfiles and package registries)` : null, excepted ? `${excepted} package(s) approved by license exceptions` : null].filter(Boolean);
    return { status: 'ok', message: notes.length ? notes.join('; ') : null, findings };
  }
}
