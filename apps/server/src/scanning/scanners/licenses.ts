import { type DraftFinding, type ScanInput, type Scanner, type ScannerOutput, type SharedScanState } from '../types';

/** "GPL-3.0*" matches "GPL-3.0-only"; matching ignores case. */
function matchesAny(id: string, patterns: string[]): boolean {
  const lid = id.toLowerCase();
  return patterns.some((p) => {
    const lp = p.toLowerCase();
    return lp.endsWith('*') ? lid.startsWith(lp.slice(0, -1)) : lid === lp;
  });
}

type Verdict = 'ok' | 'review' | 'deny';

/**
 * Evaluates a (possibly compound) SPDX expression. "A OR B" is acceptable if any option is;
 * "A AND B" requires every part. Returns the worst verdict and the offending identifiers.
 */
export function evaluateLicense(expression: string, deny: string[], review: string[]): { verdict: Verdict; offending: string[] } {
  const rank: Record<Verdict, number> = { ok: 0, review: 1, deny: 2 };
  const verdictOf = (id: string): Verdict => (matchesAny(id, deny) ? 'deny' : matchesAny(id, review) ? 'review' : 'ok');
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

/** Flags dependencies whose declared license is denied or needs review under the organisation's policy. */
export class LicensesScanner implements Scanner {
  readonly name = 'licenses' as const;

  async run(input: ScanInput, shared: SharedScanState): Promise<ScannerOutput> {
    if (!shared.inventory) return { status: 'partial', message: 'The dependency scanner did not run, so there is no inventory to check.', findings: [] };
    const { licenseDeny, licenseReview } = input.settings;
    const findings: DraftFinding[] = [];
    let unknown = 0;
    for (const dep of shared.inventory) {
      if (!dep.license) {
        unknown++;
        continue;
      }
      const { verdict, offending } = evaluateLicense(dep.license, licenseDeny, licenseReview);
      if (verdict === 'ok') continue;
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
            : 'Have the license reviewed for this use; record the outcome as a suppression if it is acceptable.',
        risk: { base: verdict === 'deny' ? 50 : 25, baseLabel: verdict === 'deny' ? 'Denied license' : 'License needs review', dev: dep.dev, transitive: !dep.direct },
      });
    }
    return { status: 'ok', message: unknown ? `${unknown} package(s) without license data (license data comes from npm lockfiles and package registries)` : null, findings };
  }
}
