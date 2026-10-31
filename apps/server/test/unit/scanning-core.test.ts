import { DEFAULT_SCANNING_SETTINGS } from '@argus/shared';
import { describe, expect, it } from 'vitest';
import { purl } from '../../src/findings/sbom';
import { cvss3BaseScore, scoreForSeverityLabel } from '../../src/scanning/cvss';
import { compileGlobs, globToRegExp } from '../../src/scanning/glob';
import { parseRepoConfig } from '../../src/scanning/repo-config';
import { computeRisk, isTestPath } from '../../src/scanning/risk';
import { fixedVersionFor } from '../../src/scanning/scanners/dependencies';
import { evaluateLicense, licenseExceptionFor, LicensesScanner } from '../../src/scanning/scanners/licenses';
import { buildSuppressionRules, matchSuppression } from '../../src/scanning/suppression-matcher';
import { type DraftFinding, type ScanInput } from '../../src/scanning/types';
import { compareVersions, highestStable, lowestAbove, majorOf, satisfies } from '../../src/scanning/versions';

describe('CVSS v3 calculator', () => {
  it.each([
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1],
    ['CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0],
  ])('%s = %d', (vector, score) => expect(cvss3BaseScore(vector)).toBe(score));

  it('rejects incomplete or non-v3 vectors', () => {
    expect(cvss3BaseScore('CVSS:3.1/AV:N/AC:L')).toBeNull();
    expect(cvss3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')).toBeNull();
    expect(scoreForSeverityLabel('MODERATE')).toBe(5);
    expect(scoreForSeverityLabel(undefined)).toBeNull();
  });
});

describe('versions', () => {
  it('compares npm and NuGet versions, including 4-part NuGet versions', () => {
    expect(compareVersions('npm', '4.17.20', '4.17.21')).toBe(-1);
    expect(compareVersions('nuget', '4.5.0.1', '4.5.0')).toBe(1);
    expect(compareVersions('nuget', '4.5.0.1', '4.5.1')).toBe(-1);
    expect(compareVersions('nuget', '13.0.1', '13.0.1.0')).toBe(0);
    expect(compareVersions('nuget', '6.0.0-preview.1', '6.0.0')).toBe(-1);
  });

  it('finds the nearest fixed version and the latest stable release', () => {
    expect(lowestAbove('npm', '4.17.15', ['4.17.21', '4.17.19', '3.0.0'])).toBe('4.17.19');
    expect(lowestAbove('npm', '5.0.0', ['4.17.21'])).toBeNull();
    expect(highestStable('nuget', ['12.0.3', '13.0.1', '13.0.2-beta1'])).toBe('13.0.1');
  });

  it('evaluates ranges and majors', () => {
    expect(satisfies('npm', '4.17.20', '<4.17.21')).toBe(true);
    expect(satisfies('npm', '4.17.21', '<4.17.21')).toBe(false);
    expect(satisfies('nuget', '12.0.3', '<13.0.1')).toBe(true);
    expect(majorOf('^15.2.0')).toBe(15);
    expect(majorOf('>=18')).toBe(18);
  });
});

describe('globs', () => {
  it('matches gitignore-style patterns', () => {
    expect(globToRegExp('test/fixtures/**').test('test/fixtures/a/b.json')).toBe(true);
    expect(globToRegExp('docs/').test('docs/x/y.md')).toBe(true);
    expect(globToRegExp('*.pem').test('deep/dir/server.pem')).toBe(true);
    expect(globToRegExp('src/*.ts').test('src/a/b.ts')).toBe(false);
    expect(globToRegExp('**/secrets.json').test('secrets.json')).toBe(true);
    expect(compileGlobs([])('anything')).toBe(false);
  });
});

describe('risk scoring', () => {
  const w = DEFAULT_SCANNING_SETTINGS.riskWeights;

  it('adds explainable factors and clamps to 0-100', () => {
    const r = computeRisk({ base: 98, baseLabel: 'CVSS 9.8', kev: true, epss: 0.9, publicRepo: true, criticality: 'critical' }, w);
    expect(r.score).toBe(100);
    expect(r.severity).toBe('critical');
    expect(r.factors.map((f) => f.key)).toEqual(['base', 'kev', 'epss', 'public_repo', 'criticality']);

    const low = computeRisk({ base: 55, baseLabel: 'Generic secret', testPath: true, publicRepo: false, criticality: 'low' }, w);
    expect(low.score).toBe(20);
    expect(low.severity).toBe('low');

    const dev = computeRisk({ base: 75, baseLabel: 'CVSS 7.5', dev: true, transitive: true, publicRepo: false, criticality: 'medium' }, w);
    // Dev dependencies get the dev adjustment only (not also the transitive one).
    expect(dev.factors.find((f) => f.key === 'transitive_dependency')).toBeUndefined();
    expect(dev.score).toBe(55);
  });

  it('recognises test and example paths', () => {
    expect(isTestPath('src/__tests__/a.ts')).toBe(true);
    expect(isTestPath('test/fixtures/key.pem')).toBe(true);
    expect(isTestPath('app/config.spec.ts')).toBe(true);
    expect(isTestPath('src/testing-utils.ts')).toBe(false);
  });
});

describe('licenses', () => {
  const { licenseDeny, licenseReview } = DEFAULT_SCANNING_SETTINGS;
  it('evaluates SPDX expressions against policy', () => {
    expect(evaluateLicense('MIT', licenseDeny, licenseReview).verdict).toBe('ok');
    expect(evaluateLicense('GPL-3.0-only', licenseDeny, licenseReview)).toEqual({ verdict: 'deny', offending: ['GPL-3.0-only'] });
    expect(evaluateLicense('(GPL-3.0-or-later OR MIT)', licenseDeny, licenseReview).verdict).toBe('ok');
    expect(evaluateLicense('MIT AND AGPL-3.0', licenseDeny, licenseReview).verdict).toBe('deny');
    expect(evaluateLicense('LGPL-2.1', licenseDeny, licenseReview).verdict).toBe('review');
    expect(evaluateLicense('GPL-2.0 WITH Classpath-exception-2.0', licenseDeny, licenseReview).verdict).toBe('deny');
  });

  it('lets allowed licenses win, and flags everything else for review in allow-only mode', () => {
    expect(evaluateLicense('LGPL-2.1-only', licenseDeny, licenseReview, ['LGPL-2.1-only']).verdict).toBe('ok');
    expect(evaluateLicense('LGPL-3.0-only', licenseDeny, licenseReview, ['LGPL-2.1-only']).verdict).toBe('review');
    expect(evaluateLicense('ISC', licenseDeny, licenseReview, ['MIT', 'Apache-2.0'], true)).toEqual({ verdict: 'review', offending: ['ISC'] });
    expect(evaluateLicense('ISC OR MIT', licenseDeny, licenseReview, ['MIT'], true).verdict).toBe('ok');
    expect(evaluateLicense('AGPL-3.0', licenseDeny, licenseReview, ['MIT'], true).verdict).toBe('deny');
  });

  it('matches license exceptions by package (or prefix), ecosystem and license', () => {
    const exceptions = [
      { package: 'lightningcss*', ecosystem: 'npm' as const, license: 'MPL-2.0', reason: 'Build tool only, reviewed by legal' },
      { package: 'Django_Filter', ecosystem: null, license: null, reason: 'Reviewed 2026-10' },
    ];
    const dep = (ecosystem: 'npm' | 'pypi', name: string, license: string) => licenseExceptionFor({ ecosystem, name, license }, exceptions)?.reason ?? null;
    expect(dep('npm', 'lightningcss-linux-x64-gnu', 'MPL-2.0')).toBe('Build tool only, reviewed by legal');
    expect(dep('npm', 'lightningcss', '(MPL-2.0 OR MIT)')).toBe('Build tool only, reviewed by legal');
    // A different license, ecosystem or package is not covered.
    expect(dep('npm', 'lightningcss', 'GPL-3.0-only')).toBeNull();
    expect(dep('pypi', 'lightningcss', 'MPL-2.0')).toBeNull();
    expect(dep('npm', 'postcss', 'MPL-2.0')).toBeNull();
    // Names are compared as the ecosystem compares them.
    expect(dep('pypi', 'django-filter', 'LGPL-3.0')).toBe('Reviewed 2026-10');
  });

  it('does not flag approved packages, and says how many were approved', async () => {
    const settings = { ...DEFAULT_SCANNING_SETTINGS, licenseExceptions: [{ package: 'lightningcss*', ecosystem: null, license: 'MPL-2.0', reason: 'Build tool only' }] };
    const item = (name: string, license: string) => ({ ecosystem: 'npm' as const, name, version: '1.32.0', direct: false, dev: true, license, manifestPath: 'package-lock.json', latestVersion: null, deprecated: null, vulnerabilities: 0 });
    const out = await new LicensesScanner().run({ settings } as unknown as ScanInput, { inventory: [item('lightningcss', 'MPL-2.0'), item('lightningcss-darwin-arm64', 'MPL-2.0'), item('other', 'MPL-2.0')] });
    expect(out.findings.map((f) => f.package?.name)).toEqual(['other']);
    expect(out.message).toBe('2 package(s) approved by license exceptions');
  });
});

describe('OSV fixed versions', () => {
  it('picks the lowest fix above the installed version for the right package', () => {
    const vuln = {
      id: 'GHSA-x',
      modified: '',
      affected: [
        { package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] },
        { package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.10.2' }] }] },
        { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '4.17.19' }] }] },
      ],
    };
    expect(fixedVersionFor(vuln, 'npm', 'lodash', '4.17.20')).toBe('4.17.21');
    expect(fixedVersionFor(vuln, 'npm', 'lodash', '3.5.0')).toBe('3.10.2');
    const nuget = { id: 'GHSA-y', modified: '', affected: [{ package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '13.0.1' }] }] }] };
    expect(fixedVersionFor(nuget, 'nuget', 'newtonsoft.json', '12.0.3')).toBe('13.0.1');
  });
});

describe('.argus.yml and suppressions', () => {
  const draft = (over: Partial<DraftFinding> = {}): DraftFinding => ({
    ruleId: 'GHSA-1234',
    identity: [],
    title: 't',
    description: null,
    path: 'test/fixtures/package-lock.json',
    line: null,
    package: { ecosystem: 'npm', name: 'Lodash', version: '1.0.0', direct: true, dev: false, fixedVersion: null },
    advisory: { id: 'GHSA-1234', aliases: ['CVE-2026-1111'], summary: null, cvssScore: null, cvssVector: null, epss: null, kev: false, url: null, published: null },
    secret: null,
    details: null,
    remediation: null,
    risk: { base: 50, baseLabel: 'x' },
    ...over,
  });

  it('parses a valid file and reports invalid ones', () => {
    const cfg = parseRepoConfig(
      'ignore:\n  paths: ["docs/"]\nscanners:\n  licenses: false\nsuppress:\n  - rule: CVE-2026-1111\n    reason: Not reachable in our code\n  - path: "test/**"\n    scanner: secrets\n    reason: Test keys only\n    expires: 2020-01-01\n',
    );
    expect(cfg.errors).toEqual([]);
    expect(cfg.ignorePaths).toEqual(['docs/']);
    expect(cfg.scanners).toEqual({ licenses: false });
    expect(cfg.suppress).toHaveLength(2);
    expect(parseRepoConfig('scanners:\n  bogus: true\n').errors[0]).toMatch(/\.argus\.yml/);
    expect(parseRepoConfig(': : :').errors[0]).toMatch(/not valid YAML/);
  });

  it('matches by rule (including aliases), path, package and scanner; drops expired file rules', () => {
    const cfg = parseRepoConfig('suppress:\n  - rule: cve-2026-1111\n    reason: aliases match too\n  - package: other\n    reason: no match\n    expires: 2020-01-01\n');
    const rules = buildSuppressionRules('repo', [], cfg, new Date());
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(buildSuppressionRules('repo', [], cfg, new Date())[0].id).toBe(rules[0].id);
    expect(matchSuppression(rules, 'dependencies', draft())?.source).toBe('repo-file');

    const db = [{ id: 'db1', repoId: null, scanner: 'secrets' as const, ruleId: null, pathPattern: 'test/**', packageName: null, groupKey: null, ticketId: null, reason: 'r', expiresAt: null, createdBy: null, createdByName: null, createdAt: new Date() }];
    const dbRules = buildSuppressionRules('repo', db, parseRepoConfig(''), new Date());
    expect(matchSuppression(dbRules, 'dependencies', draft())).toBeNull();
    expect(matchSuppression(dbRules, 'secrets', draft())?.id).toBe('db1');
    expect(matchSuppression(dbRules, 'secrets', draft({ path: 'src/app.ts' }))).toBeNull();
    const pkgRule = buildSuppressionRules('repo', [{ ...db[0], scanner: null, pathPattern: null, packageName: 'lodash' }], parseRepoConfig(''), new Date());
    expect(matchSuppression(pkgRule, 'licenses', draft())).not.toBeNull();
  });
});

describe('package URLs', () => {
  it('encodes scoped npm names and NuGet ids', () => {
    expect(purl('npm', '@angular/core', '15.2.0')).toBe('pkg:npm/%40angular/core@15.2.0');
    expect(purl('npm', 'lodash', '4.17.21')).toBe('pkg:npm/lodash@4.17.21');
    expect(purl('nuget', 'Newtonsoft.Json', '13.0.1')).toBe('pkg:nuget/Newtonsoft.Json@13.0.1');
  });
});
