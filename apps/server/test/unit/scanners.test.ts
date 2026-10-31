import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type Repository } from '@argus/data';
import { DEFAULT_SCANNING_SETTINGS } from '@argus/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type EolCycle, type IntelService, type OsvVuln } from '../../src/scanning/intel.service';
import { parseNuGetLock, parsePackagesConfig, parseProjectFile, parseCentralVersions, projectTargetFrameworks, lowestNuGetVersion } from '../../src/scanning/parsers/nuget';
import { parsePackageJsonDependencies, parsePackageLock, parsePnpmLock, parseYarnLock } from '../../src/scanning/parsers/npm';
import { CertificatesScanner } from '../../src/scanning/scanners/certificates';
import { collectDependencies, DependenciesScanner } from '../../src/scanning/scanners/dependencies';
import { FrameworksScanner, mapTargetFramework, matchCycle } from '../../src/scanning/scanners/frameworks';
import { addedLines, maskSecret, SecretsScanner, shannonEntropy } from '../../src/scanning/scanners/secrets';
import { type RepoFile, type ScanInput, type SharedScanState } from '../../src/scanning/types';
import { runGit } from '../../src/scans/git';
import { isVendoredPath, walkFiles } from '../../src/scans/inventory';
import { type Advisory } from '@argus/data';

describe('npm parsers', () => {
  const pkg = { dependencies: { lodash: '^4.17.20' }, devDependencies: { jest: '^29.0.0' } };

  it('reads package-lock v3 with direct/dev/license and skips workspaces and links', () => {
    const lock = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { lodash: '^4.17.20' }, devDependencies: { jest: '^29.0.0' } },
        'node_modules/lodash': { version: '4.17.20', license: 'MIT' },
        'node_modules/jest': { version: '29.7.0', dev: true, license: 'MIT' },
        'node_modules/jest/node_modules/lodash': { version: '4.17.15', dev: true },
        'packages/lib': { version: '1.0.0' },
        'node_modules/lib': { link: true, resolved: 'packages/lib' },
        'node_modules/@scope/pkg': { version: '2.0.0', license: { type: 'Apache-2.0' } },
      },
    });
    const deps = parsePackageLock(lock, 'package-lock.json', pkg);
    expect(deps.map((d) => [d.name, d.version, d.direct, d.dev, d.license])).toEqual([
      ['lodash', '4.17.20', true, false, 'MIT'],
      ['jest', '29.7.0', true, true, 'MIT'],
      ['lodash', '4.17.15', false, true, null],
      ['@scope/pkg', '2.0.0', false, false, 'Apache-2.0'],
    ]);
  });

  it('reads package-lock v1 nested dependencies', () => {
    const lock = JSON.stringify({ lockfileVersion: 1, dependencies: { lodash: { version: '4.17.20', dependencies: { inner: { version: '1.0.0' } } }, jest: { version: '29.0.0', dev: true } } });
    const deps = parsePackageLock(lock, 'package-lock.json', pkg);
    expect(deps.map((d) => [d.name, d.direct, d.dev])).toEqual([
      ['lodash', true, false],
      ['inner', false, false],
      ['jest', true, true],
    ]);
  });

  it('reads yarn classic and Berry lockfiles', () => {
    const classic = '# yarn lockfile v1\n\n"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.0"\n  resolved "x"\n\nlodash@^4.17.20:\n  version "4.17.20"\n';
    expect(parseYarnLock(classic, 'yarn.lock', pkg).map((d) => [d.name, d.version, d.direct])).toEqual([
      ['@babel/core', '7.22.0', false],
      ['lodash', '4.17.20', true],
    ]);
    const berry = '__metadata:\n  version: 6\n\n"lodash@npm:^4.17.20":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n';
    expect(parseYarnLock(berry, 'yarn.lock', pkg).map((d) => [d.name, d.version])).toEqual([['lodash', '4.17.20']]);
  });

  it('reads pnpm v6 and v9 lockfiles', () => {
    const v6 = "lockfileVersion: '6.0'\ndependencies:\n  lodash:\n    specifier: ^4.17.20\n    version: 4.17.20\npackages:\n  /lodash@4.17.20:\n    resolution: {integrity: x}\n    dev: false\n  /jest@29.7.0(@types/node@20.0.0):\n    dev: true\n";
    expect(parsePnpmLock(v6, 'pnpm-lock.yaml', null).map((d) => [d.name, d.version, d.direct, d.dev])).toEqual([
      ['lodash', '4.17.20', true, false],
      ['jest', '29.7.0', false, true],
    ]);
    const v9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      '@scope/tool':\n        specifier: ^1.0.0\n        version: 1.2.3\npackages:\n  '@scope/tool@1.2.3':\n    resolution: {integrity: x}\n";
    expect(parsePnpmLock(v9, 'pnpm-lock.yaml', null).map((d) => [d.name, d.version, d.direct, d.dev])).toEqual([['@scope/tool', '1.2.3', true, true]]);
  });

  it('falls back to the lowest version allowed by package.json ranges', () => {
    const deps = parsePackageJsonDependencies({ dependencies: { lodash: '^4.17.20', local: 'file:../x', gh: 'github:a/b' }, devDependencies: { jest: '~29.1.0' } }, 'package.json');
    expect(deps.map((d) => [d.name, d.version, d.dev, d.unpinned])).toEqual([
      ['lodash', '4.17.20', false, true],
      ['jest', '29.1.0', true, true],
    ]);
  });
});

describe('NuGet parsers', () => {
  it('reads packages.lock.json, project files with central versions, and packages.config', () => {
    const lock = JSON.stringify({
      version: 1,
      dependencies: {
        'net6.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.3' }, 'System.Memory': { type: 'Transitive', resolved: '4.5.4' }, MyLib: { type: 'Project' } },
        net48: { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.3' } },
      },
    });
    expect(parseNuGetLock(lock, 'src/packages.lock.json').map((d) => [d.name, d.version, d.direct])).toEqual([
      ['Newtonsoft.Json', '12.0.3', true],
      ['System.Memory', '4.5.4', false],
    ]);

    const central = parseCentralVersions('<Project><ItemGroup><PackageVersion Include="Serilog" Version="2.10.0" /></ItemGroup></Project>');
    const csproj = `<Project Sdk="Microsoft.NET.Sdk">
      <PropertyGroup><TargetFrameworks>net6.0;net48</TargetFrameworks></PropertyGroup>
      <ItemGroup>
        <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
        <PackageReference Include="Serilog" />
        <PackageReference Include="StyleCop.Analyzers" Version="1.1.118" PrivateAssets="all" />
        <PackageReference Include="Dapper"><Version>[2.0.123, 3.0)</Version></PackageReference>
      </ItemGroup>
    </Project>`;
    expect(parseProjectFile(csproj, 'src/App.csproj', central).map((d) => [d.name, d.version, d.dev])).toEqual([
      ['Newtonsoft.Json', '12.0.3', false],
      ['Serilog', '2.10.0', false],
      ['StyleCop.Analyzers', '1.1.118', true],
      ['Dapper', '2.0.123', false],
    ]);
    expect(projectTargetFrameworks(csproj)).toEqual(['net6.0', 'net48']);
    expect(projectTargetFrameworks('<Project><PropertyGroup><TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion></PropertyGroup></Project>')).toEqual(['net472']);
    // Entities declared in a repository's DOCTYPE are never expanded.
    const withDtd = '<?xml version="1.0"?><!DOCTYPE Project [<!ENTITY v "9.9.9-from-entity">]><Project><ItemGroup><PackageReference Include="Evil" Version="&v;" /></ItemGroup></Project>';
    expect(JSON.stringify(parseProjectFile(withDtd, 'x.csproj', new Map()))).not.toContain('from-entity');

    expect(parsePackagesConfig('<packages><package id="jQuery" version="1.8.0" /><package id="NUnit" version="3.0.0" developmentDependency="true" /></packages>', 'packages.config').map((d) => [d.name, d.dev])).toEqual([
      ['jQuery', false],
      ['NUnit', true],
    ]);
    expect(lowestNuGetVersion('1.2.*')).toBe('1.2.0');
    expect(lowestNuGetVersion('$(MyVersion)')).toBeNull();
  });
});

describe('framework detection', () => {
  it('matches endoflife.date cycle names in their various formats', () => {
    const cycles = [
      { cycle: '6', eol: '2024-11-12' },
      { cycle: '3.1', eol: '2022-12-13' },
      { cycle: '3.5', eol: false },
      { cycle: '22', eol: '2027-04-30' },
    ];
    expect(matchCycle(cycles, '6.0')?.cycle).toBe('6');
    expect(matchCycle(cycles, '3.1')?.cycle).toBe('3.1');
    expect(matchCycle(cycles, '3.5')?.cycle).toBe('3.5');
    expect(matchCycle(cycles, '22.4')?.cycle).toBe('22');
    expect(matchCycle(cycles, '7.0')).toBeNull();
  });

  it('maps target frameworks to endoflife.date products', () => {
    expect(mapTargetFramework('net6.0')).toMatchObject({ product: 'dotnet', cycle: '6.0' });
    expect(mapTargetFramework('net8.0-windows')).toMatchObject({ product: 'dotnet', cycle: '8.0' });
    expect(mapTargetFramework('netcoreapp3.1')).toMatchObject({ product: 'dotnet', cycle: '3.1' });
    expect(mapTargetFramework('net472')).toMatchObject({ product: 'dotnetfx', cycle: '4.7.2' });
    expect(mapTargetFramework('net48')).toMatchObject({ product: 'dotnetfx', cycle: '4.8' });
    expect(mapTargetFramework('netstandard2.0')).toBeNull();
  });
});

describe('secret helpers', () => {
  it('masks and measures entropy', () => {
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE', 'aws-access-token')).toBe('AKIA…MPLE');
    expect(maskSecret('short', 'generic')).toBe('••••••');
    expect(maskSecret('-----BEGIN RSA PRIVATE KEY-----', 'private-key')).toBe('PEM private key');
    expect(shannonEntropy('aaaaaaaa')).toBe(0);
    expect(shannonEntropy('aB3$xZ9!qW')).toBeGreaterThan(3);
  });
});

// ---------------------------------------------------------------------------------------------- scanners on disk

const repo = { id: 'r1', visibility: 'private', criticality: 'medium', disabledScanners: [] } as unknown as Repository;
let root: string;
let files: RepoFile[];

function input(over: Partial<ScanInput> = {}): ScanInput {
  return {
    workdir: root,
    files,
    repo,
    settings: DEFAULT_SCANNING_SETTINGS,
    log: () => undefined,
    hashSecret: (v) => `h(${v.length})`,
    readText: async (f) => (await import('node:fs/promises')).readFile(f.abs, 'utf8'),
    excluded: () => false,
    git: (args) => runGit(args, { cwd: root, home: tmpdir(), timeoutMs: 30_000 }),
    ...over,
  };
}

const fakeIntel = (over: Partial<Record<keyof IntelService, unknown>> = {}) =>
  ({
    offline: false,
    queryVulnerabilities: async (pkgs: { ecosystem: string; name: string; version: string }[]) =>
      new Map(pkgs.map((p) => [`${p.ecosystem}|${p.ecosystem === 'nuget' ? p.name.toLowerCase() : p.name}|${p.version}`, p.name === 'lodash' && p.version === '4.17.20' ? ['GHSA-lodash'] : []])),
    vulnerabilities: async () =>
      new Map<string, OsvVuln>([
        [
          'GHSA-lodash',
          {
            id: 'GHSA-lodash',
            summary: 'Command injection in lodash',
            aliases: ['CVE-2021-23337'],
            modified: '2026-01-01',
            severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H' }],
            affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
          },
        ],
      ]),
    argusAdvisories: async () => [],
    packageLicense: async (p: { name: string }) => (p.name.toLowerCase() === 'newtonsoft.json' ? 'MIT' : null),
    nvdCvss: async () => new Map(),
    kev: async () => new Set(['CVE-2021-23337']),
    epss: async () => new Map([['CVE-2021-23337', 0.5]]),
    packageMeta: async (p: { name: string }) => ({ latest: '9.9.9', deprecated: p.name === 'request' ? 'request has been deprecated' : null }),
    eolCycles: async (product: string): Promise<EolCycle[] | null> =>
      product === 'dotnet'
        ? [
            // Real endoflife.date naming: "8", not "8.0".
            { cycle: '8', eol: '2026-11-10', lts: true },
            { cycle: '6', eol: '2024-11-12', lts: true },
          ]
        : product === 'nodejs'
          ? [
              { cycle: '24', eol: '2028-04-30', lts: true },
              { cycle: '22', eol: new Date(Date.now() + 60 * 86_400_000).toISOString().slice(0, 10), lts: true },
            ]
          : null,
    ...over,
  }) as unknown as IntelService;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'argus-scanners-'));
  mkdirSync(join(root, 'src'));
  mkdirSync(join(root, 'test', 'fixtures'), { recursive: true });
  mkdirSync(join(root, 'certs'));
  mkdirSync(join(root, 'node_modules', 'x'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ engines: { node: '>=22' }, dependencies: { lodash: '^4.17.20', request: '^2.88.0', react: '^18.2.0' } }));
  writeFileSync(
    join(root, 'package-lock.json'),
    JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { dependencies: { lodash: '^4.17.20', request: '^2.88.0' } }, 'node_modules/lodash': { version: '4.17.20', license: 'MIT' }, 'node_modules/request': { version: '2.88.2', license: 'Apache-2.0' }, 'node_modules/gpl-thing': { version: '1.0.0', license: 'GPL-3.0-only' } },
    }),
  );
  writeFileSync(join(root, 'src', 'App.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></ItemGroup></Project>');
  writeFileSync(join(root, 'src', 'config.js'), `module.exports = { awsKey: "AKIAIOSFODNN7EXAMPLE", password: "${'x'.repeat(4)}" };\nconst token = "ghp_${'A1b2C3d4'.repeat(4)}abcd";\n`);
  writeFileSync(join(root, 'test', 'fixtures', 'key.txt'), '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n');
  writeFileSync(join(root, 'node_modules', 'x', 'leak.js'), 'AKIAIOSFODNN7EXAMPLE');
  writeFileSync(join(root, 'certs', 'store.pfx'), Buffer.from([0x30, 0x82, 0x00]));
  const soon = Math.floor(Date.now() / 1000) + 10 * 86_400;
  const jwt = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ sub: 'svc', exp: soon })).toString('base64url')}.c2lnbmF0dXJlc2lnbmF0dXJl`;
  writeFileSync(join(root, 'appsettings.json'), JSON.stringify({ Api: { Token: jwt } }));
  // A short-lived certificate with a weak key, generated with OpenSSL.
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:1024', '-nodes', '-keyout', join(root, 'tmp.key'), '-out', join(root, 'certs', 'server.pem'), '-days', '5', '-subj', '/CN=argus.test'], { stdio: 'ignore' });
  rmSync(join(root, 'tmp.key'));
  files = await walkFiles(root);
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe('scanners', () => {
  it('walks files without vendored folders', () => {
    expect(files.map((f) => f.path)).not.toContain('node_modules/x/leak.js');
    expect(files.map((f) => f.path)).toContain('src/App.csproj');
  });

  it('secrets: built-in rules find keys and tokens, ignore placeholders, and never expose values', async () => {
    const out = await new SecretsScanner('argus-no-such-gitleaks-binary', 10_000).run(input());
    expect(out.message).toMatch(/Built-in rules/);
    const byRule = new Map(out.findings.map((f) => [f.ruleId, f]));
    // The JWT in appsettings.json is a committed credential too; the GitHub token is not double-reported as a generic secret.
    expect([...byRule.keys()].sort()).toEqual(['aws-access-token', 'github-pat', 'jwt', 'private-key']);
    const aws = byRule.get('aws-access-token')!;
    expect(aws).toMatchObject({ path: 'src/config.js', line: 1, secret: { preview: 'AKIA…MPLE', hash: 'h(20)' } });
    expect(JSON.stringify(out.findings)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(byRule.get('private-key')!.risk.testPath).toBe(true);
  });

  it('dependencies: inventory, vulnerabilities with KEV/EPSS/fix, and deprecations', async () => {
    const shared: SharedScanState = { inventory: null };
    const out = await new DependenciesScanner(fakeIntel()).run(input(), shared);
    expect(out.status).toBe('ok');
    expect(shared.inventory!.map((d) => `${d.ecosystem}:${d.name}@${d.version}`).sort()).toEqual(['npm:gpl-thing@1.0.0', 'npm:lodash@4.17.20', 'npm:request@2.88.2', 'nuget:Newtonsoft.Json@12.0.3']);
    const vuln = out.findings.find((f) => f.ruleId === 'GHSA-lodash')!;
    expect(vuln.package).toMatchObject({ name: 'lodash', fixedVersion: '4.17.21', direct: true });
    expect(vuln.advisory).toMatchObject({ kev: true, epss: 0.5, cvssScore: 7.2, aliases: ['CVE-2021-23337'] });
    expect(vuln.risk).toMatchObject({ base: 72, kev: true, epss: 0.5 });
    expect(out.findings.find((f) => f.ruleId === 'deprecated-package')?.package?.name).toBe('request');
    expect(shared.inventory!.find((d) => d.name === 'lodash')).toMatchObject({ vulnerabilities: 1, latestVersion: '9.9.9' });
  });

  it('dependencies: matches Argus advisories by range, skips ones OSV already covers, and fills CVSS from NVD', async () => {
    const shared: SharedScanState = { inventory: null };
    const argus = (over: Partial<Advisory>): Advisory => ({
      id: 'a1',
      key: 'ARGUS-2026-0001',
      ecosystem: 'nuget',
      packageName: 'newtonsoft.json',
      affectedRange: '<13.0.1',
      fixedVersion: '13.0.1',
      severity: 'high',
      cvssScore: null,
      cveIds: [],
      title: 'Stack overflow in Newtonsoft.Json',
      summary: 'Deeply nested JSON',
      references: ['https://example.com/advisory'],
      source: 'news',
      sourceItemId: null,
      withdrawn: false,
      autoApproved: false,
      createdBy: null,
      createdAt: new Date('2026-10-01'),
      updatedAt: new Date('2026-10-01'),
      ...over,
    });
    const intel = fakeIntel({
      argusAdvisories: async () => [
        argus({}),
        // Not affected: the installed version is outside the range.
        argus({ id: 'a2', key: 'ARGUS-2026-0002', affectedRange: '>=14.0.0 <14.1.0' }),
        // Duplicates the OSV advisory for lodash (same CVE): OSV wins.
        argus({ id: 'a3', key: 'ARGUS-2026-0003', ecosystem: 'npm', packageName: 'lodash', affectedRange: '<4.17.21', cveIds: ['CVE-2021-23337'] }),
      ],
      vulnerabilities: async () =>
        new Map<string, OsvVuln>([['GHSA-lodash', { id: 'GHSA-lodash', summary: 'Command injection in lodash', aliases: ['CVE-2021-23337'], modified: '2026-01-01', database_specific: { severity: 'HIGH' } }]]),
      nvdCvss: async (cves: string[]) => new Map(cves.map((c) => [c, { score: 8.8, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H' }])),
    });
    const out = await new DependenciesScanner(intel).run(input(), shared);
    const keys = out.findings.filter((f) => f.advisory).map((f) => f.ruleId).sort();
    expect(keys).toEqual(['ARGUS-2026-0001', 'GHSA-lodash']);
    const json = out.findings.find((f) => f.ruleId === 'ARGUS-2026-0001')!;
    expect(json).toMatchObject({ path: 'src/App.csproj', package: { name: 'Newtonsoft.Json', fixedVersion: '13.0.1' }, advisory: { id: 'ARGUS-2026-0001', url: 'https://example.com/advisory' }, risk: { base: 75 } });
    // Same identity as an OSV finding for the package, so scans and re-matching agree.
    expect(json.identity).toEqual(['src/App.csproj', 'nuget', 'newtonsoft.json']);
    const lodash = out.findings.find((f) => f.ruleId === 'GHSA-lodash')!;
    expect(lodash.advisory).toMatchObject({ cvssScore: 8.8 });
    expect(lodash.risk).toMatchObject({ base: 88, baseLabel: 'CVSS 8.8 (NVD)' });
  });

  it('dependencies: an unreachable vulnerability feed gives a partial result', async () => {
    const shared: SharedScanState = { inventory: null };
    const out = await new DependenciesScanner(fakeIntel({ queryVulnerabilities: async () => Promise.reject(new Error('down')) })).run(input(), shared);
    expect(out.status).toBe('partial');
    expect(out.message).toMatch(/vulnerability lookup failed: down/);
    expect(shared.inventory).toHaveLength(4);
  });

  it('dependencies: collects manifests per folder', async () => {
    const { deps, errors } = await collectDependencies(input());
    expect(errors).toEqual([]);
    expect(new Set(deps.map((d) => d.manifestPath))).toEqual(new Set(['package-lock.json', 'src/App.csproj']));
  });

  it('frameworks: flags end-of-life and soon-to-be end-of-life runtimes', async () => {
    const out = await new FrameworksScanner(fakeIntel()).run(input());
    const titles = out.findings.map((f) => f.title);
    expect(titles.some((t) => /^\.NET 6 is end of life \(since 2024-11-12\)/.test(t))).toBe(true);
    expect(titles.some((t) => /^Node\.js 22 reaches end of life on/.test(t))).toBe(true);
    expect(out.findings.find((f) => f.ruleId === 'framework-eol')?.remediation).toMatch(/\.NET 8 \(LTS\)/);
    // React has no cycle data in the fake feed: no finding, no failure.
    expect(out.status).toBe('ok');
  });

  it('certificates: expiring certificates, weak keys, key stores and expiring tokens', async () => {
    const out = await new CertificatesScanner().run(input());
    const rules = out.findings.map((f) => f.ruleId).sort();
    expect(rules).toEqual(['certificate-expiring', 'certificate-weak-key', 'keystore-in-repository', 'token-expiring']);
    const cert = out.findings.find((f) => f.ruleId === 'certificate-expiring')!;
    expect(cert.details).toMatchObject({ subject: 'CN=argus.test', selfSigned: true });
    expect((cert.details as { daysLeft: number }).daysLeft).toBeLessThanOrEqual(5);
    expect(JSON.stringify(out.findings.find((f) => f.ruleId === 'token-expiring'))).not.toMatch(/eyJhbGciOiJIUzI1NiJ9\.ey/);
  });
});

describe('secrets in git history', () => {
  const token = ['ghp_', 'Hist'.repeat(9)].join('');
  const npmToken = ['npm_', 'Kept'.repeat(9)].join('');
  let repoDir: string;

  beforeAll(async () => {
    repoDir = mkdtempSync(join(tmpdir(), 'argus-history-'));
    const git = (...args: string[]) => execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], { cwd: repoDir, stdio: 'ignore' });
    git('init', '-q', '-b', 'main');
    writeFileSync(join(repoDir, 'README.md'), 'hello\n');
    git('add', '.');
    git('commit', '-q', '-m', 'initial');
    mkdirSync(join(repoDir, 'src'));
    mkdirSync(join(repoDir, 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(repoDir, 'src', 'app.js'), `const a = 1;\nconst t = "${token}";\n`);
    writeFileSync(join(repoDir, 'src', 'keep.js'), `const k = "${npmToken}";\n`);
    writeFileSync(join(repoDir, 'node_modules', 'x', 'leak.js'), `"${['ghp_', 'Vend'.repeat(9)].join('')}"`);
    git('add', '-f', '.');
    git('commit', '-q', '-m', 'add config');
    writeFileSync(join(repoDir, 'src', 'app.js'), 'const a = 1;\nconst t = process.env.TOKEN;\n');
    git('commit', '-q', '-am', 'remove token');
  });
  afterAll(() => rmSync(repoDir, { recursive: true, force: true }));

  const historyInput = async (commits: number): Promise<ScanInput> => ({
    workdir: repoDir,
    files: (await walkFiles(repoDir)).filter((f) => !f.path.startsWith('.git/')),
    repo,
    settings: { ...DEFAULT_SCANNING_SETTINGS, secretHistoryCommits: commits },
    log: () => undefined,
    hashSecret: (v) => `h(${v})`,
    readText: async (f) => (await import('node:fs/promises')).readFile(f.abs, 'utf8'),
    excluded: isVendoredPath,
    git: (args) => runGit(args, { cwd: repoDir, home: tmpdir(), timeoutMs: 30_000 }),
  });

  it('parses added lines of a unified diff', () => {
    const patch = ['diff --git a/x.js b/x.js', '--- a/x.js', '+++ b/x.js', '@@ -1,0 +5,2 @@', '+one', '+two', '+++ /dev/null', '@@ -1 +0,0 @@', '+ignored'].join('\n');
    expect([...addedLines(patch)]).toEqual([
      { path: 'x.js', line: 5, text: 'one' },
      { path: 'x.js', line: 6, text: 'two' },
    ]);
  });

  it('is off by default', async () => {
    const out = await new SecretsScanner('argus-no-such-gitleaks-binary', 10_000).run(await historyInput(0));
    expect(out.findings.map((f) => f.ruleId)).toEqual(['npm-access-token']);
  });

  it('reports removed secrets once, with their commit, and skips vendored folders and secrets still in the code', async () => {
    const out = await new SecretsScanner('argus-no-such-gitleaks-binary', 10_000).run(await historyInput(10));
    expect(out.status).toBe('ok');
    const history = out.findings.filter((f) => f.details?.history);
    expect(history).toHaveLength(1);
    const [h] = history;
    expect(h).toMatchObject({ ruleId: 'github-pat', path: 'src/app.js', line: null, title: 'GitHub personal access token in src/app.js (git history)' });
    expect(h.details).toMatchObject({ history: { line: 2, commit: expect.stringMatching(/^[0-9a-f]{40}$/) } });
    expect(h.description).toMatch(/still in the git history/);
    // The same identity as in the current code, so removing it from the code does not close the finding.
    expect(h.identity).toEqual(['src/app.js', `h(${token})`]);
    expect(out.findings.filter((f) => f.ruleId === 'npm-access-token')).toHaveLength(1);
  });

  it('becomes partial when the history cannot be read', async () => {
    const out = await new SecretsScanner('argus-no-such-gitleaks-binary', 10_000).run({ ...(await historyInput(5)), git: async () => Promise.reject(new Error('boom')) });
    expect(out.status).toBe('partial');
    expect(out.message).toMatch(/git history could not be scanned: boom/);
  });
});
