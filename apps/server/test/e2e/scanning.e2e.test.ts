import 'reflect-metadata';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type INestApplication } from '@nestjs/common';
import { type DataStore } from '@argus/data';
import { type FindingDto, type FindingSummary, type Paged, type RepositoryDto, type ScanRunDto } from '@argus/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiApp } from '../../src/app.factory';
import { AppConfig } from '../../src/config/app-config';
import { DATA_STORE } from '../../src/core/tokens';
import { BASE_TEST_ENV, Client, dbHarnesses, waitFor } from './helpers';
import { createGitRepo, type FixtureRepo, type MockGitHub, startMockGitHub } from './mock-github';
import { intelEnv, intelRoutes, lockfile, LODASH_GHSA } from './mock-intel';

const TOKEN = 'ghp_e2eScanningToken0123456789';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

const harnesses = dbHarnesses();

describe.each(harnesses)('scanners, findings & SBOM e2e: $name', (h) => {
  let app: INestApplication;
  let admin: Client;
  let mock: MockGitHub;
  let fixture: FixtureRepo;
  let tmp: string;
  let repo: RepositoryDto;
  let teamId = '';
  const intelCalls = new Map<string, number>();

  const latestRun = async (after?: string) =>
    waitFor(
      async () => {
        const r = (await admin.call('get', `/api/v1/repos/${repo.id}`)).body as RepositoryDto;
        if (!r.lastScanRunId || r.lastScanRunId === after || r.lastScanStatus === 'queued' || r.lastScanStatus === 'running') return null;
        return (await admin.call('get', `/api/v1/scans/${r.lastScanRunId}`)).body as ScanRunDto;
      },
      { what: 'scan to finish', timeoutMs: 90_000 },
    );
  const findings = async (query = '') => (await admin.call('get', `/api/v1/findings?repoId=${repo.id}&pageSize=100${query}`)).body as Paged<FindingDto>;

  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'argus-scan-e2e-'));
    fixture = createGitRepo(tmp, {
      'package.json': JSON.stringify({ name: 'shop', dependencies: { lodash: '^4.17.20', 'gpl-lib': '1.0.0' } }),
      'package-lock.json': lockfile('4.17.20'),
      'src/Api/Api.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>',
      'src/config.js': `module.exports = { region: "eu-west-1", accessKeyId: "${AWS_KEY}" };\n`,
      'test/fixtures/sample-key.pem': '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n',
      '.argus.yml': 'suppress:\n  - scanner: secrets\n    path: "test/**"\n    reason: Throwaway keys used only by unit tests\n',
    });
    mock = await startMockGitHub({ bare: fixture.bare, token: TOKEN, repos: [{ id: 501, name: 'shop' }], extra: intelRoutes(intelCalls) });
    const env = await h.env();
    app = await createApiApp(
      AppConfig.fromEnv({
        ...env,
        ...BASE_TEST_ENV,
        ARGUS_ADMIN_PASSWORD: 'Initial-Admin-Pass-1',
        ARGUS_ROLE: 'all',
        ARGUS_SCAN_WORKDIR: join(tmp, 'scans'),
        ARGUS_SCHEDULER_INTERVAL_SECONDS: '1',
        ARGUS_GITLEAKS_PATH: 'argus-test-no-gitleaks',
        ...intelEnv(mock.baseUrl),
      }),
    );
    await app.init();
    admin = new Client(app);
    await admin.login('admin', 'Initial-Admin-Pass-1');
    await admin.call('post', '/api/v1/auth/change-password', { currentPassword: 'Initial-Admin-Pass-1', newPassword: 'Second-Root-Pass-9' });
    teamId = (await admin.call('post', '/api/v1/teams', { name: 'Shop' })).body.id;
    await admin.call('post', '/api/v1/sources', { name: 'Mock', provider: 'github', baseUrl: mock.baseUrl, scope: 'acme', token: TOKEN, autoActivatePattern: 'acme/*', defaultTeamId: teamId });
    repo = await waitFor(async () => ((await admin.call('get', '/api/v1/repos')).body as Paged<RepositoryDto>).items[0], { what: 'repository discovery' });
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    mock?.server.close();
    await h.stop();
    rmSync(tmp, { recursive: true, force: true });
  });

  it('runs every scanner and records a summary on the scan run', async () => {
    const run = await latestRun();
    expect(run.status).toBe('succeeded');
    expect(run.stats?.scanners?.map((s) => [s.scanner, s.status])).toEqual([
      ['secrets', 'ok'],
      ['dependencies', 'ok'],
      ['licenses', 'ok'],
      ['frameworks', 'ok'],
      ['certificates', 'ok'],
      ['code', 'skipped'],
      ['iac', 'skipped'],
      ['containers', 'skipped'],
    ]);
    expect(run.stats?.dependencies).toBe(3);
    expect(run.stats?.findings).toMatchObject({ new: 5, fixed: 0 });
    expect(run.log!.some((l) => l.includes('Scan completed: 5 new, 0 fixed'))).toBe(true);
    expect(JSON.stringify(run)).not.toContain(AWS_KEY);
  });

  it('stores scored, explainable findings without secret values', async () => {
    const page = await findings();
    expect(page.total).toBe(5);
    const by = new Map(page.items.map((f) => [f.ruleId, f]));

    const vuln = by.get(LODASH_GHSA)!;
    expect(vuln).toMatchObject({
      scanner: 'dependencies',
      status: 'open',
      repoFullName: 'acme/shop',
      path: 'package-lock.json',
      package: { name: 'lodash', version: '4.17.20', fixedVersion: '4.17.21', direct: true },
      advisory: { aliases: ['CVE-2021-23337'], kev: true, epss: 0.4, cvssScore: 7.2 },
    });
    // 72 (CVSS 7.2) + 15 (KEV) + 6 (EPSS 40% of 15) = 93 -> critical.
    expect(vuln.riskScore).toBe(93);
    expect(vuln.severity).toBe('critical');
    expect(vuln.riskFactors.map((f) => f.key)).toEqual(['base', 'kev', 'epss']);
    expect(vuln.remediation).toMatch(/Upgrade lodash to 4\.17\.21/);

    const secret = by.get('aws-access-token')!;
    expect(secret).toMatchObject({ scanner: 'secrets', status: 'open', path: 'src/config.js', line: 1, secret: { preview: 'AKIA…MPLE' } });
    const testKey = by.get('private-key')!;
    expect(testKey.status).toBe('suppressed');
    expect(testKey.details).toMatchObject({ suppression: { source: 'repo-file', reason: 'Throwaway keys used only by unit tests' } });

    expect(by.get('framework-eol')).toMatchObject({ scanner: 'frameworks', path: 'src/Api/Api.csproj', details: { product: 'dotnet', cycle: '6', suggested: '8' } });
    expect(by.get('license-denied')).toMatchObject({ scanner: 'licenses', package: { name: 'gpl-lib' }, details: { license: 'GPL-3.0-only' } });
    expect(JSON.stringify(page)).not.toContain(AWS_KEY);

    expect((await findings('&severity=critical')).total).toBe(1);
    expect((await findings('&status=suppressed')).total).toBe(1);
    expect((await findings('&search=lodash')).total).toBe(1);
    const summary = (await admin.call('get', `/api/v1/findings/summary?repoId=${repo.id}`)).body as FindingSummary;
    expect(summary).toMatchObject({ openTotal: 4, suppressed: 1, byScanner: { dependencies: 1, secrets: 1, frameworks: 1, licenses: 1 } });
  });

  it('exposes the dependency inventory, a CycloneDX SBOM and cross-repository package search', async () => {
    const deps = (await admin.call('get', `/api/v1/repos/${repo.id}/dependencies?pageSize=50`)).body;
    expect(deps.total).toBe(3);
    expect(deps.items[0]).toMatchObject({ name: 'lodash', vulnerabilities: 1, latestVersion: '4.17.21', license: 'MIT' });
    expect(deps.items.find((d: { name: string }) => d.name === 'Newtonsoft.Json')).toMatchObject({ ecosystem: 'nuget', latestVersion: '13.0.1' });

    const sbomRes = await admin.call('get', `/api/v1/repos/${repo.id}/sbom`);
    expect(sbomRes.headers['content-type']).toMatch(/application\/vnd\.cyclonedx\+json/);
    expect(sbomRes.headers['content-disposition']).toMatch(/acme_shop\.cdx\.json/);
    const sbom = sbomRes.body;
    expect(sbom).toMatchObject({ bomFormat: 'CycloneDX', specVersion: '1.5', metadata: { component: { name: 'acme/shop' } } });
    expect(sbom.components.map((c: { purl: string }) => c.purl).sort()).toEqual(['pkg:npm/gpl-lib@1.0.0', 'pkg:npm/lodash@4.17.20', 'pkg:nuget/Newtonsoft.Json@13.0.1']);
    expect(sbom.vulnerabilities).toEqual([expect.objectContaining({ id: LODASH_GHSA, affects: [{ ref: 'pkg:npm/lodash@4.17.20' }] })]);

    expect((await admin.call('get', '/api/v1/packages/search?name=LODASH')).body.total).toBe(1);
    expect((await admin.call('get', '/api/v1/packages/search?name=lodash&version=%3C4.17.21')).body.items[0]).toMatchObject({ repoFullName: 'acme/shop', version: '4.17.20' });
    expect((await admin.call('get', '/api/v1/packages/search?name=lodash&version=%3C4.0.0')).body.total).toBe(0);
    expect((await admin.call('get', '/api/v1/packages/search?name=newtonsoft.json&ecosystem=nuget')).body.total).toBe(1);
  });

  it('suppressions apply immediately, are audited, need triage rights, and can be removed', async () => {
    const dev = await admin.call('post', '/api/v1/users', { username: 'dev.shop', displayName: 'Dev', role: 'developer', password: 'Dev-Shop-Pass-1234', teamIds: [teamId] });
    const d = new Client(app);
    await d.login('dev.shop', 'Dev-Shop-Pass-1234');
    await d.call('post', '/api/v1/auth/change-password', { currentPassword: 'Dev-Shop-Pass-1234', newPassword: 'Dev-Shop-Pass-5678' });
    expect((await d.call('get', `/api/v1/findings?repoId=${repo.id}`)).body.total).toBe(5);
    expect((await d.call('post', '/api/v1/suppressions', { repoId: repo.id, ruleId: 'CVE-2021-23337', reason: 'Not reachable' })).status).toBe(403);

    const bad = await admin.call('post', '/api/v1/suppressions', { repoId: repo.id, reason: 'Too broad' });
    expect(bad.status).toBe(400);
    const created = await admin.call('post', '/api/v1/suppressions', { repoId: repo.id, ruleId: 'cve-2021-23337', reason: 'Template function is never called' });
    expect(created.status).toBe(201);
    expect(created.body).toMatchObject({ matchedFindings: 1, repoFullName: 'acme/shop', createdByName: 'System Administrator' });
    expect((await findings('&status=suppressed')).total).toBe(2);
    expect((await admin.call('get', `/api/v1/suppressions?repoId=${repo.id}`)).body).toHaveLength(1);

    const removed = await admin.call('delete', `/api/v1/suppressions/${created.body.id}`);
    expect(removed.body).toEqual({ reopened: 1 });
    expect((await findings('&status=open')).total).toBe(4);

    // Team scoping: once the developer leaves the team, findings disappear for them.
    const one = (await findings()).items[0];
    await admin.call('patch', `/api/v1/users/${dev.body.user.id}`, { teamIds: [] });
    expect((await d.call('get', '/api/v1/findings')).body.total).toBe(0);
    expect((await d.call('get', `/api/v1/findings/${one.id}`)).status).toBe(404);
    expect((await d.call('get', '/api/v1/packages/search?name=lodash')).body.total).toBe(0);
  });

  it('marks fixed issues fixed after the next scan, and honours disabled scanners', async () => {
    const before = (await admin.call('get', `/api/v1/repos/${repo.id}`)).body as RepositoryDto;
    await admin.call('patch', `/api/v1/repos/${repo.id}`, { disabledScanners: ['licenses'] });
    fixture.commit({ 'src/config.js': 'module.exports = { region: process.env.AWS_REGION };\n', 'package-lock.json': lockfile('4.17.21') }, 'Remove key, upgrade lodash');
    expect((await admin.call('post', `/api/v1/repos/${repo.id}/scans`)).status).toBe(202);
    const run = await latestRun(before.lastScanRunId!);

    expect(run.commitSha).toBe(fixture.sha);
    expect(run.stats?.scanners?.find((s) => s.scanner === 'licenses')).toMatchObject({ status: 'skipped' });
    expect(run.stats?.findings).toMatchObject({ new: 0, fixed: 2 });
    const fixed = await findings('&status=fixed');
    expect(fixed.items.map((f) => f.ruleId).sort()).toEqual([LODASH_GHSA, 'aws-access-token'].sort());
    expect(fixed.items.every((f) => f.fixedAt)).toBe(true);
    // The license scanner did not run, so its finding is left as it was rather than "fixed".
    expect((await findings('&scanner=licenses')).items[0].status).toBe('open');
  });

  it('manages scanning settings and reports intel feed status', async () => {
    const settings = (await admin.call('get', '/api/v1/settings/scanning')).body;
    expect(settings.riskWeights.kev).toBe(15);
    const updated = await admin.call('put', '/api/v1/settings/scanning', { ...settings, licenseDeny: [...settings.licenseDeny, 'WTFPL'], eolWarningDays: 90 });
    expect(updated.body).toMatchObject({ eolWarningDays: 90 });
    expect((await admin.call('put', '/api/v1/settings/scanning', { ...settings, eolWarningDays: -1 })).status).toBe(400);

    const status = (await admin.call('get', '/api/v1/intel/status')).body;
    expect(status.gitleaks).toEqual({ available: false, version: null });
    const feeds = new Map(status.feeds.map((f: { key: string; fetchedAt: string | null; entries: number | null; error: string | null }) => [f.key, f]));
    expect(feeds.get('osv')).toMatchObject({ error: null });
    expect(feeds.get('kev')).toMatchObject({ entries: 2, error: null });
    expect(intelCalls.get('osv-vuln')).toBe(1);

    const actions = new Set(((await admin.call('get', '/api/v1/audit?pageSize=100')).body.items as { action: string }[]).map((e) => e.action));
    for (const a of ['suppression.created', 'suppression.deleted', 'repo.sbom_exported', 'settings.scanning_updated']) expect(actions).toContain(a);
  });

  it('reports ongoing scans as activity, within the caller\'s scope', async () => {
    expect((await admin.call('get', '/api/v1/activity')).body).toEqual({ scans: { running: [], runningTotal: 0, queued: 0 }, tasks: [] });

    // A run row without a job is never picked up by the worker, so it stays "running" for the assertions.
    const store = app.get<DataStore>(DATA_STORE);
    const run = await store.scanRuns.create({ repoId: repo.id, sourceId: repo.sourceId, teamId, trigger: 'manual', requestedBy: null, branch: null });
    await store.scanRuns.update(run.id, { status: 'running', startedAt: new Date() });
    const busy = (await admin.call('get', '/api/v1/activity')).body;
    expect(busy.scans).toMatchObject({ runningTotal: 1, queued: 0, running: [{ id: run.id, repoId: repo.id, repoFullName: repo.fullName }] });

    await admin.call('post', '/api/v1/users', { username: 'viewer.other', displayName: 'Other', role: 'viewer', password: 'Viewer-Other-Pass-1234', teamIds: [] });
    const v = new Client(app);
    await v.login('viewer.other', 'Viewer-Other-Pass-1234');
    await v.call('post', '/api/v1/auth/change-password', { currentPassword: 'Viewer-Other-Pass-1234', newPassword: 'Viewer-Other-Pass-5678' });
    expect((await v.call('get', '/api/v1/activity')).body.scans).toEqual({ running: [], runningTotal: 0, queued: 0 });

    await store.scanRuns.update(run.id, { status: 'cancelled', finishedAt: new Date() });
  });

  it('leaves no workspace or scanner report behind', () => {
    const dir = join(tmp, 'scans');
    expect(existsSync(dir) ? readdirSync(dir) : []).toEqual([]);
  });
});
