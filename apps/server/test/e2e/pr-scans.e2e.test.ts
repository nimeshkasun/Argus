import 'reflect-metadata';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { type IncomingMessage, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { type INestApplication } from '@nestjs/common';
import { type FindingDto, type Paged, type PrScanDto, type RepositoryDto } from '@argus/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiApp } from '../../src/app.factory';
import { AppConfig } from '../../src/config/app-config';
import { BASE_TEST_ENV, Client, dbHarnesses, waitFor } from './helpers';
import { createGitRepo, type FixtureRepo, type MockGitHub, startMockGitHub } from './mock-github';
import { intelEnv, intelRoutes, lockfile, LODASH_GHSA } from './mock-intel';

const TOKEN = 'ghp_e2ePrScanToken0123456789abcdef';
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const NEW_SECRET = `ghp_${'Zx9Yw8Vu'.repeat(4)}abcd`;

const git = (args: string[], cwd: string) => execFileSync('git', ['-c', 'user.name=Dev', '-c', 'user.email=dev@example.com', ...args], { cwd, stdio: 'pipe' }).toString().trim();

describe.each(dbHarnesses())('pull request scans from CI e2e: $name', (h) => {
  let app: INestApplication;
  let admin: Client;
  let mock: MockGitHub;
  let fixture: FixtureRepo;
  let tmp: string;
  let repo: RepositoryDto;
  let ciToken = '';
  let prHead = '';
  const comments: { method: string; path: string; body: string }[] = [];
  const intelCalls = new Map<string, number>();

  /** Commits a pull request branch on top of main and publishes it as refs/pull/7/head, like GitHub does. */
  const pushPullRequest = (files: Record<string, string>, message: string) => {
    git(['checkout', '-q', '-B', 'feature', prHead || 'main'], fixture.work);
    for (const [path, content] of Object.entries(files)) {
      mkdirSync(dirname(join(fixture.work, path)), { recursive: true });
      writeFileSync(join(fixture.work, path), content);
      git(['add', path], fixture.work);
    }
    git(['commit', '-q', '-m', message], fixture.work);
    prHead = git(['rev-parse', 'HEAD'], fixture.work);
    git(['push', '-q', '-f', fixture.bare, `HEAD:refs/pull/7/head`], fixture.work);
    git(['update-server-info'], fixture.bare);
    git(['checkout', '-q', 'main'], fixture.work);
  };

  const pullRequestRoutes = (req: IncomingMessage, url: URL, body: string, res: ServerResponse): boolean => {
    const json = (data: unknown, status = 200) => (res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(data)), true);
    const p = url.pathname;
    if (!p.startsWith('/api/v3/repos/acme/shop/')) return false;
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return json({ message: 'Bad credentials' }, 401);
    if (p === '/api/v3/repos/acme/shop/pulls/7') return json({ title: 'Add checkout', html_url: `${mock.baseUrl}/acme/shop/pull/7`, state: 'open', merged_at: null, head: { sha: prHead, ref: 'feature' }, base: { ref: 'main' } });
    if (p === '/api/v3/repos/acme/shop/pulls/8') return json({ title: 'Old', html_url: '', state: 'closed', merged_at: '2026-01-01T00:00:00Z', head: { sha: 'x', ref: 'old' }, base: { ref: 'main' } });
    if (p === '/api/v3/repos/acme/shop/pulls/7/files')
      return json([
        { filename: 'src/checkout.js', status: 'added' },
        { filename: 'src/config.js', status: 'modified' },
        { filename: 'package-lock.json', status: 'modified' },
        { filename: 'gone.txt', status: 'removed' },
      ]);
    if (req.method === 'POST' && p === '/api/v3/repos/acme/shop/issues/7/comments') {
      comments.push({ method: 'POST', path: p, body: (JSON.parse(body) as { body: string }).body });
      return json({ id: 4242, html_url: `${mock.baseUrl}/acme/shop/pull/7#issuecomment-4242` }, 201);
    }
    if (req.method === 'PATCH' && p === '/api/v3/repos/acme/shop/issues/comments/4242') {
      comments.push({ method: 'PATCH', path: p, body: (JSON.parse(body) as { body: string }).body });
      return json({ id: 4242, html_url: `${mock.baseUrl}/acme/shop/pull/7#issuecomment-4242` });
    }
    return json({ message: 'Not Found' }, 404);
  };

  const ci = (method: 'get' | 'post', path: string, body?: object, token = ciToken) => {
    const r = request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${token}`);
    return body ? r.send(body) : r;
  };
  const finished = (id: string) =>
    waitFor(
      async () => {
        const s = (await ci('get', `/api/v1/ci/pull-requests/${id}`)).body as PrScanDto;
        return s.status === 'succeeded' || s.status === 'failed' ? s : null;
      },
      { what: 'pull request scan', timeoutMs: 90_000 },
    );

  beforeAll(async () => {
    tmp = mkdtempSync(join(tmpdir(), 'argus-pr-e2e-'));
    // main: lodash is patched, and an old AWS key is already known.
    fixture = createGitRepo(tmp, {
      'package.json': JSON.stringify({ name: 'shop', dependencies: { lodash: '^4.17.21', 'gpl-lib': '1.0.0' } }),
      'package-lock.json': lockfile('4.17.21'),
      'src/config.js': `module.exports = { accessKeyId: "${AWS_KEY}" };\n`,
    });
    const intel = intelRoutes(intelCalls);
    mock = await startMockGitHub({ bare: fixture.bare, token: TOKEN, repos: [{ id: 601, name: 'shop' }], extra: (req, url, body, res) => pullRequestRoutes(req, url, body, res) || intel(req, url, body, res) });
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
        ARGUS_PUBLIC_URL: 'https://argus.example.com',
        ...intelEnv(mock.baseUrl),
      }),
    );
    await app.init();
    admin = new Client(app);
    await admin.login('admin', 'Initial-Admin-Pass-1');
    await admin.call('post', '/api/v1/auth/change-password', { currentPassword: 'Initial-Admin-Pass-1', newPassword: 'Second-Root-Pass-9' });
    await admin.call('post', '/api/v1/sources', { name: 'Mock', provider: 'github', baseUrl: mock.baseUrl, scope: 'acme', token: TOKEN, autoActivatePattern: 'acme/*' });
    repo = await waitFor(async () => ((await admin.call('get', '/api/v1/repos')).body as Paged<RepositoryDto>).items[0], { what: 'repository discovery' });
    // The repository's own scan sets the baseline the pull request is compared with.
    await waitFor(async () => {
      const r = (await admin.call('get', `/api/v1/repos/${repo.id}`)).body as RepositoryDto;
      return r.lastScanStatus === 'succeeded' ? r : null;
    }, { what: 'baseline scan', timeoutMs: 90_000 });
    ciToken = (await admin.call('post', '/api/v1/me/tokens', { name: 'CI', scopes: ['scans:run', 'repos:read'], expiresInDays: 30 })).body.token;

    // The pull request: a new hard-coded token, a downgrade to a vulnerable lodash, and an edit next to the known AWS key.
    pushPullRequest(
      {
        'src/checkout.js': `const token = "${NEW_SECRET}";\nmodule.exports = token;\n`,
        'package-lock.json': lockfile('4.17.20'),
        'src/config.js': `module.exports = { accessKeyId: "${AWS_KEY}", region: "eu-west-1" };\n`,
      },
      'checkout',
    );
  }, 240_000);

  afterAll(async () => {
    await app?.close();
    mock?.server.close();
    await h.stop();
    rmSync(tmp, { recursive: true, force: true });
  });

  it('refuses requests it cannot serve', async () => {
    expect((await request(app.getHttpServer()).post('/api/v1/ci/pull-requests').send({ repository: 'acme/shop', pullRequest: 7 })).status).toBe(401);
    const readOnly = (await admin.call('post', '/api/v1/me/tokens', { name: 'Read only', scopes: ['repos:read'], expiresInDays: 7 })).body.token as string;
    expect((await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/shop', pullRequest: 7 }, readOnly)).status).toBe(403);
    expect((await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/nope', pullRequest: 7 })).status).toBe(404);
    expect((await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/shop', pullRequest: 99 })).status).toBe(404);
    const closed = await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/shop', pullRequest: 8 });
    expect(closed.status).toBe(409);
    expect(closed.body.message).toMatch(/merged/);
    expect((await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/shop', pullRequest: 7, failOn: 'sometimes' })).status).toBe(400);
  });

  it('scans the pull request, reports only what it introduces, and comments with fixes', async () => {
    const before = ((await admin.call('get', `/api/v1/findings?repoId=${repo.id}&pageSize=100`)).body as Paged<FindingDto>).total;
    const res = await ci('post', '/api/v1/ci/pull-requests', { repository: 'ACME/shop', pullRequest: 7, failOn: 'high' });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({ repoFullName: 'acme/shop', number: 7, title: 'Add checkout', headSha: prHead, headBranch: 'feature', baseBranch: 'main', status: 'queued', gate: null });
    expect(res.body.argusUrl).toBe(`https://argus.example.com/repositories/${repo.id}?tab=pull-requests&scan=${res.body.id}`);

    const scan = await finished(res.body.id);
    expect(scan.status).toBe('succeeded');
    expect(scan.gate).toBe('failed');
    const result = scan.result!;
    expect(result.changedFiles).toBe(3);
    expect(result.findings.map((f) => f.ruleId).sort()).toEqual([LODASH_GHSA, 'github-pat'].sort());
    expect(result.findings.find((f) => f.ruleId === LODASH_GHSA)).toMatchObject({ path: 'package-lock.json', fixCommand: 'npm install lodash@4.17.21' });
    // The AWS key was already known and the GPL license finding is unchanged: neither counts against the pull request.
    expect(result.existingInChangedFiles).toBe(2);
    expect(scan.commentUrl).toBe(`${mock.baseUrl}/acme/shop/pull/7#issuecomment-4242`);

    expect(comments).toHaveLength(1);
    const body = comments[0].body;
    expect(body).toContain('Argus security scan: ❌ failed');
    expect(body).toContain('**2 new issues** in this pull request');
    expect(body).toContain('npm install lodash@4.17.21');
    expect(body).toContain('[open in Argus](https://argus.example.com/repositories/');
    expect(body).not.toContain(NEW_SECRET);
    expect(body).not.toContain(AWS_KEY);
    expect(JSON.stringify(scan)).not.toContain(NEW_SECRET);

    // A pull request scan is a preview: the repository's findings are untouched.
    expect(((await admin.call('get', `/api/v1/findings?repoId=${repo.id}&pageSize=100`)).body as Paged<FindingDto>).total).toBe(before);
    const list = (await admin.call('get', `/api/v1/ci/pull-requests?repoId=${repo.id}`)).body as Paged<PrScanDto>;
    expect(list.items[0]).toMatchObject({ id: scan.id, gate: 'failed' });
  });

  it('updates its comment when the pull request changes, and passes once the issues are fixed', async () => {
    pushPullRequest({ 'src/checkout.js': 'module.exports = process.env.CHECKOUT_TOKEN;\n', 'package-lock.json': lockfile('4.17.21') }, 'fix');
    const res = await ci('post', '/api/v1/ci/pull-requests', { repository: 'acme/shop', pullRequest: 7 });
    const scan = await finished(res.body.id);
    expect(scan).toMatchObject({ status: 'succeeded', gate: 'passed', headSha: prHead });
    expect(scan.result!.findings).toEqual([]);
    expect(comments.map((c) => c.method)).toEqual(['POST', 'PATCH']);
    expect(comments[1].body).toContain('✅ passed');
    expect(comments[1].body).toContain('**No new issues**');

    const audit = (await admin.call('get', '/api/v1/audit?action=pr_scan.requested&pageSize=10')).body as { items: { details: Record<string, unknown> }[] };
    expect(audit.items.length).toBeGreaterThanOrEqual(2);
    expect(audit.items[0].details).toMatchObject({ repo: 'acme/shop', pullRequest: 7 });
  });
});
