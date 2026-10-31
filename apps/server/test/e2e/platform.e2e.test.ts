import 'reflect-metadata';
import { createServer, type Server } from 'node:http';
import { type AddressInfo } from 'node:net';
import { type INestApplication } from '@nestjs/common';
import { type DataStore } from '@argus/data';
import { type ApiTokenCreatedDto, type ApiTokenDto } from '@argus/shared';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createApiApp } from '../../src/app.factory';
import { AppConfig } from '../../src/config/app-config';
import { DATA_STORE } from '../../src/core/tokens';
import { CredentialsService } from '../../src/credentials/credentials.service';
import { NotificationsService } from '../../src/integrations/notifications.service';
import { BASE_TEST_ENV, Client, dbHarnesses } from './helpers';

const harnesses = dbHarnesses();
const METRICS_TOKEN = 'metrics-token-0123456789';

describe.each(harnesses)('platform e2e: $name', (h) => {
  let app: INestApplication;
  let admin: Client;
  let dev: Client;
  let devId = '';

  const bearer = (token: string) => ({ headers: { Authorization: `Bearer ${token}` } });
  const anon = (method: 'get' | 'post' | 'put' | 'delete' | 'patch', path: string, token: string, body?: object) => {
    const r = request(app.getHttpServer())[method](path).set('Authorization', `Bearer ${token}`);
    return body ? r.send(body) : r;
  };

  /** Mock Microsoft Entra token endpoint and Graph applications API (two pages). */
  let graph: Server;
  const graphState = { apps: [] as unknown[], webhooks: [] as { title: string; event: string }[] };
  const graphUrl = () => `http://127.0.0.1:${(graph.address() as AddressInfo).port}`;

  beforeAll(async () => {
    graph = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        const json = (data: unknown, status = 200) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(data));
        const url = new URL(req.url ?? '/', graphUrl());
        if (url.pathname === '/login/contoso/oauth2/v2.0/token') return new URLSearchParams(body).get('client_secret') === 'entra-secret-0001' ? json({ access_token: 'graph-token' }) : json({ error: 'invalid_client' }, 401);
        if (url.pathname === '/hook') {
          graphState.webhooks.push(JSON.parse(body));
          return json({ ok: true });
        }
        if (req.headers.authorization !== 'Bearer graph-token') return json({ error: 'unauthorized' }, 401);
        if (url.pathname === '/graph/v1.0/applications' && !url.searchParams.get('page')) return json({ value: graphState.apps.slice(0, 1), '@odata.nextLink': `${graphUrl()}/graph/v1.0/applications?page=2` });
        if (url.pathname === '/graph/v1.0/applications') return json({ value: graphState.apps.slice(1) });
        return json({}, 404);
      });
    });
    await new Promise<void>((r) => graph.listen(0, '127.0.0.1', r));
    const env = await h.env();
    app = await createApiApp(
      AppConfig.fromEnv({ ...env, ...BASE_TEST_ENV, ARGUS_ADMIN_PASSWORD: 'Initial-Admin-Pass-1', ARGUS_ROLE: 'api', ARGUS_METRICS_TOKEN: METRICS_TOKEN, ARGUS_GRAPH_URL: `${graphUrl()}/graph`, ARGUS_ENTRA_LOGIN_URL: `${graphUrl()}/login` }),
    );
    await app.init();
    admin = new Client(app);
    await admin.login('admin', 'Initial-Admin-Pass-1');
    await admin.call('post', '/api/v1/auth/change-password', { currentPassword: 'Initial-Admin-Pass-1', newPassword: 'Second-Root-Pass-9' });
    devId = (await admin.call('post', '/api/v1/users', { username: 'dev.tok', displayName: 'Dev Tok', role: 'developer', password: 'Dev-Tok-Pass-12345', teamIds: [] })).body.user.id;
    dev = new Client(app);
    await dev.login('dev.tok', 'Dev-Tok-Pass-12345');
    await dev.call('post', '/api/v1/auth/change-password', { currentPassword: 'Dev-Tok-Pass-12345', newPassword: 'Dev-Tok-Pass-67890' });
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    graph?.close();
    await h.stop();
  });

  describe('credential inventory', () => {
    it('tracks credentials (never their values), scoped to teams, with audited changes', async () => {
      const team = (await admin.call('post', '/api/v1/teams', { name: 'Payments' })).body.id;
      const res = await admin.call('post', '/api/v1/credentials', { name: 'Stripe live key', kind: 'api_key', system: 'Stripe', owner: 'payments@acme.com', teamId: team, expiresAt: new Date(Date.now() + 10 * 86_400_000).toISOString(), notifyEmails: ['payments@acme.com'] });
      expect(res.status).toBe(201);
      expect(res.body).toMatchObject({ source: 'manual', teamName: 'Payments', daysLeft: 9 });
      expect(Object.keys(res.body)).not.toContain('value');
      // Developers can see credentials of their teams only and cannot manage them.
      expect(((await dev.call('get', '/api/v1/credentials')).body as { total: number }).total).toBe(0);
      expect((await dev.call('post', '/api/v1/credentials', { name: 'x', kind: 'other', expiresAt: new Date().toISOString() })).status).toBe(403);
      const list = (await admin.call('get', '/api/v1/credentials?expiringWithinDays=30')).body as { items: { id: string; name: string }[] };
      expect(list.items.map((c) => c.name)).toContain('Stripe live key');
      const renewed = await admin.call('patch', `/api/v1/credentials/${res.body.id}`, { expiresAt: new Date(Date.now() + 365 * 86_400_000).toISOString() });
      expect(renewed.body.daysLeft).toBeGreaterThan(360);
      expect((await admin.call('get', '/api/v1/audit?action=credential.updated')).body.items[0].details).toMatchObject({ renewed: true });
      // Tracked credentials appear on the dashboard's expiry timeline.
      await admin.call('patch', `/api/v1/credentials/${res.body.id}`, { expiresAt: new Date(Date.now() + 20 * 86_400_000).toISOString() });
      const d = (await admin.call('get', '/api/v1/dashboard?days=30')).body as { expiring: { kind: string; title: string }[] };
      expect(d.expiring).toEqual([expect.objectContaining({ kind: 'credential', title: 'Stripe live key' })]);
      expect((await admin.call('delete', `/api/v1/credentials/${res.body.id}`)).status).toBe(200);
    });

    it('imports Entra ID application secrets and certificates, archiving ones removed in Entra', async () => {
      const end = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
      graphState.apps = [
        { appId: 'app-1', displayName: 'Payroll API', passwordCredentials: [{ keyId: 'k1', displayName: 'prod', endDateTime: end(12) }], keyCredentials: [{ keyId: 'c1', displayName: 'CN=payroll', endDateTime: end(200) }] },
        { appId: 'app-2', displayName: 'Intranet', passwordCredentials: [{ keyId: 'k2', displayName: null, endDateTime: end(400) }], keyCredentials: [] },
      ];
      expect((await admin.call('put', '/api/v1/credentials/entra', { enabled: true, tenantId: 'contoso', clientId: 'app-id' })).status).toBe(400);
      const saved = await admin.call('put', '/api/v1/credentials/entra', { enabled: true, tenantId: 'contoso', clientId: 'app-id', clientSecret: 'entra-secret-0001' });
      expect(saved.body).toMatchObject({ secretConfigured: true, secretHint: '••••0001' });
      expect(JSON.stringify(saved.body)).not.toContain('entra-secret-0001');
      expect((await dev.call('get', '/api/v1/credentials/entra')).status).toBe(403);

      const sync = await admin.call('post', '/api/v1/credentials/entra/sync');
      expect(sync.body).toMatchObject({ lastSyncError: null, lastSyncCount: 3 });
      let list = (await admin.call('get', '/api/v1/credentials?search=Payroll')).body as { items: { name: string; kind: string; source: string; id: string }[] };
      expect(list.items.map((c) => [c.name, c.kind, c.source])).toEqual([
        ['Payroll API — prod', 'client_secret', 'entra'],
        ['Payroll API — CN=payroll', 'certificate', 'entra'],
      ]);
      expect((await admin.call('delete', `/api/v1/credentials/${list.items[0].id}`)).status).toBe(400);

      // The certificate is removed in Entra: the next sync archives it.
      (graphState.apps[0] as { keyCredentials: unknown[] }).keyCredentials = [];
      expect((await admin.call('post', '/api/v1/credentials/entra/sync')).body.lastSyncCount).toBe(2);
      list = (await admin.call('get', '/api/v1/credentials?search=Payroll')).body;
      expect(list.items.map((c) => c.name)).toEqual(['Payroll API — prod']);
      expect(((await admin.call('get', '/api/v1/credentials?search=Payroll&archived=true')).body as { total: number }).total).toBe(1);

      // A wrong secret is reported, not thrown.
      await admin.call('put', '/api/v1/credentials/entra', { enabled: true, tenantId: 'contoso', clientId: 'app-id', clientSecret: 'wrong-secret' });
      const failed = (await admin.call('post', '/api/v1/credentials/entra/sync')).body;
      expect(failed.lastSyncError).toMatch(/Microsoft Entra ID returned HTTP 401/);
      expect(failed.lastSyncError).not.toContain('wrong-secret');
    });

    it('sends expiry notices through notification rules, once per threshold', async () => {
      const channel = (await admin.call('post', '/api/v1/integrations/channels', { type: 'webhook', name: 'Ops hook', enabled: true, config: { url: `${graphUrl()}/hook` }, secret: 'whsec_0123456789abcdef' })).body.id;
      await admin.call('post', '/api/v1/integrations/rules', { name: 'Expiring credentials', events: ['credential_expiring'], minSeverity: 'medium', channelIds: [channel] });
      await admin.call('post', '/api/v1/credentials', { name: 'Expired DB password', kind: 'password', system: 'Azure SQL', expiresAt: new Date(Date.now() - 86_400_000).toISOString() });
      const svc = app.get(CredentialsService);
      // The expired password, and the imported Entra secret that expires in 12 days (its 14-day notice).
      expect(await svc.sendNotices(new Date())).toBe(2);
      // Already notified at these thresholds: nothing new.
      expect(await svc.sendNotices(new Date())).toBe(0);
      // In the api role nothing delivers jobs, so the queued notification is still there to inspect.
      const store = app.get<DataStore>(DATA_STORE);
      const jobs = (await store.jobs.countByStatus()).filter((j) => j.type === 'notification.deliver' && j.status === 'queued');
      expect(jobs.reduce((n, j) => n + j.count, 0)).toBe(2);
    });
  });

  describe('API tokens', () => {
    let token = '';
    let tokenId = '';

    it('creates a scoped, expiring token shown once and stored only as a hash', async () => {
      expect((await dev.call('post', '/api/v1/me/tokens', { name: 'CI', scopes: ['findings:read', 'users:manage'], expiresInDays: 30 })).status).toBe(400);
      expect((await dev.call('post', '/api/v1/me/tokens', { name: 'CI', scopes: ['findings:read'], expiresInDays: 3650 })).status).toBe(400);
      const res = await dev.call('post', '/api/v1/me/tokens', { name: 'CI', scopes: ['findings:read', 'repos:read'], expiresInDays: 30 });
      expect(res.status).toBe(201);
      const created = res.body as ApiTokenCreatedDto;
      token = created.token;
      tokenId = created.id;
      expect(token).toMatch(/^argus_pat_[A-Za-z0-9_-]{40,}$/);
      expect(token.startsWith(created.prefix)).toBe(true);
      const days = (new Date(created.expiresAt).getTime() - Date.now()) / 86_400_000;
      expect(Math.round(days)).toBe(30);

      const list = (await dev.call('get', '/api/v1/me/tokens')).body as ApiTokenDto[];
      expect(list).toHaveLength(1);
      expect(JSON.stringify(list)).not.toContain(token);
      const audit = (await admin.call('get', '/api/v1/audit?action=api_token.created')).body.items;
      expect(audit[0]).toMatchObject({ actorName: 'dev.tok', targetId: tokenId });
      expect(JSON.stringify(audit)).not.toContain(token);
    });

    it('authenticates with the token, within its scopes and the owner role, without cookies or CSRF', async () => {
      expect((await anon('get', '/api/v1/findings', token)).status).toBe(200);
      expect((await anon('get', '/api/v1/repos', token)).status).toBe(200);
      // Not in the token's scopes, though the developer role has it.
      const tickets = await anon('get', '/api/v1/tickets', token);
      expect(tickets.status).toBe(403);
      expect(tickets.body.message).toMatch(/lacks the scope: tickets:read/);
      // Endpoints that declare no permission, and session-only endpoints, are closed to tokens.
      expect((await anon('get', '/api/v1/auth/me', token)).status).toBe(403);
      expect((await anon('post', '/api/v1/me/tokens', token, { name: 'x', scopes: ['findings:read'], expiresInDays: 7 })).status).toBe(403);
      expect((await anon('get', '/api/v1/findings', 'argus_pat_not-a-real-token')).status).toBe(401);
      expect((await anon('get', '/api/v1/findings', 'not-even-the-format')).status).toBe(401);
      const used = ((await dev.call('get', '/api/v1/me/tokens')).body as ApiTokenDto[])[0];
      expect(used.lastUsedAt).not.toBeNull();
    });

    it('follows the owner: a role downgrade narrows it, disabling the user stops it', async () => {
      await admin.call('patch', `/api/v1/users/${devId}`, { role: 'viewer' });
      // Viewers can still read findings…
      expect((await anon('get', '/api/v1/findings', token)).status).toBe(200);
      const disabled = await admin.call('patch', `/api/v1/users/${devId}`, { status: 'disabled' });
      expect(disabled.body).toMatchObject({ status: 'disabled' });
      expect((await anon('get', '/api/v1/findings', token)).status).toBe(401);
      await admin.call('patch', `/api/v1/users/${devId}`, { status: 'active', role: 'developer' });
      expect((await anon('get', '/api/v1/findings', token)).status).toBe(200);
    });

    it('can be revoked by its owner or an administrator', async () => {
      const all = (await admin.call('get', '/api/v1/api-tokens')).body as ApiTokenDto[];
      expect(all.find((t) => t.id === tokenId)).toMatchObject({ userName: 'Dev Tok', revokedAt: null });
      expect((await dev.call('get', '/api/v1/api-tokens')).status).toBe(403);
      expect((await admin.call('delete', `/api/v1/api-tokens/${tokenId}`)).status).toBe(200);
      expect((await anon('get', '/api/v1/findings', token)).status).toBe(401);
      expect(((await dev.call('get', '/api/v1/me/tokens')).body as ApiTokenDto[])[0].revokedAt).not.toBeNull();
      const audit = (await admin.call('get', '/api/v1/audit?action=api_token.revoked')).body.items;
      expect(audit[0]).toMatchObject({ actorName: 'admin', targetId: tokenId });
      void bearer;
    });
  });

  describe('dashboards and reports', () => {
    it("serves the dashboard within the caller's scope, and a findings CSV", async () => {
      const d = (await admin.call('get', '/api/v1/dashboard?days=30')).body;
      expect(d).toMatchObject({ days: 30, openTotal: 0, sla: { resolved: 0, compliancePct: null } });
      expect(d.trend).toHaveLength(30);
      expect((await admin.call('get', '/api/v1/dashboard?days=7')).status).toBe(400);
      const team = (await admin.call('post', '/api/v1/teams', { name: 'Reports team' })).body.id;
      // A developer only sees their own teams.
      expect((await dev.call('get', `/api/v1/dashboard?teamId=${team}`)).status).toBe(403);
      expect((await dev.call('get', '/api/v1/dashboard')).status).toBe(200);
      expect((await dev.call('get', `/api/v1/dashboard?repoId=${crypto.randomUUID()}`)).status).toBe(404);
      const csv = await admin.call('get', '/api/v1/reports/findings.csv');
      expect(csv.status).toBe(200);
      expect(csv.headers['content-type']).toMatch(/text\/csv/);
      expect(csv.text.split('\r\n')[0]).toBe('repository,severity,risk_score,status,scanner,rule,title,location,package,version,fixed_version,advisory,cves,kev,epss,first_seen,last_seen,ticket');
      expect((await admin.call('get', '/api/v1/audit?action=report.findings_exported')).body.items).toHaveLength(1);
    });

    it('builds the monthly report notification from the same figures', async () => {
      const msg = await app.get(NotificationsService).monthlyReportMessage({ id: 'r', name: 'All', enabled: true, events: ['monthly_report'], minSeverity: 'low', teamIds: [], channelIds: [], recipients: [], includeRepoRecipients: false, createdAt: new Date(), updatedAt: new Date() });
      expect(msg.title).toMatch(/^Security report — /);
      expect(msg.summary).toContain('0 open finding(s)');
      expect(msg.facts.map((x) => x.name)).toEqual(expect.arrayContaining(['Open critical / high', 'Mean time to fix (critical)', 'Overdue tickets']));
      // Email channels attach the same report as a PDF.
      expect(msg.attachments).toEqual([expect.objectContaining({ filename: expect.stringMatching(/^security-report-\d{4}-\d{2}\.pdf$/), contentType: 'application/pdf' })]);
      expect(msg.attachments![0].content.subarray(0, 8).toString('latin1')).toBe('%PDF-1.4');
    });

    it('downloads the report as a PDF, within the caller\'s scope, and audits it', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/reports/summary.pdf?days=90').set('Cookie', [...admin.cookies].map(([k, v]) => k + '=' + v).join('; ')).buffer(true).parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toMatch(/^attachment; filename="security-report-\d{4}-\d{2}-\d{2}\.pdf"$/);
      expect((res.body as Buffer).subarray(0, 8).toString('latin1')).toBe('%PDF-1.4');
      expect((await admin.call('get', '/api/v1/audit?action=report.pdf_exported')).body.items).toHaveLength(1);
      expect((await dev.call('get', `/api/v1/reports/summary.pdf?teamId=${'0'.repeat(8)}-0000-4000-8000-000000000000`)).status).toBe(403);
    });
  });

  describe('metrics and OpenAPI', () => {
    it('serves Prometheus metrics only with the metrics token', async () => {
      expect((await request(app.getHttpServer()).get('/metrics')).status).toBe(401);
      expect((await request(app.getHttpServer()).get('/metrics').set('Authorization', 'Bearer wrong-token-0123456789')).status).toBe(401);
      const res = await request(app.getHttpServer()).get('/metrics').set('Authorization', `Bearer ${METRICS_TOKEN}`);
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toMatch(/^text\/plain;.*version=0\.0\.4/);
      expect(res.text).toMatch(/^# HELP argus_info /m);
      expect(res.text).toContain(`role="api",database="${h.name}"} 1`);
      expect(res.text).toMatch(/^argus_findings_open\{severity="critical"\} \d+$/m);
      expect(res.text).toMatch(/^argus_users 2$/m);
      expect(res.text).toMatch(/^argus_worker_heartbeat_age_seconds -?\d+$/m);
      // Session cookies do not grant access to metrics.
      expect((await admin.call('get', '/metrics')).status).toBe(401);
    });

    it('describes the API from the running code, with permissions and validation schemas', async () => {
      const res = await request(app.getHttpServer()).get('/api/v1/openapi.json');
      expect(res.status).toBe(200);
      const doc = res.body as { openapi: string; paths: Record<string, Record<string, Record<string, unknown>>> };
      expect(doc.openapi).toBe('3.1.0');
      const createAdvisory = doc.paths['/api/v1/intel/advisories'].post;
      expect(createAdvisory['x-argus-permissions']).toEqual(['intel:manage']);
      const body = (createAdvisory.requestBody as { content: { 'application/json': { schema: { properties: Record<string, unknown>; required: string[] } } } }).content['application/json'].schema;
      expect(body.required).toEqual(expect.arrayContaining(['ecosystem', 'packageName', 'affectedRange']));
      expect(body.properties.ecosystem).toMatchObject({ enum: ['npm', 'nuget', 'pypi', 'maven', 'go', 'cargo'] });
      const listFindings = doc.paths['/api/v1/findings'].get;
      expect((listFindings.parameters as { name: string; in: string }[]).map((p) => p.name)).toEqual(expect.arrayContaining(['page', 'pageSize', 'repoId']));
      expect(doc.paths['/api/v1/tickets/{id}'].get.parameters).toEqual([expect.objectContaining({ name: 'id', in: 'path' })]);
      expect(doc.paths['/api/v1/me/tokens'].post.security).toEqual([{ session: [] }]);
      expect(doc.paths['/healthz'].get.security).toEqual([]);
      expect(Object.keys(doc.paths).length).toBeGreaterThan(60);
    });
  });

  describe('branding and configuration file', () => {
    it('serves branding before sign-in, and only administrators change it', async () => {
      const pub = await request(app.getHttpServer()).get('/api/v1/settings/branding');
      expect(pub.status).toBe(200);
      expect(pub.body).toEqual({ productName: 'Argus', loginNotice: '' });
      expect((await dev.call('put', '/api/v1/settings/branding', { productName: 'X', loginNotice: '' })).status).toBe(403);
      expect((await admin.call('put', '/api/v1/settings/branding', { productName: '<script>', loginNotice: '' })).status).toBe(400);
      const res = await admin.call('put', '/api/v1/settings/branding', { productName: 'Contoso Security', loginNotice: 'Authorised use only.' });
      expect(res.status).toBe(200);
      expect((await request(app.getHttpServer()).get('/api/v1/settings/branding')).body.productName).toBe('Contoso Security');
      // New MFA enrolments use the product name as the authenticator label.
      const enrol = await dev.call('post', '/api/v1/auth/mfa/setup');
      if (enrol.status === 200 || enrol.status === 201) expect(enrol.body.otpauthUrl).toContain('Contoso%20Security');
    });

    it('exports settings without secrets and imports them section by section', async () => {
      expect((await admin.call('post', '/api/v1/intel/sources', { name: 'Vendor advisories', url: 'https://vendor.example.com/advisories.rss', enabled: false })).status).toBe(201);
      expect((await dev.call('get', '/api/v1/settings/export')).status).toBe(403);
      const exp = await admin.call('get', '/api/v1/settings/export');
      expect(exp.status).toBe(200);
      expect(exp.body).toMatchObject({ format: 'argus-settings', version: 1, settings: { branding: { productName: 'Contoso Security' } } });
      expect(Object.keys(exp.body.settings).sort()).toEqual(['branding', 'intel', 'retention', 'scanning', 'security', 'ticketing']);
      // The Entra import secret configured earlier stays out of it.
      expect(JSON.stringify(exp.body)).not.toContain('entra-secret-0001');
      const sources = exp.body.intelSources as { url: string }[];
      expect(sources.length).toBeGreaterThan(0);

      const file = {
        ...exp.body,
        settings: { scanning: { ...exp.body.settings.scanning, eolWarningDays: 99 }, branding: { productName: 'Imported', loginNotice: '' } },
        intelSources: [...sources, { name: 'Imported feed', url: 'https://feeds.example.com/security.xml', enabled: false, intervalMinutes: 60 }],
      };
      const imp = await admin.call('post', '/api/v1/settings/import', file);
      expect(imp.status).toBe(200);
      expect(imp.body).toEqual({ applied: ['scanning', 'branding'], intelSourcesAdded: 1, intelSourcesSkipped: sources.length });
      expect((await admin.call('get', '/api/v1/settings/scanning')).body.eolWarningDays).toBe(99);
      // Sections left out are untouched.
      expect((await admin.call('get', '/api/v1/settings/retention')).body).toEqual(exp.body.settings.retention);
      expect((await admin.call('post', '/api/v1/settings/import', { format: 'something-else', version: 1, settings: {} })).status).toBe(400);
      const audit = await admin.call('get', '/api/v1/audit?action=settings.imported');
      expect(audit.body.items[0].details).toMatchObject({ applied: ['scanning', 'branding'], intelSourcesAdded: 1 });
      await admin.call('put', '/api/v1/settings/branding', { productName: 'Argus', loginNotice: '' });
    });
  });

  describe('saved views', () => {
    it('keeps private views private, lets triagers share, and is not reachable with API tokens', async () => {
      const mine = await dev.call('post', '/api/v1/saved-views', { page: 'tickets', name: 'My overdue', query: 'sla=breached&assignee=me' });
      expect(mine.status).toBe(201);
      expect(mine.body).toMatchObject({ name: 'My overdue', shared: false, mine: true, ownerName: 'Dev Tok' });
      // Developers cannot share; administrators can.
      expect((await dev.call('post', '/api/v1/saved-views', { page: 'tickets', name: 'Team', query: '', shared: true })).status).toBe(403);
      const shared = await admin.call('post', '/api/v1/saved-views', { page: 'tickets', name: 'Critical open', query: 'severity=critical', shared: true });
      expect(shared.status).toBe(201);
      await admin.call('post', '/api/v1/saved-views', { page: 'tickets', name: 'Admin only', query: 'status=all' });
      expect((await admin.call('post', '/api/v1/saved-views', { page: 'tickets', name: 'Bad', query: '?x=1' })).status).toBe(400);

      const devList = (await dev.call('get', '/api/v1/saved-views?page=tickets')).body as { name: string; mine: boolean }[];
      expect(devList.map((v) => [v.name, v.mine])).toEqual([
        ['Critical open', false],
        ['My overdue', true],
      ]);
      expect((await dev.call('get', '/api/v1/saved-views?page=findings')).body).toEqual([]);

      // Someone else's private view looks missing; a shared one needs triage rights to delete.
      expect((await admin.call('delete', `/api/v1/saved-views/${mine.body.id}`)).status).toBe(404);
      expect((await dev.call('delete', `/api/v1/saved-views/${shared.body.id}`)).status).toBe(403);
      expect((await dev.call('delete', `/api/v1/saved-views/${mine.body.id}`)).status).toBe(204);

      const token = (await dev.call('post', '/api/v1/me/tokens', { name: 'views', scopes: ['tickets:read'], expiresInDays: 7 })).body.token as string;
      expect((await anon('get', '/api/v1/saved-views?page=tickets', token)).status).toBe(403);
    });
  });
});
