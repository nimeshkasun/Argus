import { createHash, createPrivateKey, type KeyObject, sign } from 'node:crypto';
import { type DiscoveredRepo, type Visibility } from '@argus/data';
import { getJson, normalizeBaseUrl, ProviderError, requestJson } from './http';
import { type ConnectionCheck, MAX_PAGES, MAX_PR_FILES, type ProviderClient, type ProviderConnection, type PullRequestComment, type PullRequestInfo } from './types';

interface GhRepo {
  id: number;
  full_name: string;
  name: string;
  owner: { login: string };
  html_url: string;
  clone_url: string;
  default_branch: string | null;
  private: boolean;
  visibility?: string;
  language: string | null;
  description: string | null;
  archived: boolean;
  pushed_at: string | null;
}

const NAME = 'GitHub';
const API_HEADERS = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };

function nextLink(link: string | null): string | null {
  const m = link?.split(',').find((p) => /rel="next"/.test(p));
  return m ? (/<([^>]+)>/.exec(m)?.[1] ?? null) : null;
}

/** Whether a connection authenticates as a GitHub App: the App ID goes in `username`, the private key in `token`. */
export function isGitHubApp(conn: Pick<ProviderConnection, 'provider' | 'username'>): boolean {
  return conn.provider === 'github' && !!conn.username;
}

/**
 * The JSON Web Token a GitHub App signs with its private key to call the App API (RS256, valid for 9 minutes,
 * backdated a minute for clock drift).
 */
export function githubAppJwt(appId: string, privateKeyPem: string, now = Date.now()): string {
  if (!/^\d{1,12}$/.test(appId)) throw new ProviderError('The GitHub App ID must be a number (shown on the app\'s settings page).', null, true);
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw new ProviderError('The GitHub App private key is not valid. Paste the whole .pem file that GitHub generated.', null, true);
  }
  const b64 = (v: object) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const iat = Math.floor(now / 1000) - 60;
  const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({ iat, exp: iat + 9 * 60, iss: appId })}`;
  return `${unsigned}.${sign('RSA-SHA256', Buffer.from(unsigned), key).toString('base64url')}`;
}

/** Installation access tokens (valid for an hour), reused until five minutes before they expire. */
const installationTokens = new Map<string, { token: string; expiresAt: number }>();
const TOKEN_MARGIN_MS = 5 * 60_000;

/**
 * GitHub.com or GitHub Enterprise Server, authenticated with a classic or fine-grained personal access token, or
 * as a GitHub App installation (short-lived tokens minted from the app's private key, repository access chosen
 * when the app is installed).
 */
export class GitHubClient implements ProviderClient {
  private readonly api: URL;
  private readonly webHost: string;
  private readonly app: { id: string; key: string } | null;

  constructor(private readonly conn: ProviderConnection) {
    if (conn.baseUrl) {
      const base = normalizeBaseUrl(conn.baseUrl);
      // Accept either the server root or its /api/v3 endpoint.
      if (!base.pathname.endsWith('/api/v3')) base.pathname = `${base.pathname.replace(/\/+$/, '')}/api/v3`;
      this.api = base;
      this.webHost = base.host;
    } else {
      this.api = new URL('https://api.github.com');
      this.webHost = 'github.com';
    }
    this.app = isGitHubApp(conn) ? { id: conn.username!.trim(), key: conn.token } : null;
  }

  private url(path: string): string {
    return `${this.api.toString().replace(/\/+$/, '')}${path}`;
  }

  private request<T>(url: string, bearer: string, method: 'GET' | 'POST' | 'PATCH' = 'GET', body?: unknown) {
    return requestJson<T>(url, { method, body, headers: { Authorization: `Bearer ${bearer}`, ...API_HEADERS }, allowedOrigin: this.api.origin, providerName: NAME });
  }

  /** "/repos/owner/name" for an "owner/name" full name. */
  private repoPath(fullName: string): string {
    const [owner, name] = fullName.split('/');
    return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name ?? '')}`;
  }

  private async get<T>(url: string) {
    return getJson<T>(url, { headers: { Authorization: `Bearer ${await this.accessToken()}`, ...API_HEADERS }, allowedOrigin: this.api.origin, providerName: NAME });
  }

  /** The personal access token, or a current installation token for a GitHub App. */
  private async accessToken(): Promise<string> {
    if (!this.app) return this.conn.token;
    const scope = this.conn.scope?.trim();
    if (!scope) throw new ProviderError('Enter the organisation or account the GitHub App is installed on.', null, true);
    const cacheKey = [this.api.origin, this.app.id, scope.toLowerCase(), createHash('sha256').update(this.app.key).digest('hex').slice(0, 16)].join('|');
    const cached = installationTokens.get(cacheKey);
    if (cached && cached.expiresAt - TOKEN_MARGIN_MS > Date.now()) return cached.token;

    const jwt = githubAppJwt(this.app.id, this.app.key);
    const installation = await this.installationId(jwt, scope);
    const { data } = await this.request<{ token: string; expires_at: string }>(this.url(`/app/installations/${installation}/access_tokens`), jwt, 'POST');
    installationTokens.set(cacheKey, { token: data.token, expiresAt: Date.parse(data.expires_at) || Date.now() + 50 * 60_000 });
    return data.token;
  }

  private async installationId(jwt: string, scope: string): Promise<number> {
    for (const kind of ['orgs', 'users']) {
      try {
        return (await this.request<{ id: number }>(this.url(`/${kind}/${encodeURIComponent(scope)}/installation`), jwt)).data.id;
      } catch (err) {
        if (!(err instanceof ProviderError && err.status === 404)) throw err;
      }
    }
    throw new ProviderError(`The GitHub App is not installed on ${scope}. Install it on that organisation or account, then try again.`, 404, true);
  }

  async check(): Promise<ConnectionCheck> {
    if (this.app) {
      const { data: app } = await this.request<{ slug: string }>(this.url('/app'), githubAppJwt(this.app.id, this.app.key));
      const { data } = await this.get<{ total_count: number }>(this.url('/installation/repositories?per_page=1'));
      return { identity: `${app.slug} (GitHub App)`, visibleRepos: data.total_count };
    }
    const { data: user } = await this.get<{ login: string }>(this.url('/user'));
    const first = await this.firstPage();
    return { identity: user.login, visibleRepos: first.length };
  }

  private async firstPage(): Promise<GhRepo[]> {
    return (await this.get<GhRepo[]>(await this.listUrl())).data;
  }

  private orgListingMissing = false;

  private async listUrl(): Promise<string> {
    const scope = this.conn.scope?.trim();
    if (!scope || this.orgListingMissing) return this.url('/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=full_name');
    const orgUrl = this.url(`/orgs/${encodeURIComponent(scope)}/repos?per_page=100&type=all&sort=full_name`);
    try {
      await this.get<unknown[]>(orgUrl.replace('per_page=100', 'per_page=1'));
      return orgUrl;
    } catch (err) {
      // The scope may be a user account rather than an organisation.
      if (err instanceof ProviderError && err.status === 404) {
        this.orgListingMissing = true;
        return this.url('/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=full_name');
      }
      throw err;
    }
  }

  async listRepositories(): Promise<DiscoveredRepo[]> {
    if (this.app) return this.listInstallationRepositories();
    const scope = this.conn.scope?.trim().toLowerCase();
    let url: string | null = await this.listUrl();
    const out: DiscoveredRepo[] = [];
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res: { data: GhRepo[]; headers: Headers } = await this.get<GhRepo[]>(url);
      for (const r of res.data) {
        if (this.orgListingMissing && scope && r.owner.login.toLowerCase() !== scope) continue;
        out.push(this.map(r));
      }
      url = nextLink(res.headers.get('link'));
    }
    return out;
  }

  /** The repositories the app installation was granted, whichever way it was installed (all or selected). */
  private async listInstallationRepositories(): Promise<DiscoveredRepo[]> {
    let url: string | null = this.url('/installation/repositories?per_page=100');
    const out: DiscoveredRepo[] = [];
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res: { data: { repositories: GhRepo[] }; headers: Headers } = await this.get<{ repositories: GhRepo[] }>(url);
      out.push(...res.data.repositories.map((r) => this.map(r)));
      url = nextLink(res.headers.get('link'));
    }
    return out;
  }

  private map(r: GhRepo): DiscoveredRepo {
    const visibility: Visibility = r.visibility === 'internal' ? 'internal' : r.private ? 'private' : 'public';
    return {
      externalId: String(r.id),
      fullName: r.full_name,
      name: r.name,
      htmlUrl: r.html_url,
      cloneUrl: r.clone_url,
      defaultBranch: r.default_branch,
      visibility,
      language: r.language,
      description: r.description,
      archived: r.archived,
      lastPushedAt: r.pushed_at ? new Date(r.pushed_at) : null,
    };
  }

  async gitAuthHeader(): Promise<string> {
    return `Authorization: Basic ${Buffer.from(`x-access-token:${await this.accessToken()}`).toString('base64')}`;
  }

  async pullRequest(fullName: string, number: number): Promise<PullRequestInfo> {
    type GhPull = { title: string; html_url: string; state: string; merged_at: string | null; head: { sha: string; ref: string }; base: { ref: string } };
    const { data } = await this.get<GhPull>(this.url(`${this.repoPath(fullName)}/pulls/${number}`));
    // GitHub keeps every pull request's head (also from forks) under refs/pull/<n>/head of the base repository.
    return { number, title: data.title, url: data.html_url, state: data.merged_at ? 'merged' : data.state, headSha: data.head.sha, headBranch: data.head.ref, baseBranch: data.base.ref, fetch: { cloneUrl: null, ref: `refs/pull/${number}/head` } };
  }

  async pullRequestFiles(fullName: string, number: number): Promise<string[]> {
    let url: string | null = this.url(`${this.repoPath(fullName)}/pulls/${number}/files?per_page=100`);
    const out: string[] = [];
    for (let page = 0; url && out.length < MAX_PR_FILES && page < 100; page++) {
      const res: { data: { filename: string; status: string }[]; headers: Headers } = await this.get<{ filename: string; status: string }[]>(url);
      for (const f of res.data) if (f.status !== 'removed') out.push(f.filename);
      url = nextLink(res.headers.get('link'));
    }
    return out;
  }

  async upsertPullRequestComment(fullName: string, number: number, body: string, existing: string | null): Promise<PullRequestComment> {
    const token = await this.accessToken();
    // Pull request conversation comments are issue comments.
    if (existing && /^\d+$/.test(existing)) {
      try {
        const { data } = await this.request<{ id: number; html_url: string }>(this.url(`${this.repoPath(fullName)}/issues/comments/${existing}`), token, 'PATCH', { body });
        return { id: String(data.id), url: data.html_url };
      } catch (err) {
        // Someone deleted it: post a new one.
        if (!(err instanceof ProviderError && err.status === 404)) throw err;
      }
    }
    const { data } = await this.request<{ id: number; html_url: string }>(this.url(`${this.repoPath(fullName)}/issues/${number}/comments`), token, 'POST', { body });
    return { id: String(data.id), url: data.html_url };
  }

  allowedCloneHosts(): string[] {
    return [this.webHost];
  }

  allowsHttpClone(): boolean {
    return this.api.protocol === 'http:';
  }
}
