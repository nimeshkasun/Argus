import { type DiscoveredRepo } from '@argus/data';
import { basicAuth, getJson, normalizeBaseUrl, ProviderError, requestJson, stripUserInfo } from './http';
import { type ConnectionCheck, MAX_PAGES, MAX_PR_FILES, type ProviderClient, type ProviderConnection, type PullRequestComment, type PullRequestInfo } from './types';

interface CloudRepo {
  uuid: string;
  full_name: string;
  name: string;
  is_private: boolean;
  language: string | null;
  description: string | null;
  updated_on: string | null;
  mainbranch?: { name: string } | null;
  links: { html?: { href: string }; clone?: { name: string; href: string }[] };
}

interface CloudPage<T> {
  values: T[];
  next?: string;
  size?: number;
}

/**
 * Bitbucket Cloud. Credentials are either a workspace/repository access token (no username),
 * or an Atlassian API token / app password together with the account email or username.
 */
export class BitbucketCloudClient implements ProviderClient {
  private readonly api = new URL('https://api.bitbucket.org/2.0');
  private readonly name = 'Bitbucket Cloud';

  constructor(private readonly conn: ProviderConnection) {
    if (!conn.scope?.trim()) throw new ProviderError('A Bitbucket Cloud workspace is required.', null, true);
  }

  private authorization(): string {
    return this.conn.username ? basicAuth(this.conn.username, this.conn.token) : `Bearer ${this.conn.token}`;
  }

  private get<T>(url: string) {
    return getJson<T>(url, { headers: { Authorization: this.authorization() }, allowedOrigin: this.api.origin, providerName: this.name });
  }

  private send<T>(url: string, method: 'POST' | 'PUT', body: unknown) {
    return requestJson<T>(url, { method, body, headers: { Authorization: this.authorization() }, allowedOrigin: this.api.origin, providerName: this.name });
  }

  /** API URL of a "workspace/slug" repository. */
  private repoUrl(fullName: string): string {
    const [workspace, slug] = fullName.split('/');
    return `${this.api.toString()}/repositories/${encodeURIComponent(workspace)}/${encodeURIComponent(slug ?? '')}`;
  }

  private reposUrl(pagelen: number): string {
    return `${this.api.toString()}/repositories/${encodeURIComponent(this.conn.scope!.trim())}?pagelen=${pagelen}&sort=full_name`;
  }

  async check(): Promise<ConnectionCheck> {
    const { data } = await this.get<CloudPage<CloudRepo>>(this.reposUrl(10));
    let identity: string | null = null;
    if (this.conn.username) {
      identity = await this.get<{ display_name?: string; username?: string }>(`${this.api.toString()}/user`)
        .then((r) => r.data.username ?? r.data.display_name ?? null)
        .catch(() => this.conn.username);
    }
    return { identity: identity ?? 'access token', visibleRepos: data.size ?? data.values.length };
  }

  async listRepositories(): Promise<DiscoveredRepo[]> {
    let url: string | undefined = this.reposUrl(100);
    const out: DiscoveredRepo[] = [];
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res: { data: CloudPage<CloudRepo> } = await this.get<CloudPage<CloudRepo>>(url);
      for (const r of res.data.values) {
        const clone = r.links.clone?.find((c) => c.name === 'https')?.href;
        if (!clone) continue;
        out.push({
          externalId: r.uuid,
          fullName: r.full_name,
          name: r.name,
          htmlUrl: r.links.html?.href ?? null,
          cloneUrl: stripUserInfo(clone),
          defaultBranch: r.mainbranch?.name ?? null,
          visibility: r.is_private ? 'private' : 'public',
          language: r.language || null,
          description: r.description || null,
          archived: false,
          lastPushedAt: r.updated_on ? new Date(r.updated_on) : null,
        });
      }
      url = res.data.next;
    }
    return out;
  }

  async gitAuthHeader(): Promise<string> {
    const header = this.conn.username ? basicAuth(this.conn.username, this.conn.token) : basicAuth('x-token-auth', this.conn.token);
    return `Authorization: ${header}`;
  }

  allowedCloneHosts(): string[] {
    return ['bitbucket.org'];
  }

  allowsHttpClone(): boolean {
    return false;
  }

  async pullRequest(fullName: string, number: number): Promise<PullRequestInfo> {
    type CloudPull = {
      title: string;
      state: string;
      links: { html?: { href: string } };
      source: { branch: { name: string }; commit: { hash: string } | null; repository: { full_name: string } | null };
      destination: { branch: { name: string } };
    };
    const { data } = await this.get<CloudPull>(`${this.repoUrl(fullName)}/pullrequests/${number}`);
    const from = data.source.repository?.full_name;
    // Bitbucket Cloud has no pull request refs: fetch the source branch, from the fork when the pull request comes from one.
    const fork = from && from.toLowerCase() !== fullName.toLowerCase() ? `https://bitbucket.org/${from}.git` : null;
    return {
      number,
      title: data.title,
      url: data.links.html?.href ?? null,
      state: data.state.toLowerCase(),
      headSha: data.source.commit?.hash ?? null,
      headBranch: data.source.branch.name,
      baseBranch: data.destination.branch.name,
      fetch: { cloneUrl: fork, ref: `refs/heads/${data.source.branch.name}` },
    };
  }

  async pullRequestFiles(fullName: string, number: number): Promise<string[]> {
    let url: string | undefined = `${this.repoUrl(fullName)}/pullrequests/${number}/diffstat?pagelen=500`;
    const out: string[] = [];
    for (let page = 0; url && out.length < MAX_PR_FILES && page < 100; page++) {
      const res: { data: CloudPage<{ status: string; new: { path: string } | null }> } = await this.get<CloudPage<{ status: string; new: { path: string } | null }>>(url);
      for (const f of res.data.values) if (f.status !== 'removed' && f.new?.path) out.push(f.new.path);
      url = res.data.next;
    }
    return out;
  }

  async upsertPullRequestComment(fullName: string, number: number, body: string, existing: string | null): Promise<PullRequestComment> {
    type CloudComment = { id: number; links: { html?: { href: string } } };
    const comments = `${this.repoUrl(fullName)}/pullrequests/${number}/comments`;
    if (existing && /^\d+$/.test(existing)) {
      try {
        const { data } = await this.send<CloudComment>(`${comments}/${existing}`, 'PUT', { content: { raw: body } });
        return { id: String(data.id), url: data.links.html?.href ?? null };
      } catch (err) {
        if (!(err instanceof ProviderError && err.status === 404)) throw err;
      }
    }
    const { data } = await this.send<CloudComment>(comments, 'POST', { content: { raw: body } });
    return { id: String(data.id), url: data.links.html?.href ?? null };
  }
}

interface ServerRepo {
  id: number;
  slug: string;
  name: string;
  description?: string;
  public?: boolean;
  archived?: boolean;
  project: { key: string };
  links: { self?: { href: string }[]; clone?: { name: string; href: string }[] };
}

interface ServerPage<T> {
  values: T[];
  isLastPage: boolean;
  nextPageStart?: number;
  size?: number;
}

/**
 * Bitbucket Data Center / Server, authenticated with an HTTP access token (bearer) or username + token.
 * The scope, when set, is a project key.
 */
export class BitbucketServerClient implements ProviderClient {
  private readonly base: URL;
  private readonly name = 'Bitbucket Data Center';

  constructor(private readonly conn: ProviderConnection) {
    if (!conn.baseUrl) throw new ProviderError('The Bitbucket Data Center server URL is required.', null, true);
    this.base = normalizeBaseUrl(conn.baseUrl);
  }

  private authorization(): string {
    return this.conn.username ? basicAuth(this.conn.username, this.conn.token) : `Bearer ${this.conn.token}`;
  }

  private get<T>(url: string) {
    return getJson<T>(url, { headers: { Authorization: this.authorization() }, allowedOrigin: this.base.origin, providerName: this.name });
  }

  private send<T>(url: string, method: 'POST' | 'PUT', body: unknown) {
    // Bitbucket Data Center refuses state-changing calls without this header (XSRF protection).
    return requestJson<T>(url, { method, body, headers: { Authorization: this.authorization(), 'X-Atlassian-Token': 'no-check' }, allowedOrigin: this.base.origin, providerName: this.name });
  }

  /** REST URL of a "PROJECT/slug" repository. */
  private repoUrl(fullName: string): string {
    const [project, slug] = fullName.split('/');
    return `${this.base.toString().replace(/\/+$/, '')}/rest/api/1.0/projects/${encodeURIComponent(project)}/repos/${encodeURIComponent(slug ?? '')}`;
  }

  private reposUrl(start: number, limit: number): string {
    const root = `${this.base.toString().replace(/\/+$/, '')}/rest/api/1.0`;
    const scope = this.conn.scope?.trim();
    const path = scope ? `/projects/${encodeURIComponent(scope)}/repos` : '/repos';
    return `${root}${path}?limit=${limit}&start=${start}`;
  }

  async check(): Promise<ConnectionCheck> {
    const { data, headers } = await this.get<ServerPage<ServerRepo>>(this.reposUrl(0, 25));
    return { identity: headers.get('x-ausername') ?? this.conn.username ?? null, visibleRepos: data.isLastPage ? data.values.length : (data.size ?? data.values.length) };
  }

  async listRepositories(): Promise<DiscoveredRepo[]> {
    const out: DiscoveredRepo[] = [];
    let start: number | undefined = 0;
    for (let page = 0; start !== undefined && page < MAX_PAGES; page++) {
      const res: { data: ServerPage<ServerRepo> } = await this.get<ServerPage<ServerRepo>>(this.reposUrl(start, 100));
      for (const r of res.data.values) {
        const clone = r.links.clone?.find((c) => c.name === 'http')?.href;
        if (!clone) continue;
        out.push({
          externalId: String(r.id),
          fullName: `${r.project.key}/${r.slug}`,
          name: r.name,
          htmlUrl: r.links.self?.[0]?.href ?? null,
          cloneUrl: stripUserInfo(clone),
          // Resolved at clone time from the remote HEAD (avoids one API call per repository).
          defaultBranch: null,
          visibility: r.public ? 'public' : 'private',
          language: null,
          description: r.description || null,
          archived: r.archived ?? false,
          lastPushedAt: null,
        });
      }
      start = res.data.isLastPage ? undefined : res.data.nextPageStart;
    }
    return out;
  }

  async gitAuthHeader(): Promise<string> {
    return `Authorization: ${this.authorization()}`;
  }

  allowedCloneHosts(): string[] {
    return [this.base.host];
  }

  allowsHttpClone(): boolean {
    return this.base.protocol === 'http:';
  }

  async pullRequest(fullName: string, number: number): Promise<PullRequestInfo> {
    type ServerPull = { title: string; state: string; links?: { self?: { href: string }[] }; fromRef: { displayId: string; latestCommit: string }; toRef: { displayId: string } };
    const { data } = await this.get<ServerPull>(`${this.repoUrl(fullName)}/pull-requests/${number}`);
    // Bitbucket Data Center keeps each pull request's source (also from forks) under refs/pull-requests/<n>/from.
    return {
      number,
      title: data.title,
      url: data.links?.self?.[0]?.href ?? null,
      state: data.state.toLowerCase(),
      headSha: data.fromRef.latestCommit,
      headBranch: data.fromRef.displayId,
      baseBranch: data.toRef.displayId,
      fetch: { cloneUrl: null, ref: `refs/pull-requests/${number}/from` },
    };
  }

  async pullRequestFiles(fullName: string, number: number): Promise<string[]> {
    const out: string[] = [];
    let start: number | undefined = 0;
    for (let page = 0; start !== undefined && out.length < MAX_PR_FILES && page < 100; page++) {
      const res: { data: ServerPage<{ type: string; path: { toString: string } }> } = await this.get<ServerPage<{ type: string; path: { toString: string } }>>(`${this.repoUrl(fullName)}/pull-requests/${number}/changes?limit=1000&start=${start}`);
      for (const c of res.data.values) if (c.type !== 'DELETE') out.push(c.path.toString);
      start = res.data.isLastPage ? undefined : res.data.nextPageStart;
    }
    return out;
  }

  async upsertPullRequestComment(fullName: string, number: number, body: string, existing: string | null): Promise<PullRequestComment> {
    const comments = `${this.repoUrl(fullName)}/pull-requests/${number}/comments`;
    const pr = await this.get<{ links?: { self?: { href: string }[] } }>(`${this.repoUrl(fullName)}/pull-requests/${number}`).catch(() => null);
    const link = (id: number) => (pr?.data.links?.self?.[0]?.href ? `${pr.data.links.self[0].href.replace(/\/overview$/, '')}/overview?commentId=${id}` : null);
    if (existing && /^\d+$/.test(existing)) {
      try {
        // Edits must name the comment's current version.
        const { data: current } = await this.get<{ version: number }>(`${comments}/${existing}`);
        const { data } = await this.send<{ id: number }>(`${comments}/${existing}`, 'PUT', { text: body, version: current.version });
        return { id: String(data.id), url: link(data.id) };
      } catch (err) {
        if (!(err instanceof ProviderError && err.status === 404)) throw err;
      }
    }
    const { data } = await this.send<{ id: number }>(comments, 'POST', { text: body });
    return { id: String(data.id), url: link(data.id) };
  }
}
