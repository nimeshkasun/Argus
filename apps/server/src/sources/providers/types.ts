import { type DiscoveredRepo, type Provider } from '@argus/data';

export interface ProviderConnection {
  provider: Provider;
  baseUrl: string | null;
  scope: string | null;
  username: string | null;
  token: string;
}

export interface ConnectionCheck {
  identity: string | null;
  visibleRepos: number | null;
}

export type WebhookEvent = { kind: 'ping' } | { kind: 'push'; externalId: string; branches: string[] } | { kind: 'ignored'; reason: string };

/** A pull request as its provider reports it; Argus never trusts commits or URLs sent by the caller. */
export interface PullRequestInfo {
  number: number;
  title: string;
  url: string | null;
  /** "open", "merged", "closed" or "declined" (lower case, as the provider names it). */
  state: string;
  headSha: string | null;
  headBranch: string | null;
  baseBranch: string | null;
  /** Where to fetch the pull request's head from: a clone URL (the repository's own when null) and a ref. */
  fetch: { cloneUrl: string | null; ref: string };
}

/** A pull request comment Argus wrote, so later scans update it instead of adding another. */
export interface PullRequestComment {
  id: string;
  url: string | null;
}

export interface ProviderClient {
  /** Verifies the credentials and scope. Throws ProviderError with an actionable message. */
  check(): Promise<ConnectionCheck>;
  listRepositories(): Promise<DiscoveredRepo[]>;
  /**
   * Value for git's http.extraHeader so the token never appears in a URL or command line. Async because some
   * credentials (GitHub App installation tokens) are minted on demand.
   */
  gitAuthHeader(): Promise<string>;
  /** Hosts (host[:port]) that clone URLs may point to; anything else is refused before credentials are sent. */
  allowedCloneHosts(): string[];
  /** Whether plain http clone URLs are acceptable (only for loopback development servers). */
  allowsHttpClone(): boolean;
  pullRequest(fullName: string, number: number): Promise<PullRequestInfo>;
  /** Paths the pull request adds or modifies (not deleted ones), at most a few thousand. */
  pullRequestFiles(fullName: string, number: number): Promise<string[]>;
  /** Posts a comment (Markdown), or replaces the text of `existing` if it still exists. */
  upsertPullRequestComment(fullName: string, number: number, body: string, existing: string | null): Promise<PullRequestComment>;
}

/** Most files of a pull request Argus reads; larger pull requests are scanned as a whole. */
export const MAX_PR_FILES = 5000;

/** Safety limit on pagination (pages of 100): 100k repositories per source. */
export const MAX_PAGES = 1000;
