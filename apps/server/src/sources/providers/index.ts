import { createHmac, timingSafeEqual } from 'node:crypto';
import { type Provider } from '@argus/data';
import { BitbucketCloudClient, BitbucketServerClient } from './bitbucket';
import { GitHubClient } from './github';
import { ProviderError } from './http';
import { type ProviderClient, type ProviderConnection, type WebhookEvent } from './types';

export { ProviderError } from './http';
export type { ConnectionCheck, ProviderClient, ProviderConnection, PullRequestComment, PullRequestInfo, WebhookEvent } from './types';
export { MAX_PR_FILES } from './types';

export function createProviderClient(conn: ProviderConnection): ProviderClient {
  switch (conn.provider) {
    case 'github':
      return new GitHubClient(conn);
    case 'bitbucket_cloud':
      return new BitbucketCloudClient(conn);
    case 'bitbucket_server':
      return new BitbucketServerClient(conn);
  }
}

/** Validates a clone URL against the provider's hosts before any credential is attached to it. */
export function assertCloneUrlAllowed(client: ProviderClient, cloneUrl: string): URL {
  let url: URL;
  try {
    url = new URL(cloneUrl);
  } catch {
    throw new ProviderError('The repository clone URL is not valid.', null, true);
  }
  const protocolOk = url.protocol === 'https:' || (url.protocol === 'http:' && client.allowsHttpClone());
  const hostOk = client.allowedCloneHosts().some((h) => h.toLowerCase() === url.host.toLowerCase());
  if (!protocolOk || !hostOk) {
    throw new ProviderError(`Refusing to clone from ${url.protocol}//${url.host}: only ${client.allowedCloneHosts().join(', ')} over HTTPS is allowed for this source.`, null, true);
  }
  url.username = '';
  url.password = '';
  return url;
}

/** Verifies an `sha256=<hex>` HMAC signature (GitHub X-Hub-Signature-256, Bitbucket X-Hub-Signature). */
export function verifyWebhookSignature(secret: string, rawBody: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  const [algo, sig] = header.split('=', 2);
  if (algo !== 'sha256' || !sig || !/^[0-9a-f]{64}$/i.test(sig)) return false;
  const expected = createHmac('sha256', secret).update(rawBody).digest();
  return timingSafeEqual(expected, Buffer.from(sig, 'hex'));
}

type Headers = Record<string, string | string[] | undefined>;
const header = (h: Headers, name: string) => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

/** Normalises push notifications from each provider. */
export function parseWebhook(provider: Provider, headers: Headers, body: Json): WebhookEvent {
  if (provider === 'github') {
    const event = header(headers, 'x-github-event');
    if (event === 'ping') return { kind: 'ping' };
    if (event !== 'push') return { kind: 'ignored', reason: `event ${event ?? 'unknown'}` };
    if (body?.deleted) return { kind: 'ignored', reason: 'branch deleted' };
    const ref: string = body?.ref ?? '';
    if (!ref.startsWith('refs/heads/') || body?.repository?.id === undefined) return { kind: 'ignored', reason: 'not a branch push' };
    return { kind: 'push', externalId: String(body.repository.id), branches: [ref.slice('refs/heads/'.length)] };
  }

  const event = header(headers, 'x-event-key');
  if (event === 'diagnostics:ping') return { kind: 'ping' };

  if (provider === 'bitbucket_cloud') {
    if (event !== 'repo:push') return { kind: 'ignored', reason: `event ${event ?? 'unknown'}` };
    const branches = ((body?.push?.changes ?? []) as Json[]).filter((c) => c?.new?.type === 'branch' && c.new.name).map((c) => String(c.new.name));
    if (!body?.repository?.uuid || !branches.length) return { kind: 'ignored', reason: 'no branch updates' };
    return { kind: 'push', externalId: String(body.repository.uuid), branches };
  }

  if (event !== 'repo:refs_changed') return { kind: 'ignored', reason: `event ${event ?? 'unknown'}` };
  const branches = ((body?.changes ?? []) as Json[]).filter((c) => c?.ref?.type === 'BRANCH' && c.type !== 'DELETE').map((c) => String(c.ref.displayId));
  if (body?.repository?.id === undefined || !branches.length) return { kind: 'ignored', reason: 'no branch updates' };
  return { kind: 'push', externalId: String(body.repository.id), branches };
}
