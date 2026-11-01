const REQUEST_TIMEOUT_MS = 30_000;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** A provider API failure with a message that is safe and useful to show to an administrator. */
export class ProviderError extends Error {
  override name = 'ProviderError';

  constructor(
    message: string,
    readonly status: number | null = null,
    /** Auth/permission/not-found problems will not fix themselves on retry. */
    readonly permanent = false,
  ) {
    super(message);
  }
}

/** Source URLs must use HTTPS, except loopback addresses (local development and tests). */
export function normalizeBaseUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new ProviderError('The server URL is not a valid URL.', null, true);
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    throw new ProviderError('The server URL must use https://.', null, true);
  }
  if (url.username || url.password) throw new ProviderError('Do not put credentials in the server URL; use the token field.', null, true);
  url.hash = '';
  url.search = '';
  url.pathname = url.pathname.replace(/\/+$/, '');
  return url;
}

function describeStatus(res: Response, providerName: string): string {
  switch (res.status) {
    case 401:
      return `${providerName} rejected the credentials (401). Check the token and username.`;
    case 403:
      if (res.headers.get('x-ratelimit-remaining') === '0') {
        const reset = Number(res.headers.get('x-ratelimit-reset'));
        return `${providerName} API rate limit exceeded${reset ? `; it resets at ${new Date(reset * 1000).toISOString()}` : ''}.`;
      }
      return `${providerName} denied access (403). The token is missing a required permission.`;
    case 404:
      return `${providerName} returned 404. Check the server URL and the organisation / workspace / project.`;
    case 429:
      return `${providerName} is rate limiting requests (429). Try again later.`;
    default:
      return `${providerName} returned HTTP ${res.status}.`;
  }
}

export interface JsonResponse<T> {
  data: T;
  headers: Headers;
}

/**
 * GET a JSON document. Only follows URLs on the expected origin so credentials can never be sent elsewhere
 * (pagination links come from the remote server).
 */
export function getJson<T>(url: string, opts: { headers: Record<string, string>; allowedOrigin: string; providerName: string }): Promise<JsonResponse<T>> {
  return requestJson<T>(url, opts);
}

/** Like getJson, for calls that are not GETs (minting a GitHub App installation token, pull request comments). */
export async function requestJson<T>(url: string, opts: { method?: 'GET' | 'POST' | 'PUT' | 'PATCH'; body?: unknown; headers: Record<string, string>; allowedOrigin: string; providerName: string }): Promise<JsonResponse<T>> {
  let target = new URL(url);
  let res: Response;
  // Redirects are followed by hand, and only on the same origin, so credentials never go anywhere else
  // (Bitbucket answers some pull request endpoints with a redirect to the repository's equivalent).
  for (let hop = 0; ; hop++) {
    if (target.origin !== opts.allowedOrigin) throw new ProviderError(`Refusing to call ${target.origin}: it is not the configured ${opts.providerName} server.`, null, true);
    try {
      res = await fetch(target, {
        method: opts.method ?? 'GET',
        headers: { Accept: 'application/json', 'User-Agent': 'Argus', ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...opts.headers },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        redirect: 'manual',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (err) {
      const cause = err instanceof Error ? ((err.cause as Error | undefined)?.message ?? err.message) : String(err);
      throw new ProviderError(`Could not reach ${target.host}: ${cause}`);
    }
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) break;
    await res.body?.cancel().catch(() => undefined);
    if (hop >= 3 || (opts.method ?? 'GET') !== 'GET') throw new ProviderError(`${opts.providerName} redirected the request unexpectedly. Check the server URL.`, res.status, true);
    target = new URL(location, target);
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => undefined);
    throw new ProviderError(describeStatus(res, opts.providerName), res.status, [400, 401, 403, 404].includes(res.status) && res.headers.get('x-ratelimit-remaining') !== '0');
  }
  try {
    return { data: (await res.json()) as T, headers: res.headers };
  } catch {
    throw new ProviderError(`${opts.providerName} returned a response that is not JSON. Check the server URL.`, res.status, true);
  }
}

export function basicAuth(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`;
}

/** Removes any user:password@ part that providers embed in clone URLs. */
export function stripUserInfo(raw: string): string {
  const url = new URL(raw);
  url.username = '';
  url.password = '';
  return url.toString();
}
