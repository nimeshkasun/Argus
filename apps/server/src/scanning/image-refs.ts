import { parseAllDocuments } from 'yaml';
import { type RepoFile } from './types';

/** A container image referenced by a repository file. */
export interface ImageRef {
  image: string;
  path: string;
  line: number | null;
}

const DOCKERFILE = /(?:^|\/)(?:Dockerfile|Containerfile)(?:[.-][^/]*)?$|\.dockerfile$/i;
const COMPOSE = /(?:^|\/)(?:docker-)?compose(?:[.-][^/]*)?\.ya?ml$/i;
const YAML = /\.ya?ml$/i;
/** CI definitions also have "image:" keys, but they name build tools rather than what is deployed. */
const NOT_MANIFESTS = /(?:^|\/)(?:\.github|\.gitlab-ci|\.circleci|\.azure-pipelines|\.buildkite)(?:\/|\.ya?ml$)|(?:^|\/)(?:azure-pipelines|bitbucket-pipelines|\.gitlab-ci)\.ya?ml$/i;

/** A plausible image reference: registry/name[:tag][@digest], no variables or template syntax left. */
const IMAGE = /^[a-z0-9][a-z0-9._\-/:]*(?:@sha256:[a-f0-9]{64})?$/i;

const lineOf = (text: string, needle: string): number | null => {
  const i = text.indexOf(needle);
  return i < 0 ? null : text.slice(0, i).split('\n').length;
};

/** Expands ${VAR}, $VAR and ${VAR:-default}; null if a variable has no value. */
function expand(value: string, vars: Map<string, string>): string | null {
  let unresolved = false;
  const out = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (_m, braced: string | undefined, fallback: string | undefined, bare: string | undefined) => {
    const v = vars.get((braced ?? bare)!) ?? fallback;
    if (v === undefined || v === '') unresolved = true;
    return v ?? '';
  });
  return unresolved ? null : out;
}

/** Base images of a Dockerfile (every FROM that is not an earlier build stage or "scratch"). Global ARG defaults are applied. */
export function dockerfileImages(text: string, path: string): ImageRef[] {
  const args = new Map<string, string>();
  const stages = new Set<string>();
  const out: ImageRef[] = [];
  const lines = text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  let seenFrom = false;
  for (const raw of lines) {
    const line = raw.trim();
    const arg = /^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(?:"([^"]*)"|'([^']*)'|(\S*)))?/i.exec(line);
    if (arg && !seenFrom) {
      const value = arg[2] ?? arg[3] ?? arg[4];
      if (value) args.set(arg[1], value);
      continue;
    }
    const from = /^FROM\s+(.*)$/i.exec(line);
    if (!from) continue;
    seenFrom = true;
    const tokens = from[1].split(/\s+/).filter((t) => !t.startsWith('--'));
    const [ref, as, alias] = tokens;
    const image = ref ? expand(ref, args) : null;
    // Only earlier stages can be named in FROM, so this line's own alias is registered after the check.
    if (image && image.toLowerCase() !== 'scratch' && !stages.has(image.toLowerCase()) && IMAGE.test(image)) out.push({ image, path, line: lineOf(text, raw) });
    if (as?.toLowerCase() === 'as' && alias) stages.add(alias.toLowerCase());
  }
  return out;
}

type YamlNode = Record<string, unknown>;

/** `image:` of Compose services; ${VAR:-default} uses the default, and an unset variable skips the service. */
export function composeImages(text: string, path: string): ImageRef[] {
  const out: ImageRef[] = [];
  for (const doc of parseAllDocuments(text)) {
    if (doc.errors.length) continue;
    const services = ((doc.toJS({ maxAliasCount: 50 }) ?? {}) as YamlNode).services as YamlNode | undefined;
    for (const svc of Object.values(services ?? {})) {
      const raw = (svc as YamlNode | null)?.image;
      if (typeof raw !== 'string') continue;
      const image = expand(raw, new Map());
      if (image && IMAGE.test(image)) out.push({ image, path, line: lineOf(text, raw) });
    }
  }
  return out;
}

/** Container images in Kubernetes manifests (pods, deployments, jobs, ...): every containers / initContainers entry. */
export function manifestImages(text: string, path: string): ImageRef[] {
  const out: ImageRef[] = [];
  const walk = (node: unknown, depth: number) => {
    if (depth > 30 || !node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach((n) => walk(n, depth + 1));
      return;
    }
    for (const [key, value] of Object.entries(node as YamlNode)) {
      if ((key === 'containers' || key === 'initContainers' || key === 'ephemeralContainers') && Array.isArray(value)) {
        for (const c of value) {
          const image = (c as YamlNode | null)?.image;
          if (typeof image === 'string' && IMAGE.test(image)) out.push({ image, path, line: lineOf(text, image) });
        }
      } else walk(value, depth + 1);
    }
  };
  // Helm templates are not YAML until rendered; their image values are template expressions anyway.
  if (text.includes('{{')) return out;
  for (const doc of parseAllDocuments(text)) {
    if (doc.errors.length) continue;
    const value = doc.toJS({ maxAliasCount: 50 }) as YamlNode | null;
    if (value && typeof value === 'object' && 'kind' in value && 'apiVersion' in value) walk(value, 0);
  }
  return out;
}

/**
 * Images referenced anywhere in the repository, first reference first. The order is stable (by file path), so the
 * same images are chosen each scan when there are more than can be scanned.
 */
export async function collectImageRefs(files: RepoFile[], readText: (f: RepoFile) => Promise<string | null>): Promise<{ refs: ImageRef[]; errors: string[] }> {
  const byImage = new Map<string, ImageRef>();
  const errors: string[] = [];
  for (const f of [...files].sort((a, b) => a.path.localeCompare(b.path))) {
    const kind = DOCKERFILE.test(f.path) ? 'dockerfile' : COMPOSE.test(f.path) ? 'compose' : YAML.test(f.path) && !NOT_MANIFESTS.test(f.path) ? 'manifest' : null;
    if (!kind || f.size > 1024 * 1024) continue;
    const text = await readText(f);
    if (!text) continue;
    try {
      const refs = kind === 'dockerfile' ? dockerfileImages(text, f.path) : kind === 'compose' ? composeImages(text, f.path) : manifestImages(text, f.path);
      for (const r of refs) if (!byImage.has(r.image.toLowerCase())) byImage.set(r.image.toLowerCase(), r);
    } catch (err) {
      errors.push(`${f.path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { refs: [...byImage.values()], errors };
}
