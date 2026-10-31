import { opendir, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { type ScanStatsRecord } from '@argus/data';
import { type RepoFile } from '../scanning/types';

/** Files that identify an ecosystem the scanners understand. Matched against the file name. */
const MANIFESTS: [RegExp, string][] = [
  [/^package\.json$/, 'npm'],
  [/^package-lock\.json$/, 'npm'],
  [/^npm-shrinkwrap\.json$/, 'npm'],
  [/^yarn\.lock$/, 'npm'],
  [/^pnpm-lock\.yaml$/, 'npm'],
  [/\.(cs|fs|vb)proj$/i, 'nuget'],
  [/^packages\.config$/i, 'nuget'],
  [/^Directory\.Packages\.props$/i, 'nuget'],
  [/^packages\.lock\.json$/i, 'nuget'],
  [/^(?:pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|requirements[^/]*\.txt)$/i, 'pypi'],
  [/^(?:pom\.xml|build\.gradle(?:\.kts)?|gradle\.lockfile|[^/]*\.versions\.toml)$/i, 'maven'],
  [/^go\.mod$/, 'go'],
  [/^Cargo\.(?:toml|lock)$/, 'cargo'],
  [/^global\.json$/i, 'dotnet'],
  [/^\.nvmrc$|^\.node-version$/, 'node'],
  [/^Dockerfile$|\.dockerfile$/i, 'docker'],
  [/\.(pem|crt|cer|der|pfx|p12)$/i, 'certificates'],
];

/** Directories that are vendored or generated; never descended into. */
const SKIP_DIRS = new Set(['.git', 'node_modules', 'bower_components', '.yarn', 'bin', 'obj', 'dist', '.next', 'vendor']);
const MAX_FILES = 500_000;

/** Whether a repository-relative path is inside a vendored or generated folder. */
export function isVendoredPath(path: string): boolean {
  return path.split('/').slice(0, -1).some((d) => SKIP_DIRS.has(d));
}
const MAX_MANIFESTS = 1_000;

/**
 * Lists the files of a checked-out repository, skipping vendored/generated folders.
 * Symbolic links are never followed (and are checked out as plain files anyway).
 */
export async function walkFiles(root: string): Promise<RepoFile[]> {
  const out: RepoFile[] = [];
  const stack = [root];
  while (stack.length && out.length < MAX_FILES) {
    const dir = stack.pop()!;
    for await (const entry of await opendir(dir)) {
      const abs = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(abs);
      } else if (entry.isFile()) {
        out.push({ path: relative(root, abs).split(sep).join('/'), abs, size: (await stat(abs)).size });
      }
    }
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** Size and ecosystems of a repository, from its file list. */
export function inventory(files: RepoFile[]): ScanStatsRecord {
  const ecosystems = new Set<string>();
  const manifests: string[] = [];
  let bytes = 0;
  for (const f of files) {
    bytes += f.size;
    const name = f.path.slice(f.path.lastIndexOf('/') + 1);
    const match = MANIFESTS.find(([re]) => re.test(name));
    if (match) {
      ecosystems.add(match[1]);
      if (manifests.length < MAX_MANIFESTS) manifests.push(f.path);
    }
  }
  return { files: files.length, bytes, ecosystems: [...ecosystems].sort(), manifests: manifests.sort() };
}
