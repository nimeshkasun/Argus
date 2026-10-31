import { canonicalPackageName } from '@argus/shared';
import { parse as parseToml } from 'smol-toml';
import { type ParsedDependency } from './types';

type TomlTable = Record<string, unknown>;

const table = (v: unknown): TomlTable => (v && typeof v === 'object' && !Array.isArray(v) ? (v as TomlTable) : {});
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const name = (n: string) => canonicalPackageName('pypi', n);

/** Requirement files whose name says they are for development or tests. */
export const isDevRequirements = (path: string) => /(?:^|[/._-])(?:dev|devel|develop|test|tests|testing|lint|docs?|ci)(?:[._-]|\.txt$)/i.test(path.slice(path.lastIndexOf('/') + 1));

const PEP508 = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*\(?\s*([^;()]*)\)?\s*(?:;.*)?$/;

/**
 * One PEP 508 requirement ("requests[socks]>=2.31,<3 ; python_version>'3.8'"). "==" pins the version; a lower bound
 * (">=", "~=", "^" or "~" in Poetry) gives the lowest version allowed, marked unpinned. Anything else is skipped.
 */
export function parseRequirement(spec: string): { name: string; version: string; pinned: boolean } | null {
  const m = PEP508.exec(spec.trim());
  if (!m) return null;
  const clauses = m[2].split(',').map((c) => c.trim()).filter(Boolean);
  for (const c of clauses) {
    const pin = /^===?\s*([^\s*]+)$/.exec(c);
    if (pin) return { name: name(m[1]), version: pin[1], pinned: true };
  }
  for (const c of clauses) {
    const lower = /^(?:>=|~=|\^|~)\s*([0-9][^\s]*)$/.exec(c) ?? /^([0-9][0-9A-Za-z.!+-]*)$/.exec(c);
    if (lower) return { name: name(m[1]), version: lower[1].replace(/\.\*$/, ''), pinned: false };
  }
  return null;
}

/** requirements.txt (pip). Options, includes, editable installs, URLs and local paths are skipped. */
export function parseRequirementsTxt(text: string, manifestPath: string): ParsedDependency[] {
  const dev = isDevRequirements(manifestPath);
  const out: ParsedDependency[] = [];
  for (const raw of text.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
    const line = raw.replace(/(?:^|\s)#.*$/, '').replace(/\s--?[a-z][\w-]*(?:[=\s]\S+)?/gi, '').trim();
    if (!line || line.startsWith('-') || /^[a-z+]+:\/\/|^[./]|\s@\s/i.test(line)) continue;
    const r = parseRequirement(line);
    if (r) out.push({ ecosystem: 'pypi', name: r.name, version: r.version, direct: true, dev, license: null, manifestPath, ...(r.pinned ? {} : { unpinned: true }) });
  }
  return out;
}

export interface PythonRoots {
  prod: Set<string>;
  dev: Set<string>;
}

/** Direct dependencies declared in pyproject.toml (PEP 621, PEP 735 groups, Poetry and uv) or a Pipfile. */
export function pythonRoots(text: string, kind: 'pyproject' | 'pipfile'): PythonRoots {
  const doc = parseToml(text) as TomlTable;
  const prod = new Set<string>();
  const dev = new Set<string>();
  const add = (set: Set<string>, specs: string[]) => specs.forEach((s) => s && PEP508.test(s.trim()) && set.add(name(PEP508.exec(s.trim())![1])));
  const addKeys = (set: Set<string>, t: unknown) => Object.keys(table(t)).forEach((k) => k.toLowerCase() !== 'python' && set.add(name(k)));
  if (kind === 'pipfile') {
    addKeys(prod, doc.packages);
    addKeys(dev, doc['dev-packages']);
    return { prod, dev };
  }
  const project = table(doc.project);
  add(prod, strings(project.dependencies));
  for (const specs of Object.values(table(project['optional-dependencies']))) add(prod, strings(specs));
  for (const specs of Object.values(table(doc['dependency-groups']))) add(dev, strings(specs));
  const poetry = table(table(doc.tool).poetry);
  addKeys(prod, poetry.dependencies);
  addKeys(dev, poetry['dev-dependencies']);
  for (const [group, g] of Object.entries(table(poetry.group))) addKeys(group === 'main' ? prod : dev, table(g).dependencies);
  add(dev, strings(table(table(doc.tool).uv)['dev-dependencies']));
  return { prod, dev };
}

/** Dependencies declared in pyproject.toml, for projects without a lock file. */
export function parsePyprojectDependencies(text: string, manifestPath: string): ParsedDependency[] {
  const doc = parseToml(text) as TomlTable;
  const out: ParsedDependency[] = [];
  const push = (spec: string, dev: boolean) => {
    const r = parseRequirement(spec);
    if (r && r.name !== 'python') out.push({ ecosystem: 'pypi', name: r.name, version: r.version, direct: true, dev, license: null, manifestPath, ...(r.pinned ? {} : { unpinned: true }) });
  };
  const project = table(doc.project);
  strings(project.dependencies).forEach((s) => push(s, false));
  for (const specs of Object.values(table(project['optional-dependencies']))) strings(specs).forEach((s) => push(s, false));
  for (const specs of Object.values(table(doc['dependency-groups']))) strings(specs).forEach((s) => push(s, true));
  // Poetry: name = "^1.2" or { version = "^1.2", ... }.
  const poetry = table(table(doc.tool).poetry);
  const poetryDeps = (t: unknown, dev: boolean) => {
    for (const [n, v] of Object.entries(table(t))) {
      const spec = typeof v === 'string' ? v : typeof table(v).version === 'string' ? (table(v).version as string) : null;
      if (spec) push(`${n}${/^[0-9]/.test(spec) ? `==${spec}` : spec}`, dev);
    }
  };
  poetryDeps(poetry.dependencies, false);
  poetryDeps(poetry['dev-dependencies'], true);
  for (const [group, g] of Object.entries(table(poetry.group))) poetryDeps(table(g).dependencies, group !== 'main');
  return out;
}

const fromRoots = (n: string, roots: PythonRoots | null) => ({
  direct: roots ? roots.prod.has(n) || roots.dev.has(n) : false,
  dev: roots ? roots.dev.has(n) && !roots.prod.has(n) : false,
});

/** poetry.lock and uv.lock: [[package]] tables with name and version. The uv project itself (editable/virtual) is skipped. */
export function parsePythonLock(text: string, manifestPath: string, roots: PythonRoots | null): ParsedDependency[] {
  const doc = parseToml(text) as TomlTable;
  const out: ParsedDependency[] = [];
  for (const p of Array.isArray(doc.package) ? (doc.package as TomlTable[]) : []) {
    const source = table(p.source);
    if (typeof p.name !== 'string' || typeof p.version !== 'string' || source.editable !== undefined || source.virtual !== undefined || source.directory !== undefined) continue;
    const n = name(p.name);
    // Poetry before 1.2 marks development packages with category = "dev".
    const { direct, dev } = fromRoots(n, roots);
    out.push({ ecosystem: 'pypi', name: n, version: p.version, direct, dev: dev || p.category === 'dev', license: null, manifestPath });
  }
  return out;
}

/** Pipfile.lock (pipenv): "default" and "develop" sections, each with every resolved package. */
export function parsePipfileLock(text: string, manifestPath: string, roots: PythonRoots | null): ParsedDependency[] {
  const doc = JSON.parse(text) as Record<string, Record<string, { version?: string }> | undefined>;
  const out: ParsedDependency[] = [];
  for (const [section, devSection] of [['default', false], ['develop', true]] as const) {
    for (const [n, entry] of Object.entries(doc[section] ?? {})) {
      const version = /^===?\s*(.+)$/.exec(entry.version ?? '')?.[1];
      if (!version) continue;
      const pkg = name(n);
      out.push({ ecosystem: 'pypi', name: pkg, version, direct: roots ? roots.prod.has(pkg) || roots.dev.has(pkg) : false, dev: devSection, license: null, manifestPath });
    }
  }
  return out;
}
