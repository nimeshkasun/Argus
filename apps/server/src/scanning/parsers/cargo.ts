import { parse as parseToml } from 'smol-toml';
import { minVersionOf } from '../versions';
import { type ParsedDependency } from './types';

type TomlTable = Record<string, unknown>;

const table = (v: unknown): TomlTable => (v && typeof v === 'object' && !Array.isArray(v) ? (v as TomlTable) : {});

export interface CargoRoots {
  prod: Set<string>;
  dev: Set<string>;
}

interface CargoDep {
  /** Crate name on crates.io (a dependency may be renamed with `package = "..."`). */
  crate: string;
  req: string | null;
  /** Path or git dependencies are not crates.io packages. */
  registry: boolean;
  dev: boolean;
}

function cargoDeps(doc: TomlTable): CargoDep[] {
  const out: CargoDep[] = [];
  const read = (t: unknown, dev: boolean) => {
    for (const [key, v] of Object.entries(table(t))) {
      const o = table(v);
      const req = typeof v === 'string' ? v : typeof o.version === 'string' ? o.version : null;
      const crate = typeof o.package === 'string' ? o.package : key;
      out.push({ crate, req, registry: o.path === undefined && o.git === undefined && o.workspace === undefined, dev });
    }
  };
  const sections = (t: TomlTable) => {
    read(t.dependencies, false);
    read(t['build-dependencies'], false);
    read(t['dev-dependencies'], true);
  };
  sections(doc);
  for (const target of Object.values(table(doc.target))) sections(table(target));
  read(table(doc.workspace).dependencies, false);
  return out;
}

/** Direct dependency names declared in a Cargo.toml (crate, workspace member or workspace root). */
export function cargoRoots(text: string, into: CargoRoots = { prod: new Set(), dev: new Set() }): CargoRoots {
  for (const d of cargoDeps(parseToml(text) as TomlTable)) (d.dev ? into.dev : into.prod).add(d.crate);
  return into;
}

/** Cargo.lock: every resolved crate. Workspace members and path dependencies (no source) are skipped. */
export function parseCargoLock(text: string, manifestPath: string, roots: CargoRoots | null): ParsedDependency[] {
  const doc = parseToml(text) as TomlTable;
  const out: ParsedDependency[] = [];
  for (const p of Array.isArray(doc.package) ? (doc.package as TomlTable[]) : []) {
    if (typeof p.name !== 'string' || typeof p.version !== 'string' || typeof p.source !== 'string') continue;
    const direct = roots ? roots.prod.has(p.name) || roots.dev.has(p.name) : false;
    out.push({ ecosystem: 'cargo', name: p.name, version: p.version, direct, dev: !!roots && roots.dev.has(p.name) && !roots.prod.has(p.name), license: null, manifestPath });
  }
  return out;
}

/** Cargo.toml without a lock file: the lowest version each requirement allows ("1.2" means ^1.2). */
export function parseCargoToml(text: string, manifestPath: string): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  for (const d of cargoDeps(parseToml(text) as TomlTable)) {
    if (!d.registry || !d.req) continue;
    // Cargo requirements without an operator are caret requirements; npm semver understands the rest.
    const version = minVersionOf(/^[0-9]/.test(d.req.trim()) ? `^${d.req.trim()}` : d.req);
    if (version) out.push({ ecosystem: 'cargo', name: d.crate, version, direct: true, dev: d.dev, license: null, manifestPath, unpinned: true });
  }
  return out;
}
