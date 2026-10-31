import { XMLParser } from 'fast-xml-parser';
import { parse as parseToml } from 'smol-toml';
import { type ParsedDependency } from './types';

// Repository files are untrusted: the DOCTYPE is removed before parsing, so only XML's predefined entities are decoded.
const xml = new XMLParser({
  ignoreAttributes: true,
  parseTagValue: false,
  trimValues: true,
  isArray: (n) => n === 'dependency',
});

type XmlNode = Record<string, unknown>;

function str(v: unknown): string | null {
  if (typeof v === 'string' && v.trim()) return v.trim();
  if (typeof v === 'number') return String(v);
  return null;
}

/** Properties and managed versions a pom passes to the modules below it. */
export interface PomContext {
  properties: Map<string, string>;
  /** "group:artifact" -> version, from dependencyManagement. */
  managed: Map<string, string>;
}

export const emptyPomContext = (): PomContext => ({ properties: new Map(), managed: new Map() });

interface Pom {
  context: PomContext;
  dependencies: { group: string; artifact: string; version: string | null; scope: string | null }[];
}

function readPom(text: string, inherited: PomContext): Pom {
  const doc = xml.parse(text.replace(/<!DOCTYPE(?:[^[>]|\[[\s\S]*?\])*>/gi, '')) as XmlNode;
  const project = (doc.project ?? {}) as XmlNode;
  const properties = new Map(inherited.properties);
  for (const [k, v] of Object.entries((project.properties ?? {}) as XmlNode)) {
    const value = str(v);
    if (value) properties.set(k, value);
  }
  const parent = (project.parent ?? {}) as XmlNode;
  const version = str(project.version) ?? str(parent.version);
  if (version) properties.set('project.version', version);
  const deps = (list: unknown) =>
    (((list ?? {}) as XmlNode).dependency as XmlNode[] | undefined)?.flatMap((d) => {
      const group = str(d.groupId);
      const artifact = str(d.artifactId);
      return group && artifact ? [{ group, artifact, version: str(d.version), scope: str(d.scope) }] : [];
    }) ?? [];
  const resolve = (v: string | null): string | null => {
    let out = v;
    // Properties may refer to other properties; a few rounds cover real projects without looping forever.
    for (let i = 0; out && out.includes('${') && i < 5; i++) out = out.replace(/\$\{([^}]+)\}/g, (m, k: string) => properties.get(k) ?? m);
    return out && !out.includes('${') ? out : null;
  };
  const managed = new Map(inherited.managed);
  for (const d of deps((project.dependencyManagement as XmlNode | undefined)?.dependencies)) {
    const v = resolve(d.version);
    if (v && d.scope !== 'import') managed.set(`${d.group}:${d.artifact}`, v);
  }
  const dependencies = deps(project.dependencies).map((d) => ({ ...d, group: resolve(d.group) ?? d.group, version: resolve(d.version) ?? managed.get(`${d.group}:${d.artifact}`) ?? null }));
  return { context: { properties, managed }, dependencies };
}

/** The context a pom.xml gives to the modules in folders below it. */
export function pomContext(text: string, inherited: PomContext): PomContext {
  return readPom(text, inherited).context;
}

/** "[1.2,2.0)" -> 1.2 (lowest allowed), "1.2.3" -> 1.2.3 (Maven treats a bare version as a soft requirement). */
export function lowestMavenVersion(spec: string): { version: string; pinned: boolean } | null {
  const s = spec.trim();
  if (!/^[[(]/.test(s)) return /^[0-9A-Za-z][0-9A-Za-z.+_-]*$/.test(s) ? { version: s, pinned: true } : null;
  const lower = s.slice(1).split(',')[0].trim();
  return lower ? { version: lower, pinned: s.startsWith('[') && s.endsWith(']') && !s.includes(',') } : null;
}

/**
 * Direct dependencies of a pom.xml. Versions come from the pom, its properties or dependencyManagement here or in a
 * parent folder; dependencies whose version is managed by an external parent or BOM cannot be resolved and are skipped.
 */
export function parsePom(text: string, manifestPath: string, inherited: PomContext = emptyPomContext()): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  for (const d of readPom(text, inherited).dependencies) {
    const v = d.version ? lowestMavenVersion(d.version) : null;
    if (!v) continue;
    out.push({ ecosystem: 'maven', name: `${d.group}:${d.artifact}`, version: v.version, direct: true, dev: d.scope === 'test', license: null, manifestPath, ...(v.pinned ? {} : { unpinned: true }) });
  }
  return out;
}

/** gradle.lockfile: "group:artifact:version=configuration,..." for the full resolved graph. */
export function parseGradleLockfile(text: string, manifestPath: string, direct: Set<string>): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^([^#:\s]+):([^:\s]+):([^=\s]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    const configurations = m[4].split(',').map((c) => c.trim()).filter(Boolean);
    const name = `${m[1]}:${m[2]}`;
    out.push({ ecosystem: 'maven', name, version: m[3], direct: direct.has(name), dev: configurations.length > 0 && configurations.every((c) => /test/i.test(c)), license: null, manifestPath });
  }
  return out;
}

const GRADLE_DEP = /\b([A-Za-z]*(?:[Ii]mplementation|[Aa]pi|[Cc]ompileOnly|[Rr]untimeOnly|[Cc]ompile|[Rr]untime|[Kk]apt|[Aa]nnotationProcessor))\s*\(?\s*["']([^"':\s$]+):([^"':\s$]+):([^"'@:\s$]+)(?::[^"'\s]*)?["']/g;

/** Dependencies with literal "group:artifact:version" coordinates in build.gradle / build.gradle.kts. */
export function parseGradleBuild(text: string, manifestPath: string): ParsedDependency[] {
  const out: ParsedDependency[] = [];
  for (const m of text.replace(/\/\*[\s\S]*?\*\//g, '').matchAll(GRADLE_DEP)) {
    out.push({ ecosystem: 'maven', name: `${m[2]}:${m[3]}`, version: m[4], direct: true, dev: /^test/i.test(m[1]), license: null, manifestPath });
  }
  return out;
}

/** Coordinates in a Gradle build file, also those whose version comes from a catalog or variable ("direct" marking). */
export function gradleCoordinates(text: string): Set<string> {
  return new Set([...text.matchAll(/["']([\w.-]+):([\w.-]+)(?::[^"']*)?["']/g)].map((m) => `${m[1]}:${m[2]}`));
}

/** Gradle version catalog (gradle/libs.versions.toml): [libraries] with literal or [versions] references. */
export function parseVersionCatalog(text: string, manifestPath: string): ParsedDependency[] {
  const doc = parseToml(text) as Record<string, Record<string, unknown> | undefined>;
  const versions = doc.versions ?? {};
  const versionOf = (v: unknown): string | null => {
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (typeof o.ref === 'string') return versionOf(versions[o.ref]);
      if (typeof o.strictly === 'string') return o.strictly;
      if (typeof o.require === 'string') return o.require;
      if (typeof o.prefer === 'string') return o.prefer;
    }
    return null;
  };
  const out: ParsedDependency[] = [];
  for (const lib of Object.values(doc.libraries ?? {})) {
    let name: string | null = null;
    let version: string | null = null;
    if (typeof lib === 'string') {
      const [g, a, v] = lib.split(':');
      if (g && a) [name, version] = [`${g}:${a}`, v ?? null];
    } else if (lib && typeof lib === 'object') {
      const o = lib as Record<string, unknown>;
      name = typeof o.module === 'string' ? o.module : typeof o.group === 'string' && typeof o.name === 'string' ? `${o.group}:${o.name}` : null;
      version = versionOf(o.version);
    }
    const v = version ? lowestMavenVersion(version) : null;
    if (name && v) out.push({ ecosystem: 'maven', name, version: v.version, direct: true, dev: false, license: null, manifestPath, ...(v.pinned ? {} : { unpinned: true }) });
  }
  return out;
}
