import semver from 'semver';
import { type Ecosystem } from '@argus/shared';

/**
 * Normalises a NuGet version (up to four numeric parts, optional prerelease) to an order-preserving semver string.
 * The fourth "revision" part is folded into the patch number, so 1.2.3.4 sorts after 1.2.3 and before 1.2.4.
 * The result is only for comparison, never for display.
 */
function nugetToSemver(v: string): string | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(-[0-9A-Za-z.-]+)?(?:\+.*)?$/.exec(v.trim());
  if (!m) return null;
  const [, a, b = '0', c = '0', d = '0', pre = ''] = m;
  const patch = Number(c) * 100_000 + Number(d);
  return `${Number(a)}.${Number(b)}.${patch}${pre}`;
}

/** Semver-ordered ecosystems: npm (loose), Cargo, Go modules ("v1.2.3", pseudo-versions are prereleases) and NuGet (normalised). */
function toSemver(ecosystem: Ecosystem, v: string): string | null {
  if (ecosystem === 'nuget') return nugetToSemver(v);
  if (ecosystem === 'go' || ecosystem === 'cargo') return semver.valid(v.trim().replace(/^v/, '')) ?? null;
  return semver.valid(v.trim(), { loose: true }) ?? semver.valid(semver.coerce(v)?.version ?? '') ?? null;
}

// ------------------------------------------------------------------ PyPI (PEP 440)

const PEP440 = /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?(?:-(\d+)|[-_.]?(?:post|rev|r)[-_.]?(\d*))?(?:[-_.]?dev[-_.]?(\d*))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;
const PRE_PHASE: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

interface Pep440 {
  /** Sort key: epoch, release, pre, post, dev. */
  key: number[][];
  prerelease: boolean;
}

function parsePep440(v: string): Pep440 | null {
  const m = PEP440.exec(v.trim());
  if (!m) return null;
  const [, epoch = '0', release, prePhase, preN, postImplicit, postN, devN] = m;
  const hasPost = postImplicit !== undefined || postN !== undefined;
  const hasDev = devN !== undefined;
  const parts = release.split('.').map(Number);
  while (parts.length > 1 && parts[parts.length - 1] === 0) parts.pop();
  // 1.0.dev1 < 1.0a1 < 1.0 < 1.0.post1; a dev release of a pre/post release sorts just before it.
  const pre = prePhase ? [PRE_PHASE[prePhase.toLowerCase()], Number(preN || 0)] : hasDev && !hasPost ? [-1] : [3];
  const post = hasPost ? [Number(postImplicit ?? postN ?? 0)] : [-1];
  const dev = hasDev ? [Number(devN || 0)] : [Infinity];
  return { key: [[Number(epoch)], parts, pre, post, dev], prerelease: !!prePhase || hasDev };
}

function compareArrays(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// ------------------------------------------------------------------ Maven

/** Qualifier order of Maven's ComparableVersion; unknown qualifiers sort after these, alphabetically. */
const MAVEN_QUALIFIERS = ['alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp'];
const MAVEN_ALIASES: Record<string, string> = { a: 'alpha', b: 'beta', m: 'milestone', cr: 'rc', ga: '', final: '', release: '' };
const RELEASE_RANK = MAVEN_QUALIFIERS.indexOf('');

type MavenItem = number | string;

function mavenItems(v: string): MavenItem[] | null {
  const s = v.trim().toLowerCase();
  if (!s || !/^[0-9a-z._+-]+$/.test(s)) return null;
  const items: MavenItem[] = [];
  // Split on separators and on digit/letter transitions ("1.0rc1" -> 1, 0, rc, 1).
  for (const token of s.split(/[.\-_+]/).flatMap((t) => t.match(/\d+|[a-z]+/g) ?? [])) {
    if (/^\d+$/.test(token)) items.push(Number(token));
    else items.push(MAVEN_ALIASES[token] ?? token);
  }
  // Trailing zeros and release qualifiers do not change the version: 1.0.0 == 1 == 1-final.
  while (items.length > 1 && (items[items.length - 1] === 0 || items[items.length - 1] === '')) items.pop();
  return items;
}

function qualifierRank(q: string): [number, string] {
  const i = MAVEN_QUALIFIERS.indexOf(q);
  return i >= 0 ? [i, ''] : [MAVEN_QUALIFIERS.length, q];
}

function compareMavenItem(a: MavenItem | undefined, b: MavenItem | undefined): number {
  // A missing item is "0" next to a number, or a release next to a qualifier.
  const x = a ?? (typeof b === 'number' ? 0 : '');
  const y = b ?? (typeof a === 'number' ? 0 : '');
  if (typeof x === 'number' && typeof y === 'number') return Math.sign(x - y);
  // Numbers sort after qualifiers: 1.0.1 > 1.0-rc1 and 1.0.1 > 1.0-sp.
  if (typeof x === 'number') return 1;
  if (typeof y === 'number') return -1;
  const [rx, sx] = qualifierRank(x);
  const [ry, sy] = qualifierRank(y);
  return rx !== ry ? Math.sign(rx - ry) : sx.localeCompare(sy);
}

function compareMaven(a: MavenItem[], b: MavenItem[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const c = compareMavenItem(a[i], b[i]);
    if (c !== 0) return c;
  }
  return 0;
}

// ------------------------------------------------------------------ comparison

/** -1 / 0 / 1, or null if either version cannot be parsed. */
export function compareVersions(ecosystem: Ecosystem, a: string, b: string): number | null {
  if (ecosystem === 'pypi') {
    const x = parsePep440(a);
    const y = parsePep440(b);
    if (!x || !y) return null;
    for (let i = 0; i < x.key.length; i++) {
      const c = compareArrays(x.key[i], y.key[i]);
      if (c !== 0) return c;
    }
    return 0;
  }
  if (ecosystem === 'maven') {
    const x = mavenItems(a);
    const y = mavenItems(b);
    return x && y ? compareMaven(x, y) : null;
  }
  const x = toSemver(ecosystem, a);
  const y = toSemver(ecosystem, b);
  if (!x || !y) return null;
  return semver.compare(x, y, { loose: true });
}

export function isPrerelease(ecosystem: Ecosystem, v: string): boolean {
  if (ecosystem === 'pypi') return parsePep440(v)?.prerelease ?? false;
  if (ecosystem === 'maven') return (mavenItems(v) ?? []).some((i) => typeof i === 'string' && qualifierRank(i)[0] < RELEASE_RANK);
  const n = toSemver(ecosystem, v);
  return !!n && semver.prerelease(n) !== null;
}

/** The lowest candidate strictly greater than `current` (e.g. the nearest fixed version). */
export function lowestAbove(ecosystem: Ecosystem, current: string, candidates: string[]): string | null {
  let best: string | null = null;
  for (const c of candidates) {
    if ((compareVersions(ecosystem, c, current) ?? -1) <= 0) continue;
    if (best === null || (compareVersions(ecosystem, c, best) ?? 1) < 0) best = c;
  }
  return best;
}

/** Highest stable version from a list (registry metadata). */
export function highestStable(ecosystem: Ecosystem, versions: string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (isPrerelease(ecosystem, v)) continue;
    if (best === null || (compareVersions(ecosystem, v, best) ?? -1) > 0) best = v;
  }
  return best;
}

const COMPARATOR = /^(<=|>=|<|>|==?)?\s*(\S+)$/;

/**
 * Comparator ranges ("<2.31.0", ">=1.0 <1.4.2", "<1.0 || >=2.0 <2.1") evaluated with the ecosystem's own version order,
 * for ecosystems whose versions are not semver. Null if the range cannot be parsed.
 */
function comparatorRange(ecosystem: Ecosystem, range: string): ((version: string) => boolean) | null {
  const sets: { op: string; v: string }[][] = [];
  for (const alt of range.split('||')) {
    const parts = alt.trim().replace(/(<=|>=|<|>|==?)\s+/g, '$1').split(/[\s,]+/).filter(Boolean);
    if (!parts.length) return null;
    const set: { op: string; v: string }[] = [];
    for (const p of parts) {
      if (p === '*') continue;
      const m = COMPARATOR.exec(p);
      if (!m || compareVersions(ecosystem, m[2], m[2]) === null) return null;
      set.push({ op: m[1] ?? '=', v: m[2] });
    }
    sets.push(set);
  }
  return (version) =>
    sets.some((set) =>
      set.every(({ op, v }) => {
        const c = compareVersions(ecosystem, version, v);
        if (c === null) return false;
        return op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : c === 0;
      }),
    );
}

/** Whether a version satisfies a range: npm-style for semver ecosystems, comparator ranges for PyPI and Maven. */
export function satisfies(ecosystem: Ecosystem, version: string, range: string): boolean {
  if (ecosystem === 'pypi' || ecosystem === 'maven') {
    const test = comparatorRange(ecosystem, range);
    if (!test) throw new TypeError(`Invalid range: ${range}`);
    return test(version);
  }
  const n = toSemver(ecosystem, version);
  if (!n) return false;
  if (ecosystem !== 'nuget') return semver.satisfies(n, range.replace(/(^|[\s<>=~^])v(?=\d)/g, '$1'), { loose: true, includePrerelease: true });
  // NuGet versions are normalised, so normalise the bounds in simple comparator ranges too.
  const normalizedRange = range.replace(/(\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?)/g, (m) => nugetToSemver(m) ?? m);
  return semver.satisfies(n, normalizedRange, { loose: true, includePrerelease: true });
}

/** Whether a range (as used in Argus advisories) can be parsed for the ecosystem. */
export function isValidRange(ecosystem: Ecosystem, range: string): boolean {
  if (ecosystem === 'pypi' || ecosystem === 'maven') return comparatorRange(ecosystem, range) !== null;
  try {
    return semver.validRange(range, { loose: true }) !== null;
  } catch {
    return false;
  }
}

/** Minimum version satisfying a declared npm range (for manifests without a lockfile). */
export function minVersionOf(range: string): string | null {
  try {
    return semver.minVersion(range)?.version ?? null;
  } catch {
    return null;
  }
}

/** Major version number of a version or range such as "^15.2.0" or ">=18". */
export function majorOf(v: string): number | null {
  const coerced = semver.coerce(v);
  return coerced ? coerced.major : null;
}
