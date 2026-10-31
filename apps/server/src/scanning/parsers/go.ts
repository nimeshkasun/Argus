import { type ParsedDependency } from './types';

/**
 * go.mod: every module in the build list (Go 1.17+ lists indirect ones too, marked "// indirect").
 * replace directives are applied; modules replaced by a local folder are skipped.
 */
export function parseGoMod(text: string, manifestPath: string): ParsedDependency[] {
  const requires: { path: string; version: string; indirect: boolean }[] = [];
  const replaces = new Map<string, { path: string; version: string } | null>();
  // Blocks Argus does not read (exclude, retract, tool, ...) are skipped up to their closing parenthesis.
  let block: 'require' | 'replace' | 'skip' | null = null;
  for (const raw of text.split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(raw);
    let line = raw.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (block && line === ')') {
      block = null;
      continue;
    }
    const opener = /^(require|replace|exclude|retract|tool|godebug|ignore)\s*\($/.exec(line);
    if (opener) {
      block = opener[1] === 'require' || opener[1] === 'replace' ? opener[1] : 'skip';
      continue;
    }
    let kind: string | null = block;
    const single = /^(require|replace)\s+(.*)$/.exec(line);
    if (!block && single) {
      kind = single[1];
      line = single[2];
    }
    if (kind === 'require') {
      const m = /^(\S+)\s+(v\S+)$/.exec(line);
      if (m) requires.push({ path: m[1].replace(/^"|"$/g, ''), version: m[2], indirect });
    } else if (kind === 'replace') {
      const m = /^(\S+)(?:\s+v\S+)?\s*=>\s*(\S+)(?:\s+(v\S+))?$/.exec(line);
      if (m) replaces.set(m[1], m[3] ? { path: m[2], version: m[3] } : null);
    }
  }
  const out: ParsedDependency[] = [];
  for (const r of requires) {
    const replaced = replaces.has(r.path) ? replaces.get(r.path) : { path: r.path, version: r.version };
    if (!replaced) continue;
    out.push({ ecosystem: 'go', name: replaced.path, version: replaced.version, direct: !r.indirect, dev: false, license: null, manifestPath });
  }
  return out;
}
