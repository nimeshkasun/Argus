/**
 * The repository's docs/ folder, bundled into the web app at build time, so the documentation always matches the
 * running version and works without internet access.
 */
const files = import.meta.glob('../../../../docs/**/*.md', { query: '?raw', import: 'default', eager: true }) as Record<string, string>;

export interface DocPage {
  /** Route below /docs: "" for docs/README.md, "features/user-management" for docs/features/user-management.md. */
  slug: string;
  /** Path inside docs/, e.g. "features/user-management.md". */
  file: string;
  title: string;
  markdown: string;
}

const pages: DocPage[] = Object.entries(files).map(([path, markdown]) => {
  const file = path.replace(/^.*?\/docs\//, '');
  const slug = file.replace(/\.md$/, '').replace(/(^|\/)README$/, '');
  const title = /^#\s+(.+)$/m.exec(markdown)?.[1].trim() ?? slug;
  return { slug, file, title, markdown };
});
const bySlug = new Map(pages.map((p) => [p.slug, p]));

export const getDoc = (slug: string) => bySlug.get(slug.replace(/\/+$/, ''));

/** Sidebar sections, in reading order. Pages not listed here are added to "More" so nothing is hidden. */
const SECTIONS: { title: string; slugs: string[] }[] = [
  { title: 'Getting started', slugs: ['', 'configuration'] },
  {
    title: 'Features',
    slugs: [
      'features',
      'features/user-management',
      'features/sources-and-repositories',
      'features/scanners-and-findings',
      'features/pull-request-scans',
      'features/tickets-and-notifications',
      'features/ai-assistance',
      'features/threat-intelligence',
      'features/dashboards-and-reports',
      'features/api-and-automation',
    ],
  },
  { title: 'Deployment', slugs: ['deployment/docker', 'deployment/azure', 'deployment/windows'] },
  { title: 'Security', slugs: ['security', 'asvs-checklist'] },
  { title: 'Reference', slugs: ['architecture', 'development'] },
];

/** Short sidebar labels where the page title is long or generic. */
const NAV_LABELS: Record<string, string> = { '': 'Overview', features: 'Feature overview' };

export interface NavSection {
  title: string;
  items: { slug: string; label: string }[];
}

export function docsNav(): NavSection[] {
  const listed = new Set(SECTIONS.flatMap((s) => s.slugs));
  const sections = SECTIONS.map((s) => ({
    title: s.title,
    items: s.slugs.filter((slug) => bySlug.has(slug)).map((slug) => ({ slug, label: NAV_LABELS[slug] ?? bySlug.get(slug)!.title })),
  }));
  const rest = pages.filter((p) => !listed.has(p.slug)).sort((a, b) => a.title.localeCompare(b.title));
  if (rest.length) sections.push({ title: 'More', items: rest.map((p) => ({ slug: p.slug, label: p.title })) });
  return sections.filter((s) => s.items.length);
}

/** GitHub-style heading anchors, so links such as user-management.md#invite-links land on the heading. */
export function slugify(text: string): string {
  return text
    .toLowerCase()
    .trim()
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .replace(/\s/g, '-');
}

export type ResolvedLink = { kind: 'external'; href: string } | { kind: 'doc'; to: string } | { kind: 'anchor'; hash: string } | { kind: 'none' };

/**
 * Turns a link inside a doc into an app route. Links to other docs become /docs routes; links to source files outside
 * docs/ (which the app does not serve) resolve to "none" and are shown as plain text.
 */
export function resolveLink(fromFile: string, href: string): ResolvedLink {
  if (/^(https?:|mailto:)/i.test(href)) return { kind: 'external', href };
  const [rawPath, hash = ''] = href.split('#');
  if (!rawPath) return { kind: 'anchor', hash };
  const parts = fromFile.split('/').slice(0, -1);
  for (const seg of rawPath.split('/')) {
    if (seg === '..') parts.pop();
    else if (seg && seg !== '.') parts.push(seg);
  }
  let target = parts.join('/');
  if (rawPath.endsWith('/')) target = `${target}/README.md`.replace(/^\//, '');
  if (!target.endsWith('.md')) return { kind: 'none' };
  const slug = target.replace(/\.md$/, '').replace(/(^|\/)README$/, '');
  if (!bySlug.has(slug)) return { kind: 'none' };
  return { kind: 'doc', to: `/docs${slug ? `/${slug}` : ''}${hash ? `#${hash}` : ''}` };
}

/** Plain text of a page, for search: no markup, links reduced to their text. */
const plain = (md: string) =>
  md
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[#>*_`|]/g, ' ')
    .replace(/-{3,}/g, ' ')
    .replace(/\s+/g, ' ');

const index = pages.map((p) => ({ ...p, text: plain(p.markdown) }));

export interface SearchHit {
  slug: string;
  title: string;
  snippet: string;
}

/** Pages whose title or text contains every word of the query; title matches first. */
export function searchDocs(query: string, limit = 12): SearchHit[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return [];
  const hits = index
    .map((p) => {
      const title = p.title.toLowerCase();
      const text = p.text.toLowerCase();
      if (!words.every((w) => title.includes(w) || text.includes(w))) return null;
      const at = Math.max(0, text.indexOf(words[0]));
      const start = Math.max(0, at - 60);
      const snippet = `${start ? '…' : ''}${p.text.slice(start, at + 120).trim()}…`;
      return { slug: p.slug, title: p.title, snippet, score: words.filter((w) => title.includes(w)).length };
    })
    .filter((h): h is SearchHit & { score: number } => !!h)
    .sort((a, b) => b.score - a.score || a.title.localeCompare(b.title));
  return hits.slice(0, limit).map(({ score: _score, ...h }) => h);
}
