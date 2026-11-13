import { type PrFindingDto, type PrReviewDto, type PrScanFailOn, type PrScanResult, SCANNER_LABELS, type Severity, SEVERITIES } from '@argus/shared';

/** Comment size limit that every provider accepts (Bitbucket's is the smallest). */
export const MAX_COMMENT_CHARS = 30_000;
const OPEN_DETAILS = 5;
/** Most of the comment the AI code review may take. */
const MAX_REVIEW_CHARS = 12_000;

const SEVERITY_ICON: Record<Severity, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
const label = (s: string) => s[0].toUpperCase() + s.slice(1);

/**
 * Text from the scanned repository or a tool (paths, titles, messages) is untrusted: a pull request from a fork
 * controls it. Escaping keeps it from adding links, images, HTML or headings, and @mentions from notifying anyone.
 */
export function escapeMarkdown(text: string): string {
  return text
    .replace(/[\\`*_{}[\]()#+!]/g, '\\$&')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    // Only real mentions ("@team"), not versions such as "lodash@4.17.21".
    .replace(/(^|[^\w.-])@(?=\w)/g, '$1@\u200b')
    .replace(/\r?\n/g, ' ');
}

/** Inline code that cannot be broken out of. */
function code(text: string): string {
  return `\`${text.replace(/`/g, "'").replace(/\r?\n/g, ' ')}\``;
}

/** A fenced block whose fence is longer than any backtick run inside it. */
function fenced(text: string, language: string | null): string {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = '`'.repeat(longest + 1);
  return `${fence}${language && /^[a-z0-9+#-]{1,20}$/i.test(language) ? language : ''}\n${text.replace(/\r\n/g, '\n').trimEnd()}\n${fence}`;
}

export type CommentProvider = 'github' | 'bitbucket_cloud' | 'bitbucket_server';

/** Link to a line of a file at the scanned commit, on the provider's web UI. */
export function fileLink(provider: CommentProvider, repoUrl: string | null, sha: string | null, path: string, line: number | null): string | null {
  if (!repoUrl || !sha || !/^[0-9a-f]{7,64}$/i.test(sha)) return null;
  const base = repoUrl.replace(/\/+$/, '');
  const p = path.split('/').map(encodeURIComponent).join('/');
  switch (provider) {
    case 'github':
      return `${base}/blob/${sha}/${p}${line ? `#L${line}` : ''}`;
    case 'bitbucket_cloud':
      return `${base}/src/${sha}/${p}${line ? `#lines-${line}` : ''}`;
    case 'bitbucket_server':
      return `${base.replace(/\/browse$/, '')}/browse/${p}?at=${sha}${line ? `#${line}` : ''}`;
  }
}

/** Only http(s) links from tools and advisories are shown. */
const safeUrl = (u: string | null) => (u && /^https?:\/\/[^\s<>()]+$/i.test(u) ? u : null);

export interface CommentContext {
  provider: CommentProvider;
  repoUrl: string | null;
  headSha: string | null;
  failOn: PrScanFailOn;
  /** This scan in Argus, when Argus knows its public address. */
  argusUrl: string | null;
}

const REVIEW_ICON = { issue: '🔴', suggestion: '🟡', nitpick: '⚪' } as const;
const CATEGORY_LABEL = { bug: 'bug', security: 'security', error_handling: 'error handling', performance: 'performance', maintainability: 'maintainability', tests: 'tests', other: 'other' } as const;

/** The AI code review: advisory remarks, clearly labelled, each linked to its line. */
function reviewSection(r: PrReviewDto, ctx: CommentContext, html: boolean): string {
  const lines = r.comments.map((c) => {
    const link = fileLink(ctx.provider, ctx.repoUrl, ctx.headSha, c.path, c.line);
    const where = code(`${c.path}:${c.line}`);
    return `- ${REVIEW_ICON[c.severity]} **${label(c.severity)}** · ${link ? `[${where}](${link})` : where} · ${CATEGORY_LABEL[c.category]}: ${escapeMarkdown(c.comment)}`;
  });
  const skipped = r.filesSkipped ? ` ${r.filesSkipped} file${r.filesSkipped === 1 ? ' was' : 's were'} not reviewed (generated, lock files, binary or too large).` : '';
  const body = [
    `_AI-assisted review by ${escapeMarkdown(r.model)}. It can be wrong: use your judgement. It does not affect the gate._`,
    escapeMarkdown(r.summary),
    lines.length ? lines.join('\n') : 'No remarks.',
    skipped ? `_${skipped.trim()}_` : null,
  ]
    .filter(Boolean)
    .join('\n\n');
  const title = `🤖 AI code review${r.comments.length ? ` (${r.comments.length} remark${r.comments.length === 1 ? '' : 's'})` : ''}`;
  return html ? `<details open>\n<summary><b>${title}</b></summary>\n\n${body}\n\n</details>` : `### ${title}\n${body}`;
}

function findingBlock(f: PrFindingDto, ctx: CommentContext, html: boolean, open: boolean): string {
  const where = f.path ? `${f.path}${f.line ? `:${f.line}` : ''}` : null;
  const link = f.path ? fileLink(ctx.provider, ctx.repoUrl, ctx.headSha, f.path, f.line) : null;
  const location = where ? (link ? `[${code(where)}](${link})` : code(where)) : '';
  const heading = `${SEVERITY_ICON[f.severity]} **${label(f.severity)}** · ${escapeMarkdown(f.title)}`;
  const body: string[] = [];
  const reference = safeUrl(f.url);
  body.push(`${location ? `${location} · ` : ''}${SCANNER_LABELS[f.scanner]} · rule ${code(f.ruleId)} · risk ${f.riskScore}${reference ? ` · [details](${reference})` : ''}`);
  if (f.remediation) body.push(`**How to fix:** ${escapeMarkdown(f.remediation)}`);
  if (f.fixCommand) body.push(fenced(f.fixCommand, 'sh'));
  if (f.ai) {
    body.push(`**Suggested fix** _(AI, ${escapeMarkdown(f.ai.model)} — review before applying)_: ${escapeMarkdown(f.ai.summary)}`);
    if (f.ai.code) body.push(fenced(f.ai.code, f.ai.language));
  }
  if (html) return `<details${open ? ' open' : ''}>\n<summary>${heading}</summary>\n\n${body.join('\n\n')}\n\n</details>`;
  return `#### ${heading}\n${body.join('\n\n')}`;
}

/** The summary comment for a pull request scan. GitHub gets collapsible sections; Bitbucket renders no HTML. */
export function renderPrComment(result: PrScanResult, ctx: CommentContext): string {
  const html = ctx.provider === 'github';
  const total = SEVERITIES.reduce((n, s) => n + result.counts[s], 0);
  const passed = result.gate === 'passed';
  const gate = ctx.failOn === 'never' ? 'report only' : `fails on ${ctx.failOn} or above`;

  const head: string[] = [];
  head.push(`## 🛡️ Argus security scan: ${passed ? '✅ passed' : '❌ failed'}`);
  head.push(
    [
      total ? `**${total} new issue${total === 1 ? '' : 's'}** in this pull request` : '**No new issues** in this pull request',
      `gate: ${gate}`,
      ctx.headSha ? `commit ${code(ctx.headSha.slice(0, 12))}` : null,
      `${result.changedFiles} changed file${result.changedFiles === 1 ? '' : 's'}`,
      ctx.argusUrl ? `[open in Argus](${ctx.argusUrl})` : null,
    ]
      .filter(Boolean)
      .join(' · '),
  );
  if (total) {
    head.push(`| ${SEVERITIES.map((s) => `${SEVERITY_ICON[s]} ${label(s)}`).join(' | ')} |\n|${SEVERITIES.map(() => ':-:').join('|')}|\n| ${SEVERITIES.map((s) => (result.counts[s] ? `**${result.counts[s]}**` : '0')).join(' | ')} |`);
  }

  const tail: string[] = [];
  const notes: string[] = [];
  if (result.existingInChangedFiles) notes.push(`${result.existingInChangedFiles} issue${result.existingInChangedFiles === 1 ? ' that was' : 's that were'} already known in the files you changed ${result.existingInChangedFiles === 1 ? 'is' : 'are'} not counted.`);
  if (result.suppressed) notes.push(`${result.suppressed} new issue${result.suppressed === 1 ? ' is' : 's are'} covered by a suppression.`);
  const degraded = result.scanners.filter((s) => s.status === 'partial' || s.status === 'failed');
  if (degraded.length) notes.push(`Incomplete: ${degraded.map((s) => `${SCANNER_LABELS[s.scanner]} (${s.status}${s.message ? `: ${escapeMarkdown(s.message.slice(0, 120))}` : ''})`).join('; ')}.`);
  if (notes.length) tail.push(notes.map((n) => `> ${n}`).join('\n>\n'));
  tail.push(`${html ? '<sub>' : '_'}Posted by Argus. This comment is updated each time the pull request is scanned.${html ? '</sub>' : '_'}`);

  // The AI review has a bounded size, so it is sized first; findings then fill what is left.
  let reviewText = result.review ? reviewSection(result.review, ctx, html) : null;
  if (reviewText && reviewText.length > MAX_REVIEW_CHARS) reviewText = `${reviewText.slice(0, MAX_REVIEW_CHARS)}\n\n_…review shortened._${html ? '\n\n</details>' : ''}`;

  // Add findings until the comment would be too long; the rest are counted and left to Argus.
  const blocks: string[] = [];
  let length = [...head, ...tail].join('\n\n').length + (reviewText?.length ?? 0) + 200;
  let shown = 0;
  for (const [i, f] of result.findings.entries()) {
    const block = findingBlock(f, ctx, html, i < OPEN_DETAILS);
    if (length + block.length > MAX_COMMENT_CHARS) break;
    blocks.push(block);
    length += block.length + 2;
    shown++;
  }
  const hidden = total - shown;
  const list: string[] = [];
  if (blocks.length) list.push('### New issues', ...blocks);
  if (hidden > 0) list.push(`_…and ${hidden} more${ctx.argusUrl ? ` — [see all in Argus](${ctx.argusUrl})` : ' in Argus'}._`);

  return [...head, ...list, ...(reviewText ? [reviewText] : []), ...tail].join('\n\n');
}
