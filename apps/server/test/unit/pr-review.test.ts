import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { type Repository } from '@argus/data';
import { type PrReviewOutput, type PrScanResult } from '@argus/shared';
import { afterAll, describe, expect, it } from 'vitest';
import { type AiService } from '../../src/ai/ai.service';
import { renderPrComment } from '../../src/pr-scans/pr-comment';
import { collectDiff, isReviewable, parseDiff, reviewPullRequest } from '../../src/pr-scans/pr-review';

const DIFF = [
  'diff --git a/src/cart.js b/src/cart.js',
  'index 1111111..2222222 100644',
  '--- a/src/cart.js',
  '+++ b/src/cart.js',
  '@@ -10,4 +10,5 @@ function total(items) {',
  '   let sum = 0;',
  '-  for (const i of items) sum += i.price;',
  '+  for (const i of items) sum += i.price * i.qty;',
  '+  if (sum < 0) return;',
  '   return sum;',
  ' }',
  '@@ -40,2 +41,3 @@',
  ' module.exports = {',
  '+  total,',
  ' };',
  'diff --git a/package-lock.json b/package-lock.json',
  '--- a/package-lock.json',
  '+++ b/package-lock.json',
  '@@ -1,1 +1,1 @@',
  '-{"a":1}',
  '+{"a":2}',
  'diff --git a/logo.png b/logo.png',
  'Binary files a/logo.png and b/logo.png differ',
  'diff --git a/old.js b/old.js',
  'deleted file mode 100644',
  '--- a/old.js',
  '+++ /dev/null',
  '@@ -1,1 +0,0 @@',
  '-gone',
].join('\n');

/** An AiService that answers with a fixed review and records the prompt it was given. */
function stubAi(output: PrReviewOutput, opts: { enabled?: boolean; limit?: number } = {}) {
  const prompts: string[] = [];
  const ai = {
    canRun: async () => opts.enabled ?? true,
    contextLimit: async () => opts.limit ?? 12_000,
    run: async (req: { prompt: string; useCase: string }) => {
      prompts.push(req.prompt);
      return { output, provider: 'relay', model: 'openai/gpt-6.1-sol', redactions: 0 };
    },
  } as unknown as AiService;
  return { ai, prompts };
}

const repo = { id: 'r1', fullName: 'acme/shop', aiEnabled: true } as Repository;
const input = (ai: AiService) => ({ ai, repo, title: 'Add quantities', diff: DIFF, known: ['src/cart.js:3 Hard-coded secret'], knownSecrets: [], subjectId: 'r1#7' });

describe('pull request diff', () => {
  it('numbers the new lines, drops removed ones and skips lock files, binaries and deletions', () => {
    const { files, skipped } = parseDiff(DIFF);
    expect(files.map((f) => f.path)).toEqual(['src/cart.js']);
    expect(skipped).toBe(3);
    expect(files[0].text.split('\n')).toEqual(['  10:   let sum = 0;', '+ 11:   for (const i of items) sum += i.price * i.qty;', '+ 12:   if (sum < 0) return;', '  13:   return sum;', '  14: }', '   ...', '  41: module.exports = {', '+ 42:   total,', '  43: };']);
    expect([...files[0].lines]).toEqual([10, 11, 12, 13, 14, 41, 42, 43]);
    expect(files[0].added).toBe(3);
    expect(isReviewable('web/dist/app.js')).toBe(false);
    expect(isReviewable('src/app.ts')).toBe(true);
  });
});

describe('AI code review', () => {
  const answer: PrReviewOutput = {
    summary: 'Multiplies prices by quantity.',
    comments: [
      { path: 'src/cart.js', line: 12, category: 'bug', severity: 'issue', comment: 'Returns undefined for a negative sum; callers expect a number.' },
      { path: 'src/cart.js', line: 99, category: 'bug', severity: 'issue', comment: 'Not a line of the diff.' },
      { path: 'src/other.js', line: 1, category: 'other', severity: 'nitpick', comment: 'Not a file of the diff.' },
    ],
    confidence: 0.8,
  };

  it('sends the numbered diff and keeps only remarks on lines the diff shows', async () => {
    const { ai, prompts } = stubAi(answer);
    const logs: string[] = [];
    const review = await reviewPullRequest(input(ai), (m) => logs.push(m));
    expect(review).toMatchObject({ summary: 'Multiplies prices by quantity.', filesReviewed: 1, filesSkipped: 3, provider: 'relay', model: 'openai/gpt-6.1-sol' });
    expect(review!.comments).toEqual([answer.comments[0]]);
    expect(prompts[0]).toContain('<diff path="src/cart.js">');
    expect(prompts[0]).toContain('+ 12:   if (sum < 0) return;');
    expect(prompts[0]).toContain('<known_issues>\nsrc/cart.js:3 Hard-coded secret');
    expect(prompts[0]).not.toContain('package-lock');
    expect(logs.join('\n')).toMatch(/1 remark\(s\) on 1 file\(s\), 2 dropped/);
  });

  it('does nothing when the feature is off or the changes do not fit', async () => {
    const off = stubAi(answer, { enabled: false });
    expect(await reviewPullRequest(input(off.ai), () => undefined)).toBeNull();
    expect(off.prompts).toHaveLength(0);
    const small = stubAi(answer, { limit: 1600 });
    expect(await reviewPullRequest(input(small.ai), () => undefined)).toBeNull();
    expect(small.prompts).toHaveLength(0);
  });

  it('appears in the comment as an advisory section with escaped text', () => {
    const result: PrScanResult = {
      gate: 'passed',
      changedFiles: 2,
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      findings: [],
      truncated: false,
      existingInChangedFiles: 0,
      suppressed: 0,
      scanners: [],
      commentError: null,
      review: { summary: 'Looks fine <img src=x>.', comments: [{ path: 'src/cart.js', line: 12, category: 'error_handling', severity: 'issue', comment: 'Ping @admins: [click](http://evil)' }], filesReviewed: 1, filesSkipped: 2, provider: 'relay', model: 'openai/gpt-6.1-sol' },
    };
    const sha = 'a'.repeat(40);
    const body = renderPrComment(result, { provider: 'github', repoUrl: 'https://github.com/acme/shop', headSha: sha, failOn: 'high', argusUrl: null });
    expect(body).toContain('✅ passed');
    expect(body).toContain('AI code review (1 remark)');
    expect(body).toContain('It does not affect the gate');
    expect(body).toContain(`[\`src/cart.js:12\`](https://github.com/acme/shop/blob/${sha}/src/cart.js#L12) · error handling:`);
    expect(body).not.toContain('<img');
    expect(body).not.toContain('](http://evil)');
    expect(body).not.toMatch(/(^|\s)@admins/);
    expect(body).toContain('2 files were not reviewed');
    // Scans stored before the feature existed have no review.
    expect(renderPrComment({ ...result, review: undefined }, { provider: 'bitbucket_cloud', repoUrl: null, headSha: sha, failOn: 'high', argusUrl: null })).not.toContain('AI code review');
  });
});

describe('collecting the diff with git', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'argus-review-'));
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));
  const sh = (args: string[], cwd: string) => execFileSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.com', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.com' } }).trim();
  const write = (dir: string, files: Record<string, string>) => {
    for (const [p, c] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, p)), { recursive: true });
      writeFileSync(join(dir, p), c);
    }
    sh(['add', '-A'], dir);
  };

  it('diffs against the point the branch left its base, not the moved tip', async () => {
    const origin = join(tmp, 'origin');
    mkdirSync(origin);
    sh(['-c', 'init.defaultBranch=main', 'init', '-q'], origin);
    write(origin, { 'a.js': 'one\ntwo\n', 'b.js': 'keep\n' });
    sh(['commit', '-q', '-m', 'base'], origin);
    sh(['checkout', '-q', '-b', 'feature'], origin);
    write(origin, { 'a.js': 'one\ntwo\nthree\n' });
    sh(['commit', '-q', '-m', 'feature'], origin);
    // The base moves on after the branch was cut.
    sh(['checkout', '-q', 'main'], origin);
    write(origin, { 'b.js': 'keep\nlater\n' });
    sh(['commit', '-q', '-m', 'later on main'], origin);

    const url = pathToFileURL(origin).toString();
    const workdir = join(tmp, 'work');
    const home = join(tmp, 'home');
    mkdirSync(home);
    // file:// only in this test: Argus itself allows https (and http) remotes.
    process.env.GIT_ALLOW_PROTOCOL = 'file';
    const git = (args: string[], cwd?: string) => execFileSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1' } }).trim();
    git(['-c', 'init.defaultBranch=argus', 'init', '-q', workdir]);
    git(['fetch', '--depth', '1', '-q', '--', url, 'refs/heads/feature'], workdir);
    git(['checkout', '-q', '--detach', 'FETCH_HEAD'], workdir);

    const logs: string[] = [];
    const diff = await collectDiff({ git: async (a, c) => git(a, c), workdir, baseUrl: url, baseBranch: 'main', headUrl: url, headRef: 'refs/heads/feature', changed: null, log: (m) => logs.push(m) });
    expect(logs).toEqual([]);
    const { files } = parseDiff(diff!);
    expect(files.map((f) => f.path)).toEqual(['a.js']);
    expect(files[0].text).toContain('+ 3: three');
    expect(await collectDiff({ git: async (a, c) => git(a, c), workdir, baseUrl: url, baseBranch: '--upload-pack=x', headUrl: url, headRef: 'refs/heads/feature', changed: null, log: () => undefined })).toBeNull();
  });
});
