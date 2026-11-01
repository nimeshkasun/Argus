import { type Finding, type ObservedFinding } from '@argus/data';
import { type PrScanResult } from '@argus/shared';
import { describe, expect, it } from 'vitest';
import { excerpt, languageOf } from '../../src/pr-scans/pr-ai';
import { buildResult, fixCommandFor, gateFails, pullRequestDelta } from '../../src/pr-scans/pr-analysis';
import { escapeMarkdown, fileLink, MAX_COMMENT_CHARS, renderPrComment } from '../../src/pr-scans/pr-comment';

const observed = (over: Partial<ObservedFinding>): ObservedFinding => ({
  scanner: 'code',
  ruleId: 'python.lang.security.audit.eval',
  fingerprint: `fp-${Math.random()}`,
  title: 'Eval in app.py',
  description: null,
  severity: 'high',
  riskScore: 72,
  riskFactors: [],
  path: 'app.py',
  line: 3,
  package: null,
  advisory: null,
  secret: null,
  details: null,
  remediation: 'Do not eval input.',
  suppressionId: null,
  ...over,
});

const stored = (fingerprint: string, status: Finding['status']) => ({ fingerprint, status }) as Finding;

describe('pull request delta', () => {
  it('keeps new issues in changed files, and counts known and suppressed ones', () => {
    const fresh = observed({ fingerprint: 'new', riskScore: 50, severity: 'medium' });
    const worse = observed({ fingerprint: 'new2', riskScore: 95, severity: 'critical', path: 'b.py' });
    const known = observed({ fingerprint: 'known' });
    const wasFixed = observed({ fingerprint: 'regressed', riskScore: 60, severity: 'medium' });
    const elsewhere = observed({ fingerprint: 'other', path: 'untouched.py' });
    const suppressed = observed({ fingerprint: 'sup', suppressionId: 's1' });
    const baseline = [stored('known', 'open'), stored('regressed', 'fixed'), stored('other', 'open')];
    const d = pullRequestDelta([fresh, worse, known, wasFixed, elsewhere, suppressed], baseline, new Set(['app.py', 'b.py']));
    expect(d.introduced.map((f) => f.fingerprint)).toEqual(['new2', 'regressed', 'new']);
    expect(d).toMatchObject({ existingInChangedFiles: 1, suppressed: 1 });
    // Without a list of changed files, every file counts.
    expect(pullRequestDelta([elsewhere], [], null).introduced).toHaveLength(1);
  });

  it('gates on the chosen severity', () => {
    const counts = { critical: 0, high: 0, medium: 2, low: 0, info: 0 };
    expect(gateFails(counts, 'high')).toBe(false);
    expect(gateFails(counts, 'medium')).toBe(true);
    expect(gateFails(counts, 'low')).toBe(true);
    expect(gateFails({ ...counts, critical: 1 }, 'never')).toBe(false);
  });

  it('builds a capped result with fix commands for direct dependencies', () => {
    const dep = observed({
      scanner: 'dependencies',
      ruleId: 'GHSA-x',
      severity: 'critical',
      riskScore: 93,
      path: 'package-lock.json',
      package: { ecosystem: 'npm', name: 'lodash', version: '4.17.20', direct: true, dev: false, fixedVersion: '4.17.21' },
      advisory: { id: 'GHSA-x', aliases: [], summary: null, cvssScore: 7.2, cvssVector: null, epss: null, kev: true, url: 'https://github.com/advisories/GHSA-x', published: null },
    });
    const many = Array.from({ length: 60 }, (_, i) => observed({ fingerprint: `f${i}`, riskScore: 10, severity: 'info' }));
    const r = buildResult(pullRequestDelta([dep, ...many], [], null), { changedFiles: 3, failOn: 'high', scanners: [] });
    expect(r).toMatchObject({ gate: 'failed', counts: { critical: 1, info: 60 }, truncated: true });
    expect(r.findings).toHaveLength(50);
    expect(r.findings[0]).toMatchObject({ fixCommand: 'npm install lodash@4.17.21', url: 'https://github.com/advisories/GHSA-x' });
  });

  it('writes a fix command per ecosystem, only for direct dependencies with a fix', () => {
    const pkg = (ecosystem: 'npm' | 'nuget' | 'pypi' | 'maven' | 'go' | 'cargo', name: string, direct = true, dev = false) => ({ scanner: 'dependencies' as const, package: { ecosystem, name, version: '1', direct, dev, fixedVersion: '2.0.1' } });
    expect(fixCommandFor(pkg('npm', 'jest', true, true))).toBe('npm install jest@2.0.1 --save-dev');
    expect(fixCommandFor(pkg('nuget', 'Newtonsoft.Json'))).toBe('dotnet add package Newtonsoft.Json --version 2.0.1');
    expect(fixCommandFor(pkg('go', 'golang.org/x/net'))).toBe('go get golang.org/x/net@v2.0.1 && go mod tidy');
    expect(fixCommandFor(pkg('cargo', 'serde'))).toBe('cargo update -p serde --precise 2.0.1');
    expect(fixCommandFor(pkg('pypi', 'requests'))).toMatch(/^pip install "requests>=2\.0\.1"/);
    expect(fixCommandFor(pkg('npm', 'minimist', false))).toBeNull();
    expect(fixCommandFor({ scanner: 'code', package: null })).toBeNull();
  });
});

describe('pull request comment', () => {
  const result = (over: Partial<PrScanResult> = {}): PrScanResult => ({
    gate: 'failed',
    changedFiles: 4,
    counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
    findings: [
      {
        scanner: 'dependencies',
        ruleId: 'GHSA-x',
        title: 'lodash@4.17.20: Command injection',
        severity: 'critical',
        riskScore: 93,
        path: 'package-lock.json',
        line: null,
        remediation: 'Upgrade lodash to 4.17.21 or later.',
        fixCommand: 'npm install lodash@4.17.21',
        url: 'https://github.com/advisories/GHSA-x',
        ai: null,
      },
    ],
    truncated: false,
    existingInChangedFiles: 2,
    suppressed: 0,
    scanners: [{ scanner: 'code', status: 'partial', findings: 0, durationMs: 1, message: 'Opengrep failed: timed out' }],
    commentError: null,
    ...over,
  });
  const ctx = { provider: 'github' as const, repoUrl: 'https://github.com/acme/shop', headSha: 'a'.repeat(40), failOn: 'high' as const, argusUrl: 'https://argus.example.com/repositories/r?tab=pull-requests&scan=s' };

  it('summarises the gate, counts, fixes and notes', () => {
    const body = renderPrComment(result(), ctx);
    expect(body).toContain('## 🛡️ Argus security scan: ❌ failed');
    expect(body).toContain('**1 new issue** in this pull request · gate: fails on high or above · commit `aaaaaaaaaaaa` · 4 changed files · [open in Argus](https://argus.example.com/');
    expect(body).toContain('<details open>\n<summary>🔴 **Critical** · lodash@4.17.20: Command injection</summary>');
    expect(body).toContain('[`package-lock.json`](https://github.com/acme/shop/blob/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/package-lock.json)');
    expect(body).toContain('```sh\nnpm install lodash@4.17.21\n```');
    expect(body).toContain('2 issues that were already known in the files you changed are not counted.');
    expect(body).toContain('Incomplete: Code weaknesses (static analysis) (partial: Opengrep failed: timed out).');
    // Bitbucket renders no HTML.
    const bb = renderPrComment(result(), { ...ctx, provider: 'bitbucket_cloud', repoUrl: 'https://bitbucket.org/acme/shop' });
    expect(bb).not.toContain('<details');
    expect(bb).toContain('#### 🔴 **Critical**');
    expect(bb).toContain('https://bitbucket.org/acme/shop/src/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/package-lock.json');
  });

  it('says so when nothing new was found', () => {
    const body = renderPrComment(result({ gate: 'passed', counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, findings: [], existingInChangedFiles: 0, scanners: [] }), ctx);
    expect(body).toContain('✅ passed');
    expect(body).toContain('**No new issues** in this pull request');
    expect(body).not.toContain('### New issues');
  });

  it('neutralises repository-controlled text and keeps AI code fenced', () => {
    const evil = result({
      findings: [
        {
          ...result().findings[0],
          scanner: 'code',
          title: 'Eval in [click](https://evil.example) @everyone <img src=x> ![t](https://evil.example/t.png)',
          path: 'src/`x`.py',
          line: 2,
          fixCommand: null,
          url: 'javascript:alert(1)',
          ai: { summary: 'Use ast.literal_eval', code: 'value = ast.literal_eval(data)\n```\n# break out', language: 'python', provider: 'anthropic', model: 'claude-x' },
        },
      ],
    });
    const body = renderPrComment(evil, ctx);
    expect(body).not.toContain('[click](');
    expect(body).not.toContain('![t](');
    expect(body).not.toContain('<img');
    expect(body).not.toContain('@everyone');
    expect(body).not.toContain('javascript:');
    expect(body).toContain("`src/'x'.py:2`");
    expect(body).toContain('````python\nvalue = ast.literal_eval(data)\n```\n# break out\n````');
    expect(escapeMarkdown('a_b*c')).toBe('a\\_b\\*c');
  });

  it('stays under the size limit, pointing to Argus for the rest', () => {
    const big = { ...result().findings[0], remediation: 'x'.repeat(2000) };
    const body = renderPrComment(result({ counts: { critical: 50, high: 0, medium: 0, low: 0, info: 0 }, findings: Array.from({ length: 50 }, () => big) }), ctx);
    expect(body.length).toBeLessThanOrEqual(MAX_COMMENT_CHARS);
    expect(body).toMatch(/…and \d+ more — \[see all in Argus\]/);
  });

  it('links files per provider and only at real commits', () => {
    const sha = 'b'.repeat(40);
    expect(fileLink('bitbucket_server', 'https://bb.example.com/projects/P/repos/r/browse', sha, 'a b/c.ts', 9)).toBe(`https://bb.example.com/projects/P/repos/r/browse/a%20b/c.ts?at=${sha}#9`);
    expect(fileLink('github', 'https://github.com/a/b', 'not-a-sha', 'x', 1)).toBeNull();
  });
});

describe('AI fix prompt helpers', () => {
  it('numbers the excerpt and marks the flagged lines', () => {
    const text = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join('\n');
    const e = excerpt(text, 15, 16).split('\n');
    expect(e[0]).toBe('   7: line 7');
    expect(e).toContain('>> 15: line 15');
    expect(e).toContain('>> 16: line 16');
    expect(e.at(-1)).toBe('   24: line 24');
    expect(languageOf('infra/main.tf')).toBe('hcl');
    expect(languageOf('Dockerfile.prod')).toBe('dockerfile');
  });
});
