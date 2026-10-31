import { execFile } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { isTestPath } from '../risk';
import { type SecretVerifier } from '../secret-verifier';
import { toolVersion } from '../tools';
import { type DraftFinding, type ScanInput, type Scanner, type ScannerOutput } from '../types';

/** Upper bound on live verifications per scan. */
const MAX_VERIFICATIONS = 25;

const execFileAsync = promisify(execFile);

interface SecretRule {
  id: string;
  description: string;
  pattern: RegExp;
  /** Capture group holding the secret (0 = whole match). */
  group?: number;
  base: number;
  /** Extra check to cut false positives (e.g. entropy of generic assignments). */
  accept?: (value: string) => boolean;
}

export const PLACEHOLDER = /^(x+|\*+|changeme|change_me|password|secret|example|sample|dummy|test|todo|redacted|null|none|undefined|<[^>]*>|\$\{.*\}|\{\{.*\}\}|%[A-Z_]+%)$/i;

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Built-in detectors, used when Gitleaks is not installed. Deliberately high-signal. */
export const BUILTIN_RULES: SecretRule[] = [
  { id: 'private-key', description: 'Private key', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, base: 90 },
  { id: 'aws-access-token', description: 'AWS access key ID', pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g, group: 1, base: 85 },
  { id: 'github-pat', description: 'GitHub personal access token', pattern: /\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g, group: 1, base: 80 },
  { id: 'github-app-token', description: 'GitHub OAuth / app token', pattern: /\b((?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b/g, group: 1, base: 80 },
  { id: 'gitlab-pat', description: 'GitLab personal access token', pattern: /\b(glpat-[A-Za-z0-9_-]{20})\b/g, group: 1, base: 80 },
  { id: 'slack-token', description: 'Slack token', pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, group: 1, base: 75 },
  { id: 'slack-webhook-url', description: 'Slack incoming webhook', pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,})/g, group: 1, base: 60 },
  { id: 'stripe-secret-key', description: 'Stripe live secret key', pattern: /\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b/g, group: 1, base: 85 },
  { id: 'gcp-api-key', description: 'Google API key', pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1, base: 70 },
  { id: 'azure-storage-account-key', description: 'Azure Storage account key', pattern: /AccountKey=([A-Za-z0-9+/]{86}==)/g, group: 1, base: 85 },
  { id: 'npm-access-token', description: 'npm access token', pattern: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1, base: 80 },
  { id: 'sendgrid-api-token', description: 'SendGrid API key', pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g, group: 1, base: 75 },
  { id: 'jwt', description: 'JSON Web Token', pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, group: 1, base: 55 },
  {
    id: 'connection-string-password',
    description: 'Password in a connection string',
    pattern: /(?:^|[;"'\s])(?:Password|Pwd)\s*=\s*([^;"'\s]{6,})/gi,
    group: 1,
    base: 65,
    accept: (v) => !PLACEHOLDER.test(v),
  },
  {
    id: 'generic-api-key',
    description: 'Hard-coded secret assignment',
    pattern: /\b(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret|access[_-]?key)\b["']?\s*[:=]\s*["']([^"'\s]{12,200})["']/gi,
    group: 1,
    base: 55,
    accept: (v) => !PLACEHOLDER.test(v) && shannonEntropy(v) >= 3.5,
  },
];

const SECRET_BASE_BY_KEYWORD: [RegExp, number][] = [
  [/private-key/i, 90],
  [/aws|gcp|azure|alibaba|stripe/i, 85],
  [/github|gitlab|npm|pypi|slack|sendgrid|twilio|shopify|atlassian|bitbucket|heroku|okta|databricks|openai|anthropic/i, 80],
  [/jwt/i, 55],
  [/generic/i, 55],
];

function baseForRule(ruleId: string): number {
  return SECRET_BASE_BY_KEYWORD.find(([re]) => re.test(ruleId))?.[1] ?? 70;
}

/** "AKIA…MPLE" for long values, fully hidden for short ones. */
export function maskSecret(value: string, ruleId: string): string {
  if (/private-key/i.test(ruleId)) return 'PEM private key';
  if (value.length < 16) return '••••••';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

const REMEDIATION =
  'Treat the secret as compromised: revoke or rotate it at the issuing service first, then remove it from the code (and from git history, e.g. with git filter-repo) and load it from a secret store or environment variable instead.';

/** "github-pat" -> "Github pat"; used for Gitleaks rules, whose descriptions are full sentences. */
function ruleLabel(ruleId: string): string {
  const s = ruleId.replace(/[-_]+/g, ' ').trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Where a secret was found in git history (only for secrets no longer in the current code). */
export interface HistoryLocation {
  commit: string;
  date: string | null;
}

function draft(
  input: ScanInput,
  ruleId: string,
  label: string,
  explanation: string,
  path: string,
  line: number | null,
  value: string,
  base: number,
  tool: string,
  history: HistoryLocation | null = null,
): DraftFinding {
  const hash = input.hashSecret(value);
  const testPath = isTestPath(path);
  const where = history
    ? ` It is no longer in the current code, but it is still in the git history (commit ${history.commit.slice(0, 12)}${history.date ? `, ${history.date.slice(0, 10)}` : ''}), so anyone with access to the repository can still read it.`
    : '';
  const finding: DraftFinding = {
    ruleId,
    // The same identity as in the current code, so a secret removed from the code stays open while it is in history.
    identity: [path, hash],
    title: `${label} in ${path}${history ? ' (git history)' : ''}`,
    description: `${explanation}${where}${testPath ? ' The file looks like test or example code; confirm the value is not a real credential.' : ''}`,
    path,
    line: history ? null : line,
    package: null,
    advisory: null,
    secret: { type: ruleId, preview: maskSecret(value, ruleId), hash },
    details: history ? { detector: tool, history: { ...history, line } } : { detector: tool },
    remediation: REMEDIATION,
    risk: { base, baseLabel: label, testPath },
  };
  // Non-enumerable: available to AI triage in memory, but never copied by spreads or serialised.
  Object.defineProperty(finding, 'secretValue', { value, enumerable: false });
  return finding;
}

interface GitleaksResult {
  RuleID: string;
  Description: string;
  File: string;
  StartLine: number;
  Secret: string;
  Commit?: string;
  Date?: string;
}

/** A secret found in a commit's changes. */
interface HistoryHit extends HistoryLocation {
  ruleId: string;
  label: string;
  explanation: string;
  path: string;
  line: number | null;
  value: string;
  base: number;
  tool: string;
}

/** Added lines of a unified diff (`git show -U0`), with their file path and new line number. */
export function* addedLines(patch: string): Generator<{ path: string; line: number; text: string }> {
  let path: string | null = null;
  let line = 0;
  for (const raw of patch.split('\n')) {
    if (raw.startsWith('+++ ')) {
      const target = raw.slice(4).trim();
      path = target === '/dev/null' ? null : target.replace(/^"?b\//, '').replace(/"$/, '');
    } else if (raw.startsWith('@@')) {
      const m = /\+(\d+)/.exec(raw);
      line = m ? Number(m[1]) : 0;
    } else if (raw.startsWith('+') && path) {
      // Minified or generated lines are skipped.
      if (raw.length <= 4096) yield { path, line, text: raw.slice(1) };
      line++;
    }
  }
}

/** Built-in rule matches in a piece of text; a value a specific rule reported is not reported again by a generic one. */
function* builtinMatches(text: string): Generator<{ rule: SecretRule; value: string; index: number }> {
  const seen = new Set<string>();
  for (const rule of BUILTIN_RULES) {
    rule.pattern.lastIndex = 0;
    for (const m of text.matchAll(rule.pattern)) {
      const value = m[rule.group ?? 0];
      if (!value || seen.has(value) || (rule.accept && !rule.accept(value))) continue;
      seen.add(value);
      yield { rule, value, index: m.index };
    }
  }
}

/** Gitleaks version, or null if the binary is not available. Probed once per process. */
export const gitleaksVersion = (binary: string) => toolVersion(binary, ['version']);

export class SecretsScanner implements Scanner {
  readonly name = 'secrets' as const;

  constructor(
    private readonly gitleaksBinary: string,
    private readonly timeoutMs: number,
    /** Live verification with the issuer; used only when the scanning setting is on and Argus is online. */
    private readonly verifier: SecretVerifier | null = null,
  ) {}

  async run(input: ScanInput): Promise<ScannerOutput> {
    const allowed = new Set(input.files.map((f) => f.path));
    const version = await gitleaksVersion(this.gitleaksBinary);
    let out: ScannerOutput;
    if (version) {
      input.log(`Secrets: running Gitleaks ${version}`);
      out = { status: 'ok', message: `Gitleaks ${version}`, findings: await this.runGitleaks(input, allowed) };
    } else {
      input.log('Secrets: Gitleaks is not installed; using Argus built-in rules');
      out = { status: 'ok', message: 'Built-in rules (Gitleaks not installed)', findings: await this.runBuiltin(input) };
    }
    if (input.settings.secretHistoryCommits > 0) {
      const history = await this.scanHistory(input, version, out.findings);
      out.findings.push(...history.findings);
      if (history.problem) out = { ...out, status: 'partial', message: history.problem };
    }
    if (this.verifier && input.settings.verifySecrets) await this.verify(out.findings, input);
    return out;
  }

  /** Checks each distinct supported secret once with its issuer, and records the result on every finding of it. */
  private async verify(findings: DraftFinding[], input: ScanInput): Promise<void> {
    const verifier = this.verifier!;
    const byValue = new Map<string, DraftFinding[]>();
    for (const f of findings) {
      if (!f.secretValue || !verifier.supports(f.ruleId)) continue;
      byValue.set(f.secretValue, [...(byValue.get(f.secretValue) ?? []), f]);
    }
    let checked = 0;
    const counts = { active: 0, inactive: 0, unknown: 0 };
    for (const [value, group] of byValue) {
      if (checked >= MAX_VERIFICATIONS) break;
      const file = input.files.find((x) => x.path === group[0].path);
      const context = file ? ((await input.readText(file)) ?? '') : '';
      const result = await verifier.verify(group[0].ruleId, value, context);
      if (!result) continue;
      checked++;
      counts[result.status]++;
      for (const f of group) {
        f.details = { ...(f.details ?? {}), verification: { status: result.status, issuer: result.issuer, checkedAt: new Date().toISOString() } };
        if (result.status !== 'unknown') f.risk = { ...f.risk, verified: result.status };
      }
    }
    if (checked) input.log(`Secrets: verified ${checked} secret(s) with their issuers: ${counts.active} active, ${counts.inactive} revoked or invalid, ${counts.unknown} inconclusive`);
  }

  /**
   * Secrets in the recent commits of the branch that are no longer in the current code. A value already found in the
   * current code is not reported again. A failure makes the scanner partial, so open history findings are not
   * wrongly marked fixed.
   */
  private async scanHistory(input: ScanInput, gitleaks: string | null, current: DraftFinding[]): Promise<{ findings: DraftFinding[]; problem: string | null }> {
    const limit = input.settings.secretHistoryCommits;
    let hits: HistoryHit[];
    try {
      hits = gitleaks ? await this.gitleaksHistory(input, limit) : await this.builtinHistory(input, limit);
    } catch (err) {
      const problem = `git history could not be scanned: ${err instanceof Error ? err.message : String(err)}`;
      input.log(`Secrets: ${problem}`);
      return { findings: [], problem };
    }
    const inCode = new Set(current.map((f) => f.secret?.hash));
    const byKey = new Map<string, DraftFinding>();
    // Newest commits come first, so each secret is reported at the commit that last added it.
    for (const h of hits) {
      if (input.excluded(h.path)) continue;
      const hash = input.hashSecret(h.value);
      const key = `${h.path}\u0000${hash}`;
      if (inCode.has(hash) || byKey.has(key)) continue;
      byKey.set(key, draft(input, h.ruleId, h.label, h.explanation, h.path, h.line, h.value, h.base, h.tool, { commit: h.commit, date: h.date }));
    }
    input.log(`Secrets: scanned up to ${limit} commit(s) of history; ${byKey.size} secret(s) found only in history`);
    return { findings: [...byKey.values()], problem: null };
  }

  private async gitleaksHistory(input: ScanInput, limit: number): Promise<HistoryHit[]> {
    const report = `${input.workdir}.gitleaks-history.json`;
    try {
      // Gitleaks reads the log itself; with a clone of limit+1 commits, "-n limit" leaves out the shallow boundary commit.
      await execFileAsync(
        this.gitleaksBinary,
        ['git', '.', '--log-opts', `-n ${limit} HEAD`, '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0', '--log-level', 'error'],
        { cwd: input.workdir, timeout: this.timeoutMs, windowsHide: true, maxBuffer: 16 * 1024 * 1024 },
      );
      const results = JSON.parse(await readFile(report, 'utf8')) as GitleaksResult[];
      return (results ?? [])
        .filter((r) => r.Secret && r.Commit)
        .map((r) => ({
          ruleId: r.RuleID,
          label: ruleLabel(r.RuleID),
          explanation: r.Description || `Matched Gitleaks rule ${r.RuleID}.`,
          path: r.File.replace(/\\/g, '/').replace(/^\.\//, ''),
          line: r.StartLine || null,
          value: r.Secret,
          base: baseForRule(r.RuleID),
          tool: 'gitleaks',
          commit: r.Commit!,
          date: r.Date || null,
        }));
    } finally {
      // The report contains raw secret values: never leave it on disk.
      await rm(report, { force: true });
    }
  }

  private async builtinHistory(input: ScanInput, limit: number): Promise<HistoryHit[]> {
    // The oldest commit of a shallow clone has no parent here, so its "changes" would be its whole tree; skip it.
    const shallow = new Set((await readFile(join(input.workdir, '.git', 'shallow'), 'utf8').catch(() => '')).split(/\s+/).filter(Boolean));
    const commits = (await input.git(['log', '-n', String(limit), '--format=%H %cI', 'HEAD'])).split('\n').filter(Boolean);
    const hits: HistoryHit[] = [];
    for (const entry of commits) {
      const [commit, date] = entry.split(' ');
      if (shallow.has(commit)) continue;
      const patch = await input.git(['show', '-U0', '--no-color', '--no-ext-diff', '--no-renames', '--format=', commit]);
      for (const added of addedLines(patch)) {
        for (const { rule, value } of builtinMatches(added.text)) {
          const explanation = `A value matching "${rule.description}" was found in the repository.`;
          hits.push({ ruleId: rule.id, label: rule.description, explanation, path: added.path, line: added.line, value, base: rule.base, tool: 'argus', commit, date: date ?? null });
        }
      }
    }
    return hits;
  }

  private async runGitleaks(input: ScanInput, allowed: Set<string>): Promise<DraftFinding[]> {
    const report = `${input.workdir}.gitleaks.json`;
    try {
      await execFileAsync(
        this.gitleaksBinary,
        ['dir', '.', '--report-format', 'json', '--report-path', report, '--no-banner', '--exit-code', '0', '--max-target-megabytes', '5', '--log-level', 'error'],
        { cwd: input.workdir, timeout: this.timeoutMs, windowsHide: true, maxBuffer: 16 * 1024 * 1024 },
      );
      const results = JSON.parse(await readFile(report, 'utf8')) as GitleaksResult[];
      const out: DraftFinding[] = [];
      for (const r of results ?? []) {
        const path = r.File.replace(/\\/g, '/').replace(/^\.\//, '');
        if (!allowed.has(path) || !r.Secret) continue;
        out.push(draft(input, r.RuleID, ruleLabel(r.RuleID), r.Description || `Matched Gitleaks rule ${r.RuleID}.`, path, r.StartLine || null, r.Secret, baseForRule(r.RuleID), 'gitleaks'));
      }
      return out;
    } finally {
      // The report contains raw secret values: never leave it on disk.
      await rm(report, { force: true });
    }
  }

  private async runBuiltin(input: ScanInput): Promise<DraftFinding[]> {
    const out: DraftFinding[] = [];
    for (const file of input.files) {
      if (file.size > 1024 * 1024) continue;
      const text = await input.readText(file);
      if (!text) continue;
      for (const { rule, value, index } of builtinMatches(text)) {
        const line = text.slice(0, index).split('\n').length;
        out.push(draft(input, rule.id, rule.description, `A value matching "${rule.description}" was found in the repository.`, file.path, line, value, rule.base, 'argus'));
      }
    }
    return out;
  }
}
