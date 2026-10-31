import { createHash } from 'node:crypto';
import { availableParallelism } from 'node:os';
import { resolve } from 'node:path';
import { isTestPath } from '../risk';
import { opengrepVersion, runJsonTool, ToolError } from '../tools';
import { type DraftFinding, type ScanInput, type Scanner, type ScannerOutput } from '../types';

/** One result of `opengrep scan --json` (the Semgrep JSON format). */
export interface OpengrepResult {
  check_id: string;
  path: string;
  start: { line: number };
  end: { line: number };
  extra: {
    message?: string;
    severity?: string;
    lines?: string;
    fix?: string;
    metadata?: {
      category?: string;
      subcategory?: string[];
      cwe?: string[] | string;
      owasp?: string[] | string;
      confidence?: string;
      likelihood?: string;
      impact?: string;
      references?: string[];
      source?: string;
    };
  };
}

interface OpengrepReport {
  results?: OpengrepResult[];
  errors?: { level?: string; type?: unknown; message?: string }[];
}

const IMPACT_BASE: Record<string, number> = { HIGH: 70, MEDIUM: 50, LOW: 30 };
const SEVERITY_BASE: Record<string, number> = { ERROR: 70, WARNING: 50, INFO: 25 };
const list = (v: string[] | string | undefined) => (Array.isArray(v) ? v : v ? [v] : []);

/** "python.lang.security.deserialization.avoid-pickle" -> "Avoid pickle". */
export function ruleTitle(ruleId: string): string {
  const last = ruleId.slice(ruleId.lastIndexOf('.') + 1).replace(/[-_]+/g, ' ').trim();
  return last ? last[0].toUpperCase() + last.slice(1) : ruleId;
}

/** Opengrep prefixes rule ids with the rules directory as a dotted path: "/opt/rules" -> "opt.rules.". */
export function rulePrefixOf(rulesDir: string): string {
  return `${resolve(rulesDir).replace(/^[A-Za-z]:/, '').split(/[\\/]+/).filter(Boolean).join('.')}.`;
}

/**
 * Turns Opengrep results into findings. Only security rules are reported (rules without a category, such as an
 * organisation's own, count as security). The matched code is hashed for identity but never stored: it may hold secrets.
 */
export function codeFindings(results: OpengrepResult[], opts: { rulePrefix: string; allowed: Set<string> }): DraftFinding[] {
  const out: DraftFinding[] = [];
  const seen = new Map<string, number>();
  for (const r of results) {
    const path = r.path.replace(/\\/g, '/').replace(/^\.\//, '');
    const meta = r.extra.metadata ?? {};
    if (!opts.allowed.has(path) || (meta.category && meta.category !== 'security')) continue;
    const ruleId = r.check_id.startsWith(opts.rulePrefix) ? r.check_id.slice(opts.rulePrefix.length) : r.check_id;
    const snippet = (r.extra.lines && r.extra.lines !== 'requires login' ? r.extra.lines : `${r.start.line}`).replace(/\s+/g, ' ').trim();
    const digest = createHash('sha256').update(snippet).digest('hex').slice(0, 16);
    // The same rule on identical code twice in one file: number the occurrences so each stays its own finding.
    const key = `${path}\u0000${ruleId}\u0000${digest}`;
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);

    const impact = meta.impact?.toUpperCase();
    const confidence = meta.confidence?.toUpperCase();
    let base = (impact ? IMPACT_BASE[impact] : undefined) ?? SEVERITY_BASE[r.extra.severity?.toUpperCase() ?? ''] ?? 40;
    if (confidence === 'LOW') base -= 15;
    else if (confidence === 'HIGH') base += 5;
    const label = [impact ? `${impact.toLowerCase()} impact` : `${(r.extra.severity ?? 'unrated').toLowerCase()} severity`, confidence ? `${confidence.toLowerCase()} confidence` : null].filter(Boolean).join(', ');
    const cwe = list(meta.cwe);
    out.push({
      ruleId,
      identity: [path, ruleId, digest, String(occurrence)],
      title: `${ruleTitle(ruleId)} in ${path}`,
      description: r.extra.message ?? null,
      path,
      line: r.start.line || null,
      package: null,
      advisory: null,
      secret: null,
      details: {
        cwe: cwe.join(', ') || null,
        owasp: list(meta.owasp).join(', ') || null,
        confidence: meta.confidence ?? null,
        likelihood: meta.likelihood ?? null,
        impact: meta.impact ?? null,
        endLine: r.end.line !== r.start.line ? r.end.line : null,
        reference: meta.references?.[0] ?? meta.source ?? null,
        tool: 'opengrep',
      },
      remediation: r.extra.fix
        ? `Suggested change: replace the flagged code with \`${r.extra.fix.slice(0, 200)}\`. ${cwe[0] ? `See ${cwe[0].split(':')[0]} for background.` : ''}`.trim()
        : `Review the flagged code${cwe[0] ? ` (${cwe[0]})` : ''} and apply the fix described above. If the input can never be attacker-controlled here, suppress the finding with that justification.`,
      risk: { base, baseLabel: `Code weakness: ${label}`, testPath: isTestPath(path) },
    });
  }
  return out;
}

/** Static analysis with Opengrep (or Semgrep, which takes the same arguments) and a local rules directory. */
export class CodeScanner implements Scanner {
  readonly name = 'code' as const;

  constructor(
    private readonly binary: string,
    /** Directory of rule files; null when none is configured. */
    private readonly rulesDir: string | null,
    private readonly timeoutMs: number,
  ) {}

  async run(input: ScanInput): Promise<ScannerOutput> {
    if (!this.rulesDir) return { status: 'skipped', message: 'No rules configured (ARGUS_OPENGREP_RULES)', findings: [] };
    const version = await opengrepVersion(this.binary);
    if (!version) return { status: 'skipped', message: 'Opengrep is not installed', findings: [] };
    input.log(`Code: running Opengrep ${version}`);
    const report = `${input.workdir}.opengrep.json`;
    const jobs = String(Math.max(1, Math.min(4, availableParallelism())));
    let out: OpengrepReport;
    try {
      out = await runJsonTool<OpengrepReport>(
        this.binary,
        ['scan', '--config', this.rulesDir, '--json', '--output', report, '--quiet', '--disable-version-check', '--timeout', '10', '--max-target-bytes', '1000000', '--jobs', jobs, '.'],
        // Semgrep reads these; they keep it from contacting semgrep.dev. Opengrep never does.
        { cwd: input.workdir, report, timeoutMs: this.timeoutMs, env: { SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0' } },
      );
    } catch (err) {
      if (err instanceof ToolError) return { status: 'partial', message: `Opengrep failed: ${err.message}`, findings: [] };
      throw err;
    }
    // Rule ids carry the rules directory as a prefix ("opt.argus.rules.opengrep.python.lang..."); it says nothing about the issue.
    const findings = codeFindings(out.results ?? [], { rulePrefix: rulePrefixOf(this.rulesDir), allowed: new Set(input.files.map((f) => f.path)) });
    // Files Opengrep cannot parse are skipped and reported as errors; that is normal and does not make the scan partial.
    const fatal = (out.errors ?? []).filter((e) => e.level === 'error' && !/Syntax error|Lexical error|parse/i.test(JSON.stringify(e.type ?? '') + (e.message ?? '')));
    return fatal.length ? { status: 'partial', message: `Opengrep reported ${fatal.length} error(s): ${fatal[0].message?.slice(0, 200) ?? 'unknown'}`, findings } : { status: 'ok', message: `Opengrep ${version}`, findings };
  }
}
