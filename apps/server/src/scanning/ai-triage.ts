import { Inject, Injectable } from '@nestjs/common';
import { type DataStore, type Finding, type Repository } from '@argus/data';
import { type AiUseCase } from '@argus/shared';
import { type AiRunResult, AiService } from '../ai/ai.service';
import { APPLICABILITY_OUTPUT, SECRET_TRIAGE_OUTPUT } from '../ai/output-schemas';
import { describeSecret } from '../ai/redaction';
import { DATA_STORE } from '../core/tokens';
import { isTestPath } from './risk';
import { type RepoFile } from './types';

const CONTEXT_LINES = 4;
const MAX_USAGES = 5;
const MAX_FILES_SEARCHED = 2000;
const MAX_FILE_BYTES = 512 * 1024;
const TRIAGED_SEVERITIES = new Set(['critical', 'high', 'medium']);
const SOURCE_EXTENSIONS: Record<string, RegExp> = {
  npm: /\.(?:[cm]?js|jsx|tsx?|vue|svelte)$/i,
  nuget: /\.(?:cs|fs|vb|cshtml|razor)$/i,
  pypi: /\.pyw?$/i,
  maven: /\.(?:java|kt|kts|scala|groovy)$/i,
  go: /\.go$/i,
  cargo: /\.rs$/i,
};

const SECRET_INSTRUCTIONS = [
  'A secret scanner flagged the value described below. Decide whether it is likely a real credential or a false positive',
  '(test fixture, documentation example, placeholder, public identifier, generated sample).',
  'You are given the value\'s characteristics and the surrounding code with the value withheld. Real-looking credentials in',
  'application code or configuration are likely real even if the file name looks harmless. Prefer "uncertain" over guessing.',
].join(' ');

const APPLICABILITY_INSTRUCTIONS = [
  'A dependency scanner found a vulnerable package version in this repository. From the advisory and the places where the',
  'code uses the package, judge whether the repository is likely affected (the vulnerable functionality is used, or usage',
  'cannot be ruled out) or likely not affected (e.g. only unrelated functions are used, or it is a development-only tool).',
  'If the code samples are not enough to decide, answer "uncertain". The package should be upgraded either way; you only help prioritise.',
].join(' ');

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function excerpt(text: string, line: number, path: string): string {
  const lines = text.split('\n');
  const from = Math.max(1, line - CONTEXT_LINES);
  const to = Math.min(lines.length, line + CONTEXT_LINES);
  const body = lines
    .slice(from - 1, to)
    .map((l, i) => `${from + i}: ${l.slice(0, 300)}`)
    .join('\n');
  return `<code path="${path}" lines="${from}-${to}">\n${body}\n</code>`;
}

function usagePattern(ecosystem: string, name: string): RegExp | null {
  const n = escapeRegex(name);
  if (ecosystem === 'npm') return new RegExp(`(?:require\\(\\s*|from\\s+|import\\s*\\(?\\s*)["'\`]${n}(?:/[^"'\`]*)?["'\`]`);
  if (ecosystem === 'nuget') return new RegExp(`\\busing\\s+(?:static\\s+)?${n}\\b|\\b${n}\\.[A-Z]`);
  // Python import names usually match the project name with "-" as "_" (not always, e.g. "beautifulsoup4" is "bs4").
  if (ecosystem === 'pypi') {
    const mod = escapeRegex(name.toLowerCase().replace(/[-.]/g, '_'));
    return new RegExp(`^\\s*(?:from\\s+${mod}(?:\\.|\\s)|import\\s+${mod}\\b)`, 'im');
  }
  // Maven: imports of the group's packages ("org.apache.logging.log4j:log4j-core" -> "import org.apache.logging.log4j").
  if (ecosystem === 'maven') return new RegExp(`^\\s*import\\s+(?:static\\s+)?${escapeRegex(name.split(':')[0])}\\.`, 'm');
  if (ecosystem === 'go') return new RegExp(`"${n}(?:/[^"]*)?"`);
  if (ecosystem === 'cargo') return new RegExp(`\\b(?:use|extern\\s+crate)\\s+${escapeRegex(name.replace(/-/g, '_'))}\\b|\\b${escapeRegex(name.replace(/-/g, '_'))}::`);
  return null;
}

/**
 * AI hints on new findings while the checkout still exists: whether a detected secret looks real, and whether a
 * vulnerable package is used in an affected way. Hints are stored next to the finding; they never suppress,
 * re-score or close anything.
 */
@Injectable()
export class ScanAiTriage {
  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly ai: AiService,
  ) {}

  async run(repo: Repository, files: RepoFile[], secretValues: Map<string, string>, readText: (f: RepoFile) => Promise<string | null>, log: (m: string) => void): Promise<void> {
    const [secrets, vulns] = await Promise.all([this.ai.canRun('secret_triage', repo), this.ai.canRun('vuln_applicability', repo)]);
    if (!secrets && !vulns) return;
    const limit = (await this.ai.getSettings()).maxScanChecks;
    if (limit === 0) return;

    const findings = (await this.store.findings.listAllForRepo(repo.id)).filter((f) => f.status === 'open' && !f.suppressionId);
    const candidates = findings.filter(
      (f) => (secrets && f.scanner === 'secrets' && secretValues.has(f.fingerprint)) || (vulns && f.scanner === 'dependencies' && f.package && f.advisory && TRIAGED_SEVERITIES.has(f.severity)),
    );
    if (candidates.length === 0) return;
    const existing = new Set((await this.store.aiInsights.listForSubjects('finding', candidates.map((f) => f.id))).map((i) => i.subjectId));
    const todo = candidates.filter((f) => !existing.has(f.id)).sort((a, b) => b.riskScore - a.riskScore);

    const byPath = new Map(files.map((f) => [f.path, f]));
    const texts = new Map<string, string | null>();
    const text = async (f: RepoFile) => {
      if (!texts.has(f.path)) texts.set(f.path, f.size > MAX_FILE_BYTES ? null : await readText(f));
      return texts.get(f.path) ?? null;
    };

    let done = 0;
    let failed = 0;
    for (const f of todo) {
      if (done + failed >= limit) break;
      try {
        if (f.scanner === 'secrets') await this.triageSecret(repo, f, secretValues.get(f.fingerprint)!, byPath, text);
        else await this.assessApplicability(repo, f, files, text);
        done++;
      } catch (err) {
        failed++;
        // Out of budget, switched off or the provider is failing: stop here; the rest are tried on the next scan.
        log(`AI triage stopped: ${err instanceof Error ? err.message : String(err)}`);
        break;
      }
    }
    if (done) log(`AI triage: ${done} finding(s) assessed${todo.length > done + failed ? `, ${todo.length - done - failed} left for later scans` : ''}`);
  }

  private async saveInsight(f: Finding, useCase: AiUseCase, res: AiRunResult<object>) {
    await this.store.aiInsights.put({ subjectType: 'finding', subjectId: f.id, repoId: f.repoId, useCase, provider: res.provider, model: res.model, output: { ...res.output }, redactions: res.redactions, createdBy: null });
  }

  private async triageSecret(repo: Repository, f: Finding, value: string, byPath: Map<string, RepoFile>, text: (f: RepoFile) => Promise<string | null>) {
    const file = f.path ? byPath.get(f.path) : undefined;
    const content = file ? await text(file) : null;
    const facts = [
      '<finding>',
      `Detector rule: ${f.ruleId}`,
      `Finding: ${f.title}`,
      `Location: ${f.path ?? 'unknown'}${f.line ? `:${f.line}` : ''}`,
      `Path looks like test or example code: ${f.path && isTestPath(f.path) ? 'yes' : 'no'}`,
      `Value characteristics (the value itself is withheld): ${JSON.stringify(describeSecret(value))}`,
      '</finding>',
      content && f.line ? excerpt(content, f.line, f.path!) : '',
    ].join('\n');
    const res = await this.ai.run({ useCase: 'secret_triage', repo, actor: null, instructions: SECRET_INSTRUCTIONS, prompt: facts, knownSecrets: [value], output: SECRET_TRIAGE_OUTPUT, subject: { type: 'finding', id: f.id } });
    await this.saveInsight(f, 'secret_triage', res);
  }

  private async assessApplicability(repo: Repository, f: Finding, files: RepoFile[], text: (f: RepoFile) => Promise<string | null>) {
    const p = f.package!;
    const a = f.advisory!;
    const pattern = usagePattern(p.ecosystem, p.name);
    const ext = SOURCE_EXTENSIONS[p.ecosystem];
    const usages: string[] = [];
    let searched = 0;
    if (pattern && ext) {
      for (const file of files) {
        if (usages.length >= MAX_USAGES || searched >= MAX_FILES_SEARCHED) break;
        if (!ext.test(file.path) || file.path.includes('node_modules/')) continue;
        searched++;
        const content = await text(file);
        if (!content) continue;
        const m = pattern.exec(content);
        if (m) usages.push(excerpt(content, content.slice(0, m.index).split('\n').length, file.path));
      }
    }
    const facts = [
      '<finding>',
      `Package: ${p.ecosystem} ${p.name}@${p.version} (${p.direct ? 'direct' : 'transitive'} dependency, ${p.dev ? 'development only' : 'production'})`,
      `Fixed in: ${p.fixedVersion ?? 'unknown'}`,
      `Advisory: ${a.id}${a.aliases.length ? ` (${a.aliases.join(', ')})` : ''}`,
      `Summary: ${a.summary ?? 'n/a'}`,
      `Details: ${f.description ?? 'n/a'}`,
      `Known exploited (CISA KEV): ${a.kev ? 'yes' : 'no'}; EPSS: ${a.epss ?? 'n/a'}`,
      '</finding>',
      usages.length ? `<context>Places where the code references ${p.name} (first ${usages.length}):</context>\n${usages.join('\n')}` : `<context>No direct references to ${p.name} were found in ${searched} source file(s); it may be used only through other packages.</context>`,
    ].join('\n');
    const res = await this.ai.run({ useCase: 'vuln_applicability', repo, actor: null, instructions: APPLICABILITY_INSTRUCTIONS, prompt: facts, output: APPLICABILITY_OUTPUT, subject: { type: 'finding', id: f.id } });
    await this.saveInsight(f, 'vuln_applicability', res);
  }
}
