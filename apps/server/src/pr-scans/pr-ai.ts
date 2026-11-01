import { type ObservedFinding, type Repository } from '@argus/data';
import { type PrFixSuggestion } from '@argus/shared';
import { type AiService } from '../ai/ai.service';
import { PR_FIX_OUTPUT } from '../ai/output-schemas';

/** AI suggestions per pull request scan: the most severe new issues only. */
export const MAX_AI_SUGGESTIONS = 5;
const CONTEXT_LINES = 8;
const MIN_CONFIDENCE = 0.4;

const LANGUAGES: [RegExp, string][] = [
  [/\.(?:[cm]?js|jsx)$/i, 'javascript'],
  [/\.tsx?$/i, 'typescript'],
  [/\.py$/i, 'python'],
  [/\.java$/i, 'java'],
  [/\.kts?$/i, 'kotlin'],
  [/\.cs$/i, 'csharp'],
  [/\.go$/i, 'go'],
  [/\.rs$/i, 'rust'],
  [/\.rb$/i, 'ruby'],
  [/\.php$/i, 'php'],
  [/\.scala$/i, 'scala'],
  [/\.swift$/i, 'swift'],
  [/\.tf$/i, 'hcl'],
  [/\.ya?ml$/i, 'yaml'],
  [/\.json$/i, 'json'],
  [/(?:^|\/)(?:Dockerfile|Containerfile)[^/]*$|\.dockerfile$/i, 'dockerfile'],
  [/\.(?:sh|bash)$/i, 'bash'],
];

export const languageOf = (path: string) => LANGUAGES.find(([re]) => re.test(path))?.[1] ?? null;

const INSTRUCTIONS = [
  'A security scanner flagged the code below in a pull request. Suggest the smallest change to the flagged lines that fixes the issue, for the pull request author.',
  'The <code> block shows numbered lines; lines marked ">>" are the flagged ones. In "code", return only the corrected replacement for the flagged lines, keeping the surrounding style and indentation, without line numbers or markers.',
  'If the fix is not a change to those lines (for example it needs configuration elsewhere, or the finding looks like a false positive), set "code" to null and explain in the summary.',
  'Do not invent APIs. Prefer standard library or framework features that clearly exist. Keep the summary to two sentences.',
].join('\n');

/** The numbered excerpt around a finding, with the flagged lines marked. */
export function excerpt(text: string, start: number, end: number): string {
  const lines = text.split('\n');
  const from = Math.max(1, start - CONTEXT_LINES);
  const to = Math.min(lines.length, end + CONTEXT_LINES);
  return lines
    .slice(from - 1, to)
    .map((l, i) => {
      const n = from + i;
      return `${n >= start && n <= end ? '>>' : '  '} ${n}: ${l.slice(0, 300)}`;
    })
    .join('\n');
}

/**
 * Fix suggestions for new code and infrastructure findings. Only runs when the "pull request fix suggestions" AI
 * feature is on and the repository allows AI; any failure just leaves a finding without a suggestion.
 */
export async function suggestFixes(
  ai: AiService,
  repo: Repository,
  findings: ObservedFinding[],
  readFile: (path: string) => Promise<string | null>,
  knownSecrets: string[],
  log: (m: string) => void,
): Promise<Map<string, PrFixSuggestion>> {
  const out = new Map<string, PrFixSuggestion>();
  const candidates = findings.filter((f) => (f.scanner === 'code' || f.scanner === 'iac') && f.path && f.line).slice(0, MAX_AI_SUGGESTIONS);
  if (!candidates.length || !(await ai.canRun('pr_fix', repo))) return out;
  let failures = 0;
  for (const f of candidates) {
    const text = await readFile(f.path!);
    if (!text) continue;
    const end = typeof f.details?.endLine === 'number' ? f.details.endLine : f.line!;
    const prompt = [
      '<finding>',
      `Issue: ${f.title}`,
      `Rule: ${f.ruleId}`,
      f.description ? `Description: ${f.description.slice(0, 1500)}` : null,
      f.remediation ? `Scanner guidance: ${f.remediation.slice(0, 800)}` : null,
      typeof f.details?.cwe === 'string' ? `CWE: ${f.details.cwe}` : null,
      '</finding>',
      `<code path="${f.path}">`,
      excerpt(text, f.line!, end),
      '</code>',
    ]
      .filter(Boolean)
      .join('\n');
    try {
      const res = await ai.run({ useCase: 'pr_fix', repo, actor: null, instructions: INSTRUCTIONS, prompt, knownSecrets, output: PR_FIX_OUTPUT, subject: { type: 'finding', id: f.fingerprint } });
      if (res.output.confidence < MIN_CONFIDENCE) continue;
      out.set(f.fingerprint, { summary: res.output.summary, code: res.output.code?.trim() ? res.output.code : null, language: languageOf(f.path!), provider: res.provider, model: res.model });
    } catch {
      failures++;
    }
  }
  log(`AI fix suggestions: ${out.size} of ${candidates.length}${failures ? ` (${failures} failed)` : ''}`);
  return out;
}
