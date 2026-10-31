import { isTestPath } from '../risk';
import { runJsonTool, ToolError, trivyVersion } from '../tools';
import { type DraftFinding, type ScanInput, type Scanner, type ScannerOutput } from '../types';

export interface TrivyMisconfiguration {
  ID: string;
  AVDID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Resolution?: string;
  Severity?: string;
  PrimaryURL?: string;
  Status?: string;
  CauseMetadata?: { Resource?: string; Provider?: string; Service?: string; StartLine?: number; EndLine?: number };
}

export interface TrivyConfigReport {
  Results?: { Target: string; Type?: string; Misconfigurations?: TrivyMisconfiguration[] }[];
}

/**
 * Trivy severity -> base score. Trivy's LOW checks are mostly hygiene (missing descriptions, no HEALTHCHECK), so they
 * start as informational and do not open tickets with the default ticketing threshold.
 */
export const TRIVY_SEVERITY_BASE: Record<string, number> = { CRITICAL: 90, HIGH: 70, MEDIUM: 45, LOW: 10, UNKNOWN: 10 };

const KIND_LABELS: Record<string, string> = {
  terraform: 'Terraform',
  cloudformation: 'CloudFormation',
  kubernetes: 'Kubernetes',
  helm: 'Helm',
  dockerfile: 'Dockerfile',
  azure_arm: 'Azure ARM',
  'azure-arm': 'Azure ARM',
  ansible: 'Ansible',
};

/** Failed Trivy misconfiguration checks as findings. The same check on the same resource is one finding per file. */
export function iacFindings(report: TrivyConfigReport, allowed: Set<string>): DraftFinding[] {
  const out: DraftFinding[] = [];
  const seen = new Set<string>();
  for (const result of report.Results ?? []) {
    const path = result.Target.replace(/\\/g, '/').replace(/^\.\//, '');
    if (!allowed.has(path)) continue;
    for (const m of result.Misconfigurations ?? []) {
      if (m.Status && m.Status !== 'FAIL') continue;
      const resource = m.CauseMetadata?.Resource ?? '';
      const key = `${path}\u0000${m.ID}\u0000${resource}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const severity = (m.Severity ?? 'UNKNOWN').toUpperCase();
      out.push({
        ruleId: m.ID,
        identity: [path, m.ID, resource],
        title: `${(m.Title ?? m.ID).replace(/\.$/, '')} in ${path}`,
        description: [m.Message, m.Description].filter(Boolean).join('\n\n') || null,
        path,
        line: m.CauseMetadata?.StartLine || null,
        package: null,
        advisory: null,
        secret: null,
        details: {
          kind: KIND_LABELS[result.Type ?? ''] ?? result.Type ?? null,
          resource: resource || null,
          provider: m.CauseMetadata?.Provider ?? null,
          service: m.CauseMetadata?.Service ?? null,
          check: m.AVDID && m.AVDID !== m.ID ? m.AVDID : null,
          reference: m.PrimaryURL ?? null,
          tool: 'trivy',
        },
        remediation: m.Resolution ?? null,
        risk: { base: TRIVY_SEVERITY_BASE[severity] ?? 10, baseLabel: `Misconfiguration: ${severity.toLowerCase()} severity`, testPath: isTestPath(path) },
      });
    }
  }
  return out;
}

/** Terraform, Kubernetes, Helm, Dockerfile, CloudFormation and Azure ARM misconfigurations, with `trivy config`. */
export class IacScanner implements Scanner {
  readonly name = 'iac' as const;

  constructor(
    private readonly binary: string,
    private readonly timeoutMs: number,
    private readonly offline: boolean,
  ) {}

  async run(input: ScanInput): Promise<ScannerOutput> {
    const version = await trivyVersion(this.binary);
    if (!version) return { status: 'skipped', message: 'Trivy is not installed', findings: [] };
    input.log(`Infrastructure as code: running Trivy ${version}`);
    const report = `${input.workdir}.trivy-config.json`;
    // Checks are updated from Trivy's registry when online; the checks embedded in the binary are used otherwise.
    const args = ['config', '--quiet', '--format', 'json', '--output', report, '--timeout', `${Math.round(this.timeoutMs / 1000)}s`, ...(this.offline ? ['--skip-check-update'] : []), '.'];
    try {
      const out = await runJsonTool<TrivyConfigReport>(this.binary, args, { cwd: input.workdir, report, timeoutMs: this.timeoutMs });
      return { status: 'ok', message: `Trivy ${version}`, findings: iacFindings(out, new Set(input.files.map((f) => f.path))) };
    } catch (err) {
      if (!(err instanceof ToolError)) throw err;
      if (this.offline) return { status: 'partial', message: `Trivy failed: ${err.message}`, findings: [] };
      // The check bundle could not be downloaded (e.g. the registry is blocked): fall back to the embedded checks.
      input.log(`Infrastructure as code: Trivy failed (${err.message}); retrying with its embedded checks`);
      try {
        const out = await runJsonTool<TrivyConfigReport>(this.binary, [...args.slice(0, -1), '--skip-check-update', '.'], { cwd: input.workdir, report, timeoutMs: this.timeoutMs });
        return { status: 'ok', message: `Trivy ${version} (embedded checks)`, findings: iacFindings(out, new Set(input.files.map((f) => f.path))) };
      } catch (retry) {
        if (retry instanceof ToolError) return { status: 'partial', message: `Trivy failed: ${retry.message}`, findings: [] };
        throw retry;
      }
    }
  }
}
