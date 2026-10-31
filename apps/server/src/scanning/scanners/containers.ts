import { type FindingAdvisory } from '@argus/shared';
import { collectImageRefs, type ImageRef } from '../image-refs';
import { type IntelService } from '../intel.service';
import { runJsonTool, ToolError, trivyVersion } from '../tools';
import { type DraftFinding, type ScanInput, type Scanner, type ScannerOutput } from '../types';
import { TRIVY_SEVERITY_BASE } from './iac';

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  PkgPath?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  PrimaryURL?: string;
  PublishedDate?: string;
  CVSS?: Record<string, { V3Score?: number; V3Vector?: string } | undefined>;
}

export interface TrivyImageReport {
  Metadata?: { OS?: { Family?: string; Name?: string; EOSL?: boolean }; RepoDigests?: string[] };
  Results?: { Target: string; Class?: string; Type?: string; Vulnerabilities?: TrivyVulnerability[] }[];
}

const SEVERITIES_FROM = { critical: 'CRITICAL', high: 'CRITICAL,HIGH', medium: 'CRITICAL,HIGH,MEDIUM', low: 'CRITICAL,HIGH,MEDIUM,LOW' } as const;
/** Each image gets at most this long; pulling large images over a slow link is the usual cost. */
const MAX_IMAGE_MS = 10 * 60_000;

function cvss(v: TrivyVulnerability): { score: number | null; vector: string | null } {
  const sources = v.CVSS ?? {};
  const pick = sources.nvd?.V3Score !== undefined ? sources.nvd : Object.values(sources).find((s) => s?.V3Score !== undefined);
  return { score: pick?.V3Score ?? null, vector: pick?.V3Vector ?? null };
}

/** Findings for one scanned image: one per vulnerable package and vulnerability, plus one if the OS is end of life. */
export function imageFindings(report: TrivyImageReport, ref: ImageRef, intel: { kev: Set<string>; epss: Map<string, number> }): DraftFinding[] {
  const out: DraftFinding[] = [];
  const os = report.Metadata?.OS?.Family ? `${report.Metadata.OS.Family} ${report.Metadata.OS.Name ?? ''}`.trim() : null;
  const digest = report.Metadata?.RepoDigests?.[0]?.split('@')[1] ?? null;
  const seen = new Set<string>();
  for (const result of report.Results ?? []) {
    for (const v of result.Vulnerabilities ?? []) {
      const identity = [ref.image, result.Type ?? '', v.PkgName, v.PkgPath ?? '', v.VulnerabilityID];
      const key = identity.join('\u0000');
      if (seen.has(key)) continue;
      seen.add(key);
      const { score, vector } = cvss(v);
      const severity = (v.Severity ?? 'UNKNOWN').toUpperCase();
      const isCve = v.VulnerabilityID.startsWith('CVE-');
      const kev = isCve && intel.kev.has(v.VulnerabilityID);
      const epss = isCve ? (intel.epss.get(v.VulnerabilityID) ?? null) : null;
      const advisory: FindingAdvisory = { id: v.VulnerabilityID, aliases: [], summary: v.Title ?? null, cvssScore: score, cvssVector: vector, epss, kev, url: v.PrimaryURL ?? null, published: v.PublishedDate ?? null };
      out.push({
        ruleId: v.VulnerabilityID,
        identity,
        title: `${v.PkgName}@${v.InstalledVersion} in ${ref.image}: ${v.Title ?? v.VulnerabilityID}`.slice(0, 300),
        description: v.Description?.slice(0, 4000) ?? v.Title ?? null,
        path: ref.path,
        line: ref.line,
        package: null,
        advisory,
        secret: null,
        details: {
          image: ref.image,
          digest,
          os,
          package: v.PkgName,
          installedVersion: v.InstalledVersion,
          fixedVersion: v.FixedVersion || null,
          packageType: result.Type ?? null,
          packagePath: v.PkgPath ?? null,
          tool: 'trivy',
        },
        remediation: v.FixedVersion
          ? `${v.PkgName} ${v.FixedVersion} fixes this. Rebuild on the latest patch release of ${ref.image} (or a newer tag) that includes it${result.Class === 'os-pkgs' ? ', or upgrade the package in your own image layer' : ''}.`
          : `No fixed version of ${v.PkgName} is published yet. Consider a different base image, or remove the package if it is not needed.`,
        risk: { base: score !== null ? score * 10 : (TRIVY_SEVERITY_BASE[severity] ?? 10), baseLabel: score !== null ? `CVSS ${score.toFixed(1)}` : `${severity.toLowerCase()} (Trivy)`, kev, epss },
      });
    }
  }
  if (report.Metadata?.OS?.EOSL && os) {
    out.push({
      ruleId: 'image-os-end-of-life',
      identity: [ref.image, 'os-end-of-life', os],
      title: `${os} in ${ref.image} is end of life`,
      description: `The operating system of ${ref.image} (${os}) no longer receives security updates, so new vulnerabilities in it will not be fixed.`,
      path: ref.path,
      line: ref.line,
      package: null,
      advisory: null,
      secret: null,
      details: { image: ref.image, digest, os, tool: 'trivy' },
      remediation: `Move to a base image on a supported ${report.Metadata.OS.Family} release.`,
      risk: { base: 60, baseLabel: 'End-of-life operating system' },
    });
  }
  return out;
}

/** Vulnerable packages in the container images a repository references, with `trivy image` (pulled from the registry). */
export class ContainersScanner implements Scanner {
  readonly name = 'containers' as const;

  constructor(
    private readonly binary: string,
    private readonly timeoutMs: number,
    private readonly offline: boolean,
    private readonly intel: IntelService,
  ) {}

  async run(input: ScanInput): Promise<ScannerOutput> {
    const settings = input.settings.containerImages;
    if (!settings.enabled) return { status: 'skipped', message: 'Turned off in the scanning settings', findings: [] };
    if (this.offline) return { status: 'skipped', message: 'Not available in offline mode (images are pulled from their registries)', findings: [] };
    const version = await trivyVersion(this.binary);
    if (!version) return { status: 'skipped', message: 'Trivy is not installed', findings: [] };

    const { refs, errors } = await collectImageRefs(input.files, (f) => input.readText(f));
    for (const e of errors) input.log(`Containers: could not read ${e}`);
    if (!refs.length) return { status: 'ok', message: 'No container images referenced', findings: [] };
    const chosen = refs.slice(0, settings.maxImages);
    input.log(`Containers: scanning ${chosen.length} of ${refs.length} image(s) with Trivy ${version}`);

    const reports: { ref: ImageRef; report: TrivyImageReport }[] = [];
    const failed: string[] = [];
    for (const [i, ref] of chosen.entries()) {
      const report = `${input.workdir}.trivy-image-${i}.json`;
      const timeout = Math.min(this.timeoutMs, MAX_IMAGE_MS);
      const args = ['image', '--quiet', '--scanners', 'vuln', '--image-src', 'remote', '--format', 'json', '--output', report, '--severity', SEVERITIES_FROM[settings.minSeverity], '--timeout', `${Math.round(timeout / 1000)}s`, ...(settings.fixableOnly ? ['--ignore-unfixed'] : []), ref.image];
      try {
        reports.push({ ref, report: await runJsonTool<TrivyImageReport>(this.binary, args, { cwd: input.workdir, report, timeoutMs: timeout }) });
      } catch (err) {
        if (!(err instanceof ToolError)) throw err;
        failed.push(ref.image);
        input.log(`Containers: could not scan ${ref.image}: ${err.message}`);
      }
    }

    const cves = [...new Set(reports.flatMap(({ report }) => (report.Results ?? []).flatMap((r) => (r.Vulnerabilities ?? []).map((v) => v.VulnerabilityID))).filter((id) => id.startsWith('CVE-')))];
    const problems: string[] = [];
    const [kev, epss] = await Promise.all([
      cves.length ? this.intel.kev().catch((err: unknown) => (problems.push(`CISA KEV: ${(err as Error).message}`), new Set<string>())) : Promise.resolve(new Set<string>()),
      cves.length ? this.intel.epss(cves).catch((err: unknown) => (problems.push(`EPSS: ${(err as Error).message}`), new Map<string, number>())) : Promise.resolve(new Map<string, number>()),
    ]);
    const findings = reports.flatMap(({ ref, report }) => imageFindings(report, ref, { kev, epss }));

    if (refs.length > chosen.length) problems.push(`${refs.length - chosen.length} more image(s) not scanned (limit ${settings.maxImages})`);
    // An image that could not be pulled keeps its earlier findings open rather than marking them fixed.
    if (failed.length) return { status: 'partial', message: [`could not scan ${failed.join(', ')}`, ...problems].join('; '), findings };
    return { status: 'ok', message: problems.length ? problems.join('; ') : `Trivy ${version}`, findings };
  }
}
