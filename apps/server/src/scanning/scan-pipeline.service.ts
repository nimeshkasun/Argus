import { open, readFile } from 'node:fs/promises';
import { Inject, Injectable } from '@nestjs/common';
import { type DataStore, type Dependency, type ObservedFinding, type Repository, type ScanRun } from '@argus/data';
import { type ScannerName, type ScannerRunResult, SCANNERS, type ScanningSettings, type ScanStats, type Severity, SEVERITIES } from '@argus/shared';
import { AppConfig } from '../config/app-config';
import { runGit } from '../scans/git';
import { isVendoredPath } from '../scans/inventory';
import { CryptoService } from '../core/crypto.service';
import { DomainEvents } from '../core/domain-events';
import { SettingsService } from '../core/settings.service';
import { DATA_STORE } from '../core/tokens';
import { ScanAiTriage } from './ai-triage';
import { SecretVerifier } from './secret-verifier';
import { compileGlobs } from './glob';
import { IntelService } from './intel.service';
import { EMPTY_REPO_CONFIG, parseRepoConfig, REPO_CONFIG_FILES, type RepoScanConfig } from './repo-config';
import { CertificatesScanner } from './scanners/certificates';
import { CodeScanner } from './scanners/code';
import { ContainersScanner } from './scanners/containers';
import { DependenciesScanner } from './scanners/dependencies';
import { FrameworksScanner } from './scanners/frameworks';
import { IacScanner } from './scanners/iac';
import { LicensesScanner } from './scanners/licenses';
import { SecretsScanner } from './scanners/secrets';
import { toObservedFinding } from './observe';
import { buildSuppressionRules } from './suppression-matcher';
import { type RepoFile, type ScanInput, type Scanner, type SharedScanState } from './types';

export interface PipelineResult {
  stats: Pick<ScanStats, 'dependencies' | 'scanners' | 'findings'>;
  /** Problems worth surfacing in the scan log (config errors, partial scanners). */
  warnings: string[];
}

/** What the scanners found in a checkout, scored and with suppressions applied, before anything is stored. */
export interface PipelineAnalysis {
  observed: ObservedFinding[];
  results: ScannerRunResult[];
  /** Scanners that ran completely; only their unseen findings may be marked fixed. */
  completed: ScannerName[];
  warnings: string[];
  shared: SharedScanState;
  /** fingerprint -> detected secret, in memory only. */
  secretValues: Map<string, string>;
  /** Files after `.argus.yml` ignore rules. */
  files: RepoFile[];
}

/** Text content of a file, or null for binary files (a NUL byte in the first 8 KiB) and files over the limit. */
async function readText(file: RepoFile, maxBytes = 2 * 1024 * 1024): Promise<string | null> {
  if (file.size > maxBytes) return null;
  const handle = await open(file.abs, 'r');
  try {
    const head = Buffer.alloc(Math.min(8192, file.size));
    await handle.read(head, 0, head.length, 0);
    if (head.includes(0)) return null;
  } finally {
    await handle.close();
  }
  return readFile(file.abs, 'utf8');
}

/**
 * Runs the enabled scanners over a checked-out repository, scores and suppresses their findings,
 * reconciles them with stored findings, and replaces the dependency inventory.
 */
@Injectable()
export class ScanPipeline {
  private readonly scanners: Scanner[];
  private readonly config: AppConfig;

  constructor(
    @Inject(DATA_STORE) private readonly store: DataStore,
    private readonly settings: SettingsService,
    private readonly crypto: CryptoService,
    private readonly events: DomainEvents,
    private readonly triage: ScanAiTriage,
    intel: IntelService,
    config: AppConfig,
  ) {
    this.config = config;
    // Order matters: the license scanner reuses the dependency inventory.
    this.scanners = [
      new SecretsScanner(config.gitleaksPath, config.scanTimeoutMs, config.offline ? null : new SecretVerifier()),
      new DependenciesScanner(intel),
      new LicensesScanner(),
      new FrameworksScanner(intel),
      new CertificatesScanner(),
      new CodeScanner(config.opengrepPath, config.opengrepRules, config.scanTimeoutMs),
      new IacScanner(config.trivyPath, config.scanTimeoutMs, config.offline),
      new ContainersScanner(config.trivyPath, config.scanTimeoutMs, config.offline, intel),
    ];
  }

  async run(repo: Repository, run: ScanRun, workdir: string, allFiles: RepoFile[], log: (m: string) => void): Promise<PipelineResult> {
    const { observed, results, completed, warnings, shared, secretValues, files } = await this.analyze(repo, workdir, allFiles, log);
    const now = new Date();
    const reconciled = await this.store.findings.reconcile({ repoId: repo.id, sourceId: repo.sourceId, teamId: repo.teamId, runId: run.id, scanners: completed, now }, observed);

    // The inventory is only replaced when the dependency scan produced one, so a failed scan keeps the last good SBOM.
    if (shared.inventory) {
      const deps: Dependency[] = shared.inventory.map((d) => ({
        repoId: repo.id,
        teamId: repo.teamId,
        ecosystem: d.ecosystem,
        name: d.name,
        version: d.version,
        direct: d.direct,
        dev: d.dev,
        license: d.license,
        manifestPath: d.manifestPath,
        latestVersion: d.latestVersion,
        deprecated: d.deprecated,
        vulnerabilities: d.vulnerabilities,
      }));
      await this.store.dependencies.replaceForRepo(repo.id, deps);
    }

    // Tickets are opened, updated and resolved from the reconciled findings.
    await this.events.emit('scan.completed', { repo, run });

    // AI hints need the checkout, so they run before it is deleted. A failure never fails the scan.
    try {
      await this.triage.run(repo, files, secretValues, readText, log);
    } catch (err) {
      warnings.push(`AI triage failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    const open = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const o of observed) if (!o.suppressionId) open[o.severity]++;
    return {
      stats: { dependencies: shared.inventory?.length, scanners: results, findings: { open, new: reconciled.opened, fixed: reconciled.fixed, reopened: reconciled.reopened } },
      warnings,
    };
  }

  /**
   * Runs the enabled scanners over a checkout and scores their findings, without storing anything. Pull request
   * scans use this directly; `overrides` adjusts the scanning settings for one analysis.
   */
  async analyze(repo: Repository, workdir: string, allFiles: RepoFile[], log: (m: string) => void, overrides: Partial<ScanningSettings> = {}): Promise<PipelineAnalysis> {
    const warnings: string[] = [];
    const repoConfig = await this.loadRepoConfig(allFiles);
    for (const e of repoConfig.errors) warnings.push(e);
    const ignored = compileGlobs(repoConfig.ignorePaths);
    const files = allFiles.filter((f) => !ignored(f.path));
    if (files.length !== allFiles.length) log(`.argus.yml ignores ${allFiles.length - files.length} file(s)`);

    const settings = { ...(await this.settings.getScanning()), ...overrides };
    const now = new Date();
    const rules = buildSuppressionRules(repo.id, await this.store.suppressions.listApplicable(repo.id, now), repoConfig, now);
    const enabled = SCANNERS.filter((s) => !repo.disabledScanners.includes(s) && repoConfig.scanners[s] !== false);

    const input: ScanInput = {
      workdir,
      files,
      repo,
      settings,
      log,
      hashSecret: (v) => this.crypto.hash(`secret:${v}`),
      readText,
      excluded: (path) => isVendoredPath(path) || ignored(path),
      git: (args) => runGit(args, { cwd: workdir, home: this.config.scanWorkdir, timeoutMs: this.config.scanTimeoutMs }),
    };
    const shared: SharedScanState = { inventory: null };
    const observed: ObservedFinding[] = [];
    const results: ScannerRunResult[] = [];
    const completed: ScannerName[] = [];
    /** fingerprint -> detected secret, in memory for AI triage during this scan only. */
    const secretValues = new Map<string, string>();

    for (const scanner of this.scanners) {
      if (!enabled.includes(scanner.name)) {
        results.push({ scanner: scanner.name, status: 'skipped', findings: 0, durationMs: 0, message: 'Disabled for this repository' });
        continue;
      }
      const started = Date.now();
      try {
        const out = await scanner.run(input, shared);
        if (out.status === 'skipped') {
          // Its earlier findings stay as they are: nothing was checked.
          results.push({ scanner: scanner.name, status: 'skipped', findings: 0, durationMs: Date.now() - started, message: out.message });
          log(`${scanner.name}: skipped (${out.message ?? 'not available'})`);
          continue;
        }
        for (const d of out.findings) {
          const o = toObservedFinding(repo, scanner.name, d, settings.riskWeights, rules);
          if (d.secretValue) secretValues.set(o.fingerprint, d.secretValue);
          observed.push(o);
        }
        if (out.status === 'ok') completed.push(scanner.name);
        else warnings.push(`${scanner.name}: ${out.message ?? 'partial results'}`);
        results.push({ scanner: scanner.name, status: out.status, findings: out.findings.length, durationMs: Date.now() - started, message: out.message });
        log(`${scanner.name}: ${out.findings.length} finding(s)${out.status === 'partial' ? ` (partial: ${out.message})` : ''}`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        warnings.push(`${scanner.name} failed: ${message}`);
        results.push({ scanner: scanner.name, status: 'failed', findings: 0, durationMs: Date.now() - started, message });
        log(`${scanner.name} failed: ${message}`);
      }
    }

    return { observed, results, completed, warnings, shared, secretValues, files };
  }

  private async loadRepoConfig(files: RepoFile[]): Promise<RepoScanConfig> {
    const file = files.find((f) => REPO_CONFIG_FILES.includes(f.path));
    if (!file) return EMPTY_REPO_CONFIG;
    const text = await readText(file, 256 * 1024);
    return text ? parseRepoConfig(text) : { ...EMPTY_REPO_CONFIG, errors: ['.argus.yml is too large or not a text file; it was ignored.'] };
  }
}
