import { dirname, posix } from 'node:path';
import { IntelError, type IntelService, mapLimit, packageKey } from '../intel.service';
import { type CargoRoots, cargoRoots, parseCargoLock, parseCargoToml } from '../parsers/cargo';
import { parseGoMod } from '../parsers/go';
import { emptyPomContext, gradleCoordinates, parseGradleBuild, parseGradleLockfile, parsePom, parseVersionCatalog, type PomContext, pomContext } from '../parsers/maven';
import { parseNuGetLock, parseCentralVersions, parsePackagesConfig, parseProjectFile } from '../parsers/nuget';
import { parsePackageJson, parsePackageJsonDependencies, parsePackageLock, parsePnpmLock, parseYarnLock } from '../parsers/npm';
import { parsePipfileLock, parsePyprojectDependencies, parsePythonLock, parseRequirementsTxt, type PythonRoots, pythonRoots } from '../parsers/pypi';
import { type ParsedDependency } from '../parsers/types';
import { matchVulnerabilities } from '../vulnerability-matcher';
import { type DraftFinding, type InventoryItem, type RepoFile, type ScanInput, type Scanner, type ScannerOutput, type SharedScanState } from '../types';

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];
const PYTHON_LOCKS = ['poetry.lock', 'uv.lock', 'pipfile.lock'];
const GRADLE_BUILDS = ['build.gradle', 'build.gradle.kts'];
/** Registry lookups (latest version, deprecation) are limited to direct dependencies. */
const MAX_REGISTRY_LOOKUPS = 400;

const base = (p: string) => p.slice(p.lastIndexOf('/') + 1);
const dir = (p: string) => (p.includes('/') ? posix.dirname(p) : '.');

/** Reads every supported manifest/lockfile into one inventory. Lockfiles win over manifests in the same folder. */
export async function collectDependencies(input: ScanInput): Promise<{ deps: ParsedDependency[]; errors: string[] }> {
  const byDir = new Map<string, Map<string, RepoFile>>();
  for (const f of input.files) {
    const d = dir(f.path);
    if (!byDir.has(d)) byDir.set(d, new Map());
    byDir.get(d)!.set(base(f.path).toLowerCase(), f);
  }
  const deps: ParsedDependency[] = [];
  const errors: string[] = [];
  const read = async (f: RepoFile) => input.readText(f, 50 * 1024 * 1024);
  const attempt = async (f: RepoFile, fn: (text: string) => ParsedDependency[]) => {
    try {
      const text = await read(f);
      if (text) deps.push(...fn(text));
    } catch (err) {
      errors.push(`${f.path}: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Central package management versions, nearest Directory.Packages.props up the tree.
  const centralByDir = new Map<string, Map<string, string>>();
  for (const [d, files] of byDir) {
    const props = files.get('directory.packages.props');
    if (props) {
      const text = await read(props);
      if (text) centralByDir.set(d, parseCentralVersions(text));
    }
  }
  const centralFor = (d: string): Map<string, string> => {
    for (let cur = d; ; cur = dir(cur)) {
      const c = centralByDir.get(cur);
      if (c) return c;
      if (cur === '.' || cur === dirname(cur)) return new Map();
    }
  };

  // Maven: properties and dependencyManagement flow from a pom.xml to the modules in folders below it.
  const pomByDir = new Map<string, PomContext>();
  const contextFor = (d: string): PomContext => {
    for (let cur = d; cur !== '.'; ) {
      cur = dir(cur);
      const c = pomByDir.get(cur);
      if (c) return c;
    }
    return emptyPomContext();
  };
  const depth = (d: string) => (d === '.' ? 0 : d.split('/').length);
  for (const d of [...byDir.keys()].sort((a, b) => depth(a) - depth(b))) {
    const pom = byDir.get(d)!.get('pom.xml');
    const text = pom ? await read(pom).catch(() => null) : null;
    if (!text) continue;
    try {
      pomByDir.set(d, pomContext(text, contextFor(d)));
    } catch {
      // Reported when the pom itself is parsed below.
    }
  }

  // Cargo: a workspace's Cargo.lock covers the crates in folders below it; their Cargo.toml files name the direct dependencies.
  const cargoLockDirs = [...byDir].filter(([, files]) => files.has('cargo.lock')).map(([d]) => d);
  const cargoLockAbove = (d: string) => cargoLockDirs.find((l) => l === '.' || d === l || d.startsWith(`${l}/`)) ?? null;
  const cargoRootsByLock = new Map<string, CargoRoots>();
  for (const [d, files] of byDir) {
    const toml = files.get('cargo.toml');
    const lockDir = toml ? cargoLockAbove(d) : null;
    if (!toml || lockDir === null) continue;
    const text = await read(toml);
    if (!text) continue;
    try {
      cargoRootsByLock.set(lockDir, cargoRoots(text, cargoRootsByLock.get(lockDir)));
    } catch {
      // A broken Cargo.toml only loses direct/dev marking; the lock file is still read.
    }
  }

  for (const [d, files] of byDir) {
    // npm
    const pkgFile = files.get('package.json');
    const pkg = pkgFile ? parsePackageJson((await read(pkgFile)) ?? '') : null;
    const lock = NPM_LOCKS.map((n) => files.get(n)).find(Boolean);
    if (lock) {
      const name = base(lock.path).toLowerCase();
      await attempt(lock, (t) => (name === 'yarn.lock' ? parseYarnLock(t, lock.path, pkg) : name === 'pnpm-lock.yaml' ? parsePnpmLock(t, lock.path, pkg) : parsePackageLock(t, lock.path, pkg)));
    } else if (pkg && pkgFile) {
      deps.push(...parsePackageJsonDependencies(pkg, pkgFile.path));
    }

    // NuGet: a lock file pins the full graph; otherwise read project files and packages.config.
    const nugetLock = files.get('packages.lock.json');
    if (nugetLock) await attempt(nugetLock, (t) => parseNuGetLock(t, nugetLock.path));
    else {
      for (const f of files.values()) {
        if (/\.(cs|fs|vb)proj$/i.test(f.path)) await attempt(f, (t) => parseProjectFile(t, f.path, centralFor(d)));
      }
    }
    const config = files.get('packages.config');
    if (config) await attempt(config, (t) => parsePackagesConfig(t, config.path));

    // PyPI: a lock file pins the full graph (pyproject.toml or Pipfile names the direct dependencies);
    // otherwise requirements files, otherwise the dependencies declared in pyproject.toml.
    const pyproject = files.get('pyproject.toml');
    const pyLock = PYTHON_LOCKS.map((n) => files.get(n)).find(Boolean);
    const requirements = [...files.values()].filter((f) => /requirements[^/]*\.txt$/i.test(base(f.path)) || (/(^|\/)requirements$/i.test(d) && /\.txt$/i.test(f.path)));
    if (pyLock) {
      const pipenv = base(pyLock.path).toLowerCase() === 'pipfile.lock';
      const rootsFile = pipenv ? files.get('pipfile') : pyproject;
      let roots: PythonRoots | null = null;
      try {
        const text = rootsFile ? await read(rootsFile) : null;
        roots = text ? pythonRoots(text, pipenv ? 'pipfile' : 'pyproject') : null;
      } catch (err) {
        errors.push(`${rootsFile!.path}: ${err instanceof Error ? err.message : String(err)}`);
      }
      await attempt(pyLock, (t) => (pipenv ? parsePipfileLock(t, pyLock.path, roots) : parsePythonLock(t, pyLock.path, roots)));
    } else if (requirements.length) {
      for (const f of requirements) await attempt(f, (t) => parseRequirementsTxt(t, f.path));
    } else if (pyproject) {
      await attempt(pyproject, (t) => parsePyprojectDependencies(t, pyproject.path));
    }

    // Maven and Gradle.
    const pom = files.get('pom.xml');
    if (pom) await attempt(pom, (t) => parsePom(t, pom.path, contextFor(d)));
    const gradleBuild = GRADLE_BUILDS.map((n) => files.get(n)).find(Boolean);
    const gradleLock = files.get('gradle.lockfile');
    if (gradleLock) {
      const buildText = gradleBuild ? await read(gradleBuild) : null;
      await attempt(gradleLock, (t) => parseGradleLockfile(t, gradleLock.path, buildText ? gradleCoordinates(buildText) : new Set()));
    } else if (gradleBuild) await attempt(gradleBuild, (t) => parseGradleBuild(t, gradleBuild.path));
    for (const f of files.values()) {
      if (/\.versions\.toml$/i.test(f.path)) await attempt(f, (t) => parseVersionCatalog(t, f.path));
    }

    // Go modules.
    const goMod = files.get('go.mod');
    if (goMod) await attempt(goMod, (t) => parseGoMod(t, goMod.path));

    // Cargo: the lock file of a workspace or crate; a crate without one (here or above it) falls back to Cargo.toml.
    const cargoLock = files.get('cargo.lock');
    const cargoToml = files.get('cargo.toml');
    if (cargoLock) await attempt(cargoLock, (t) => parseCargoLock(t, cargoLock.path, cargoRootsByLock.get(d) ?? null));
    else if (cargoToml && cargoLockAbove(d) === null) await attempt(cargoToml, (t) => parseCargoToml(t, cargoToml.path));
  }

  // One entry per package version per manifest.
  const unique = new Map<string, ParsedDependency>();
  for (const dep of deps) {
    const key = `${dep.manifestPath}|${packageKey(dep)}`;
    const existing = unique.get(key);
    if (existing) {
      existing.direct ||= dep.direct;
      existing.dev &&= dep.dev;
    } else unique.set(key, { ...dep });
  }
  return { deps: [...unique.values()], errors };
}

// Shared with continuous re-matching, so both produce the same findings.
export { fixedVersionFor } from '../vulnerability-matcher';

export class DependenciesScanner implements Scanner {
  readonly name = 'dependencies' as const;

  constructor(private readonly intel: IntelService) {}

  async run(input: ScanInput, shared: SharedScanState): Promise<ScannerOutput> {
    const { deps, errors } = await collectDependencies(input);
    for (const e of errors) input.log(`Dependencies: could not parse ${e}`);
    const inventory: InventoryItem[] = deps.map((d) => ({ ...d, latestVersion: null, deprecated: null, vulnerabilities: 0 }));
    shared.inventory = inventory;
    input.log(`Dependencies: ${inventory.length} package versions in ${new Set(deps.map((d) => d.manifestPath)).size} manifest(s)`);
    if (!inventory.length) return { status: 'ok', message: 'No supported package manifests found', findings: [] };

    const problems: string[] = [];
    const findings: DraftFinding[] = [];

    // 1. Known vulnerabilities: OSV.dev (including GitHub advisories) and Argus's own advisories.
    const matched = await matchVulnerabilities(this.intel, inventory, { nvdLookups: 5 });
    findings.push(...matched.findings);
    problems.push(...matched.problems);

    // 2. Latest version and deprecation for direct dependencies.
    const direct = inventory.filter((d) => d.direct).slice(0, MAX_REGISTRY_LOOKUPS);
    if (!this.intel.offline && direct.length) {
      let registryFailures = 0;
      await mapLimit(direct, 8, async (dep) => {
        try {
          const meta = await this.intel.packageMeta(dep);
          dep.latestVersion = meta.latest;
          dep.deprecated = meta.deprecated;
        } catch (err) {
          if (err instanceof IntelError) registryFailures++;
        }
      });
      if (registryFailures) problems.push(`registry metadata unavailable for ${registryFailures} package(s)`);
      for (const dep of direct) {
        if (!dep.deprecated) continue;
        findings.push({
          ruleId: 'deprecated-package',
          identity: [dep.manifestPath, dep.ecosystem, dep.name],
          title: `${dep.name}@${dep.version} is deprecated`,
          description: dep.deprecated,
          path: dep.manifestPath,
          line: null,
          package: { ecosystem: dep.ecosystem, name: dep.name, version: dep.version, direct: true, dev: dep.dev, fixedVersion: null, latestVersion: dep.latestVersion },
          advisory: null,
          secret: null,
          details: { deprecation: dep.deprecated },
          remediation: `Follow the maintainer's deprecation notice; move to ${dep.latestVersion ? `a supported version (latest ${dep.latestVersion}) or ` : ''}a maintained alternative.`,
          risk: { base: 30, baseLabel: 'Deprecated package', dev: dep.dev },
        });
      }
    }

    // 3. Licenses for the license scanner: npm lockfiles carry them; other ecosystems' manifests do not.
    const unlicensed = inventory.filter((d) => d.ecosystem !== 'npm' && !d.license).slice(0, MAX_REGISTRY_LOOKUPS);
    if (!this.intel.offline && unlicensed.length) {
      let failures = 0;
      await mapLimit(unlicensed, 8, async (dep) => {
        try {
          dep.license = await this.intel.packageLicense(dep);
        } catch {
          failures++;
        }
      });
      if (failures) problems.push(`license data unavailable for ${failures} package(s)`);
    }

    // Without vulnerability data the result is incomplete: do not let missing findings count as "fixed".
    return { status: matched.incomplete ? 'partial' : 'ok', message: problems.length ? problems.join('; ') : null, findings };
  }
}
