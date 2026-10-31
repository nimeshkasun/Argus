import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { type Repository } from '@argus/data';
import { canonicalPackageName, DEFAULT_SCANNING_SETTINGS } from '@argus/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purl } from '../../src/findings/sbom';
import { packageKey } from '../../src/scanning/intel.service';
import { cargoRoots, parseCargoLock, parseCargoToml } from '../../src/scanning/parsers/cargo';
import { parseGoMod } from '../../src/scanning/parsers/go';
import { emptyPomContext, gradleCoordinates, parseGradleBuild, parseGradleLockfile, parsePom, parseVersionCatalog, pomContext } from '../../src/scanning/parsers/maven';
import { isDevRequirements, parsePipfileLock, parsePyprojectDependencies, parsePythonLock, parseRequirement, parseRequirementsTxt, pythonRoots } from '../../src/scanning/parsers/pypi';
import { collectDependencies, fixedVersionFor } from '../../src/scanning/scanners/dependencies';
import { type ScanInput } from '../../src/scanning/types';
import { compareVersions, highestStable, isPrerelease, isValidRange, lowestAbove, satisfies } from '../../src/scanning/versions';
import { inventory, walkFiles } from '../../src/scans/inventory';

const short = (deps: { name: string; version: string; direct: boolean; dev: boolean; unpinned?: boolean }[]) => deps.map((d) => `${d.name}@${d.version}${d.direct ? '' : ' (transitive)'}${d.dev ? ' (dev)' : ''}${d.unpinned ? ' (unpinned)' : ''}`);

describe('package names', () => {
  it('compares PyPI names per PEP 503 and NuGet/Cargo names without case', () => {
    expect(canonicalPackageName('pypi', 'Django_REST.framework')).toBe('django-rest-framework');
    expect(canonicalPackageName('cargo', 'Serde')).toBe('serde');
    expect(canonicalPackageName('maven', 'org.Apache:Thing')).toBe('org.Apache:Thing');
    expect(packageKey({ ecosystem: 'pypi', name: 'PyYAML', version: '6.0' })).toBe(packageKey({ ecosystem: 'pypi', name: 'pyyaml', version: '6.0' }));
  });
});

describe('version order per ecosystem', () => {
  it('PyPI follows PEP 440', () => {
    const ordered = ['1.0.dev1', '1.0a1', '1.0a2.dev1', '1.0a2', '1.0b1', '1.0rc1', '1.0', '1.0.post1', '1.0.1', '1!0.1'];
    for (let i = 1; i < ordered.length; i++) expect(compareVersions('pypi', ordered[i - 1], ordered[i]), `${ordered[i - 1]} < ${ordered[i]}`).toBe(-1);
    expect(compareVersions('pypi', '2.0', '2.0.0')).toBe(0);
    expect(compareVersions('pypi', '1.0-1', '1.0.post1')).toBe(0);
    expect(isPrerelease('pypi', '2.0rc1')).toBe(true);
    expect(isPrerelease('pypi', '2.0.post1')).toBe(false);
    expect(highestStable('pypi', ['2.31.0', '2.32.0rc1', '2.30.0'])).toBe('2.31.0');
    expect(compareVersions('pypi', 'not-a-version', '1.0')).toBeNull();
  });

  it('Maven follows ComparableVersion qualifiers', () => {
    const ordered = ['1.0-alpha1', '1.0-beta2', '1.0-M1', '1.0-RC1', '1.0-SNAPSHOT', '1.0', '1.0-sp1', '1.0.1', '1.1'];
    for (let i = 1; i < ordered.length; i++) expect(compareVersions('maven', ordered[i - 1], ordered[i]), `${ordered[i - 1]} < ${ordered[i]}`).toBe(-1);
    expect(compareVersions('maven', '1.0.0', '1')).toBe(0);
    expect(compareVersions('maven', '2.17.1', '2.17.0.Final')).toBe(1);
    expect(compareVersions('maven', '5.3.39', '5.3.4')).toBe(1);
    expect(isPrerelease('maven', '6.0.0-RC2')).toBe(true);
    expect(isPrerelease('maven', '2.0.Final')).toBe(false);
  });

  it('Go and Cargo use semver (Go with a "v" prefix and pseudo-versions)', () => {
    expect(compareVersions('go', 'v0.0.0-20210101000000-abcdef123456', 'v0.0.1')).toBe(-1);
    expect(compareVersions('go', 'v1.2.3', 'v1.10.0')).toBe(-1);
    expect(compareVersions('go', 'v2.0.0+incompatible', 'v2.0.0')).toBe(0);
    expect(lowestAbove('go', 'v0.17.0', ['0.23.0', '0.17.1'])).toBe('0.17.1');
    expect(compareVersions('cargo', '1.0.0-alpha', '1.0.0')).toBe(-1);
  });

  it('evaluates comparator ranges for PyPI and Maven, and validates them per ecosystem', () => {
    expect(satisfies('pypi', '2.30.0', '<2.31.0')).toBe(true);
    expect(satisfies('pypi', '2.31.0', '>=2.0, <2.31.0')).toBe(false);
    expect(satisfies('pypi', '1.0rc1', '<1.0')).toBe(true);
    expect(satisfies('maven', '2.14.1', '>=2.0-beta9 <2.15.0 || >=2.16.0 <2.17.1')).toBe(true);
    expect(satisfies('maven', '2.15.5', '>=2.0-beta9 <2.15.0 || >=2.16.0 <2.17.1')).toBe(false);
    expect(satisfies('go', 'v0.17.0', '<0.17.1')).toBe(true);
    expect(isValidRange('pypi', '>=1.0 <2.0')).toBe(true);
    expect(isValidRange('maven', '<2.17.0.Final')).toBe(true);
    expect(isValidRange('pypi', 'nonsense ~~')).toBe(false);
    expect(() => satisfies('pypi', '1.0', 'nonsense ~~')).toThrow();
  });

  it('finds OSV fixes for PyPI with normalised names', () => {
    const vuln = { id: 'PYSEC-1', modified: '', affected: [{ package: { ecosystem: 'PyPI', name: 'Django' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '4.2' }, { fixed: '4.2.16' }, { introduced: '5.0' }, { fixed: '5.0.9' }] }] }] };
    expect(fixedVersionFor(vuln, 'pypi', 'django', '4.2.11')).toBe('4.2.16');
    const go = { id: 'GO-1', modified: '', affected: [{ package: { ecosystem: 'Go', name: 'golang.org/x/net' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.23.0' }] }] }] };
    expect(fixedVersionFor(go, 'go', 'golang.org/x/net', 'v0.17.0')).toBe('0.23.0');
  });
});

describe('PyPI parsers', () => {
  it('reads PEP 508 requirements', () => {
    expect(parseRequirement('requests[socks] == 2.31.0 ; python_version > "3.8"')).toEqual({ name: 'requests', version: '2.31.0', pinned: true });
    expect(parseRequirement('Django>=4.2,<5')).toEqual({ name: 'django', version: '4.2', pinned: false });
    expect(parseRequirement('flask')).toBeNull();
    expect(parseRequirement('numpy<2')).toBeNull();
  });

  it('reads requirements.txt and skips options, includes and URLs', () => {
    const text = ['# comment', 'requests==2.31.0 --hash=sha256:abc', '-r base.txt', '-e .', 'Flask_Login>=0.6  # inline', 'git+https://github.com/x/y.git', 'pkg @ https://example.com/pkg.whl', 'urllib3==1.26.18 \\', '    --hash=sha256:def'].join('\n');
    expect(short(parseRequirementsTxt(text, 'requirements.txt'))).toEqual(['requests@2.31.0', 'flask-login@0.6 (unpinned)', 'urllib3@1.26.18']);
    expect(isDevRequirements('requirements-dev.txt')).toBe(true);
    expect(isDevRequirements('requirements/test.txt')).toBe(true);
    expect(isDevRequirements('requirements.txt')).toBe(false);
    expect(parseRequirementsTxt('pytest==8.0.0', 'requirements-dev.txt')[0].dev).toBe(true);
  });

  const pyproject = `[project]
name = "app"
dependencies = ["requests>=2.31", "pydantic==2.7.1"]
[project.optional-dependencies]
s3 = ["boto3==1.34.0"]
[dependency-groups]
dev = ["pytest==8.2.0"]
[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
[tool.poetry.group.test.dependencies]
coverage = { version = "7.5.0" }
`;

  it('reads direct dependencies and declared versions from pyproject.toml', () => {
    const roots = pythonRoots(pyproject, 'pyproject');
    expect([...roots.prod].sort()).toEqual(['boto3', 'httpx', 'pydantic', 'requests']);
    expect([...roots.dev].sort()).toEqual(['coverage', 'pytest']);
    expect(short(parsePyprojectDependencies(pyproject, 'pyproject.toml'))).toEqual([
      'requests@2.31 (unpinned)',
      'pydantic@2.7.1',
      'boto3@1.34.0',
      'pytest@8.2.0 (dev)',
      'httpx@0.27 (unpinned)',
      'coverage@7.5.0 (dev)',
    ]);
  });

  it('reads poetry.lock and uv.lock, marking direct and dev from pyproject', () => {
    const roots = pythonRoots(pyproject, 'pyproject');
    const poetry = `[[package]]\nname = "requests"\nversion = "2.32.3"\n\n[[package]]\nname = "urllib3"\nversion = "2.2.2"\n\n[[package]]\nname = "pytest"\nversion = "8.2.0"\n\n[metadata]\nlock-version = "2.0"\n`;
    expect(short(parsePythonLock(poetry, 'poetry.lock', roots))).toEqual(['requests@2.32.3', 'urllib3@2.2.2 (transitive)', 'pytest@8.2.0 (dev)']);
    const uv = `version = 1\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "Pydantic"\nversion = "2.7.1"\nsource = { registry = "https://pypi.org/simple" }\n`;
    expect(short(parsePythonLock(uv, 'uv.lock', roots))).toEqual(['pydantic@2.7.1']);
    // Poetry < 1.2 lock files mark development packages with a category.
    expect(parsePythonLock('[[package]]\nname = "black"\nversion = "23.1.0"\ncategory = "dev"\n', 'poetry.lock', null)[0].dev).toBe(true);
  });

  it('reads Pipfile.lock with direct dependencies from the Pipfile', () => {
    const roots = pythonRoots('[packages]\nflask = "*"\n[dev-packages]\npytest = "*"\n', 'pipfile');
    const lock = JSON.stringify({ _meta: {}, default: { flask: { version: '==3.0.3' }, werkzeug: { version: '==3.0.3' } }, develop: { pytest: { version: '==8.2.0' } } });
    expect(short(parsePipfileLock(lock, 'Pipfile.lock', roots))).toEqual(['flask@3.0.3', 'werkzeug@3.0.3 (transitive)', 'pytest@8.2.0 (dev)']);
  });
});

describe('Maven and Gradle parsers', () => {
  const parent = `<?xml version="1.0"?>
<project>
  <version>1.4.0</version>
  <properties><log4j.version>2.14.1</log4j.version><spring.version>5.3.20</spring.version></properties>
  <dependencyManagement><dependencies>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.13.0</version></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>3.2.0</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement>
</project>`;
  const child = `<project>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.4.0</version></parent>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>\${log4j.version}</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-web</artifactId><version>[\${spring.version},6.0)</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter</artifactId></dependency>
    <dependency><groupId>com.acme</groupId><artifactId>sibling</artifactId><version>\${project.version}</version></dependency>
  </dependencies>
</project>`;

  it('resolves pom versions from properties and dependencyManagement in parent folders', () => {
    const ctx = pomContext(parent, emptyPomContext());
    expect(short(parsePom(child, 'service/pom.xml', ctx))).toEqual([
      'org.apache.logging.log4j:log4j-core@2.14.1',
      'com.fasterxml.jackson.core:jackson-databind@2.13.0',
      'org.springframework:spring-web@5.3.20 (unpinned)',
      'junit:junit@4.13.2 (dev)',
      'com.acme:sibling@1.4.0',
    ]);
    // Entities declared in a repository's DOCTYPE are never expanded.
    const evil = '<!DOCTYPE project [<!ENTITY v "6.6.6">]><project><dependencies><dependency><groupId>a</groupId><artifactId>b</artifactId><version>&v;</version></dependency></dependencies></project>';
    expect(JSON.stringify(parsePom(evil, 'pom.xml'))).not.toContain('6.6.6');
  });

  it('reads gradle.lockfile, literal coordinates in build files and version catalogs', () => {
    const build = `dependencies {\n  implementation("org.apache.commons:commons-text:1.9")\n  testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0'\n  implementation(libs.guava)\n  implementation "com.example:dynamic:$someVersion"\n  /* implementation 'com.old:gone:1.0' */\n}\n`;
    expect(short(parseGradleBuild(build, 'build.gradle'))).toEqual(['org.apache.commons:commons-text@1.9', 'org.junit.jupiter:junit-jupiter@5.10.0 (dev)']);
    const lock = '# comment\norg.apache.commons:commons-text:1.9=compileClasspath,runtimeClasspath\norg.apache.commons:commons-lang3:3.11=runtimeClasspath\norg.junit.jupiter:junit-jupiter:5.10.0=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n';
    expect(short(parseGradleLockfile(lock, 'gradle.lockfile', gradleCoordinates(build)))).toEqual([
      'org.apache.commons:commons-text@1.9',
      'org.apache.commons:commons-lang3@3.11 (transitive)',
      'org.junit.jupiter:junit-jupiter@5.10.0 (dev)',
    ]);
    const catalog = `[versions]\nguava = "32.1.2-jre"\n[libraries]\nguava = { module = "com.google.guava:guava", version.ref = "guava" }\nokhttp = "com.squareup.okhttp3:okhttp:4.12.0"\nnetty = { group = "io.netty", name = "netty-all", version = "4.1.100.Final" }\nbom = { module = "org.example:bom" }\n`;
    expect(short(parseVersionCatalog(catalog, 'gradle/libs.versions.toml'))).toEqual(['com.google.guava:guava@32.1.2-jre', 'com.squareup.okhttp3:okhttp@4.12.0', 'io.netty:netty-all@4.1.100.Final']);
  });
});

describe('Go and Cargo parsers', () => {
  it('reads go.mod with indirect modules and replace directives', () => {
    const mod = `module example.com/app

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgolang.org/x/net v0.17.0 // indirect
\texample.com/local v1.0.0
)

require github.com/stretchr/testify v1.9.0

exclude golang.org/x/crypto v0.1.0

replace (
\texample.com/local => ../local
\tgithub.com/gin-gonic/gin v1.9.1 => github.com/fork/gin v1.9.2
)
`;
    expect(short(parseGoMod(mod, 'go.mod'))).toEqual(['github.com/fork/gin@v1.9.2', 'golang.org/x/net@v0.17.0 (transitive)', 'github.com/stretchr/testify@v1.9.0']);
  });

  it('reads Cargo.lock with direct dependencies from Cargo.toml, and Cargo.toml alone', () => {
    const toml = `[package]\nname = "app"\n\n[dependencies]\nserde = { version = "1.0", features = ["derive"] }\ntokio = "1.37"\nlocal = { path = "../local" }\nrenamed = { package = "reqwest", version = "0.12" }\n\n[dev-dependencies]\ntempfile = "3"\n\n[target.'cfg(unix)'.dependencies]\nlibc = "=0.2.155"\n`;
    const lock = `version = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.203"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "mio"\nversion = "0.8.11"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "tempfile"\nversion = "3.10.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`;
    expect(short(parseCargoLock(lock, 'Cargo.lock', cargoRoots(toml)))).toEqual(['serde@1.0.203', 'mio@0.8.11 (transitive)', 'tempfile@3.10.1 (dev)']);
    expect(short(parseCargoToml(toml, 'Cargo.toml'))).toEqual([
      'serde@1.0.0 (unpinned)',
      'tokio@1.37.0 (unpinned)',
      'reqwest@0.12.0 (unpinned)',
      'tempfile@3.0.0 (dev) (unpinned)',
      'libc@0.2.155 (unpinned)',
    ]);
  });
});

describe('package URLs for the new ecosystems', () => {
  it('follows the purl spec', () => {
    expect(purl('pypi', 'Django_Filter', '24.2')).toBe('pkg:pypi/django-filter@24.2');
    expect(purl('maven', 'org.apache.logging.log4j:log4j-core', '2.14.1')).toBe('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');
    expect(purl('go', 'github.com/gin-gonic/gin', 'v1.9.1')).toBe('pkg:golang/github.com/gin-gonic/gin@v1.9.1');
    expect(purl('cargo', 'serde', '1.0.203')).toBe('pkg:cargo/serde@1.0.203');
  });
});

describe('collecting a polyglot repository', () => {
  let root: string;
  const write = (path: string, text: string) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), text);
  };

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), 'argus-ecosystems-'));
    write('api/requirements.txt', 'requests==2.31.0\n');
    write('api/requirements-dev.txt', 'pytest==8.2.0\n');
    write('ml/pyproject.toml', '[project]\ndependencies = ["numpy>=1.26"]\n');
    write('ml/poetry.lock', '[[package]]\nname = "numpy"\nversion = "1.26.4"\n');
    write('java/pom.xml', '<project><properties><v>2.14.1</v></properties></project>');
    write('java/core/pom.xml', '<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>${v}</version></dependency></dependencies></project>');
    write('svc/go.mod', 'module x\n\nrequire golang.org/x/net v0.17.0\n');
    write('rs/Cargo.toml', '[workspace]\nmembers = ["cli"]\n');
    write('rs/Cargo.lock', '[[package]]\nname = "clap"\nversion = "4.5.4"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n');
    write('rs/cli/Cargo.toml', '[package]\nname = "cli"\n[dependencies]\nclap = "4"\n');
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it('finds every ecosystem and resolves workspace and parent context', async () => {
    const files = await walkFiles(root);
    expect(inventory(files).ecosystems.sort()).toEqual(['cargo', 'go', 'maven', 'pypi']);
    const input = { files, readText: async (f: { abs: string }) => readFile(f.abs, 'utf8'), repo: {} as Repository, settings: DEFAULT_SCANNING_SETTINGS } as unknown as ScanInput;
    const { deps, errors } = await collectDependencies(input);
    expect(errors).toEqual([]);
    expect(deps.map((d) => `${d.ecosystem}:${d.name}@${d.version}${d.direct ? '' : ' (transitive)'}${d.dev ? ' (dev)' : ''}`).sort()).toEqual([
      'cargo:clap@4.5.4',
      'go:golang.org/x/net@v0.17.0',
      'maven:org.apache.logging.log4j:log4j-core@2.14.1',
      'pypi:numpy@1.26.4',
      'pypi:pytest@8.2.0 (dev)',
      'pypi:requests@2.31.0',
    ]);
  });
});
