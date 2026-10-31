# Scanners, findings and risk scoring

Every scan runs five scanners over a fresh checkout of the repository. Each problem they report becomes a **finding** with a 0–100 **risk score**. Findings are tracked across scans: they are opened, refreshed, fixed and reopened automatically.

## Scanners

| Scanner | What it finds | How |
|---|---|---|
| **Leaked secrets** | Cloud keys (AWS, Azure, GCP), GitHub/GitLab/npm tokens, Slack, Stripe, SendGrid and similar keys, private keys, JWTs, passwords in connection strings, and high-entropy hard-coded secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) (bundled in the Docker image, pinned version and checksum). If Gitleaks is not installed, Argus falls back to its own built-in high-signal rules. |
| **Vulnerable & deprecated packages** | npm, NuGet, PyPI, Maven, Go and Cargo packages with published vulnerabilities, and packages marked deprecated | Reads lockfiles and manifests (below), then queries [OSV.dev](https://osv.dev), which includes the GitHub Advisory Database. Vulnerabilities are enriched with CISA KEV and FIRST EPSS. The latest versions come from the npm and NuGet registries, and from [deps.dev](https://deps.dev) for the other ecosystems. |
| **End-of-life frameworks & runtimes** | .NET, .NET Framework, Node.js, Angular, React, Vue, Next.js and NestJS versions that are out of support, or will be within the warning window | Version data from [endoflife.date](https://endoflife.date). Versions are read from target frameworks in `.csproj` files, `global.json`, `.nvmrc`, `engines.node`, `package.json` dependencies, and Dockerfile `FROM` lines. |
| **Certificates & credential expiry** | Expired or soon-to-expire certificates, RSA keys under 2048 bits, committed `.pfx`/`.p12` key stores, and expiring JWTs in configuration files | Parses `.pem`, `.crt`, `.cer` and `.der` files. Reads JWT `exp` claims in JSON, YAML, `.env`, `.config` and similar files. |
| **License policy** | Dependencies whose license is not allowed, or needs review, under your policy | SPDX expressions from npm lockfiles, NuGet `.nuspec` files and deps.dev (`OR` means any acceptable option is enough; `AND` means every part must be acceptable). |

**Supported manifests:**
- **npm:** `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` (v5–v9).
  - `package.json` alone: the lowest version allowed by each range is used, and the finding is marked *unpinned*.
- **NuGet:** `packages.lock.json`, `PackageReference` in SDK-style projects (including central package management via `Directory.Packages.props`), and `packages.config`.
- **PyPI:** `poetry.lock`, `uv.lock` and `Pipfile.lock`, with direct and development dependencies taken from `pyproject.toml` or the `Pipfile`.
  - Without a lock file: `requirements*.txt` (and `.txt` files in a `requirements/` folder), otherwise the dependencies declared in `pyproject.toml`. Only `==` pins are exact; a lower bound such as `>=2.31` is used as the version and marked *unpinned*.
  - Requirement files named for development, tests, linting or docs (for example `requirements-dev.txt`) count as development dependencies.
- **Maven and Gradle:** `pom.xml`, with versions resolved from properties and `dependencyManagement` in the same pom or a `pom.xml` in a parent folder; `gradle.lockfile` (the full resolved graph); literal `group:artifact:version` coordinates in `build.gradle(.kts)`; and Gradle version catalogs (`*.versions.toml`).
  - A pom dependency whose version comes only from an external parent or BOM (for example `spring-boot-dependencies`) cannot be resolved without downloading it, so it is skipped. Use a Gradle lock file, or declare the version, for complete coverage.
  - `test`-scoped dependencies count as development dependencies.
- **Go:** `go.mod`, including indirect modules and `replace` directives. Modules replaced by a local folder are skipped.
- **Cargo:** `Cargo.lock` (workspace members' `Cargo.toml` files name the direct and development dependencies), or `Cargo.toml` alone for a crate without a lock file.
- Package names are compared the way each ecosystem does: NuGet ids and crate names ignore case, and PyPI names follow PEP 503 (`Django_Filter` and `django-filter` are the same project). Versions are ordered by each ecosystem's own rules, for example PEP 440 for PyPI and Maven's qualifier order (`alpha` < `beta` < `milestone` < `rc` < `snapshot` < release < `sp`).
- `node_modules`, `bin`, `obj`, `dist` and similar folders are never scanned.

### Secrets: git history and live verification

Both are off by default and are turned on under **Administration → Scanning settings**.

- **Git history.** Set *Commits of history to scan for secrets* (1–1000) to also scan that many recent commits of the scanned branch.
  - The clone then fetches that many commits instead of only the latest one. Other scanners still look only at the current code.
  - A secret that was committed and later deleted is reported as *… (git history)*, with the commit and date.
  - A secret in history has the same identity as the one in the code, so deleting it from the code does not close the finding. Rotating the secret does: suppress or resolve the finding after rotating it.
  - Secrets still in the current code are not reported twice. Vendored folders and `.argus.yml` ignore rules apply to history too.
  - A finding closes as fixed once its commit is older than the scanned window.
- **Live verification.** Argus asks the issuer whether a detected credential still works, using one read-only request to the issuer's own API. A working secret raises the risk score; a revoked one lowers it.

  | Credential | Request | Needs |
  |---|---|---|
  | GitHub, GitLab, Slack, npm tokens | The issuer's "who am I" endpoint | — |
  | AWS access keys (`AKIA…`) | STS `GetCallerIdentity` (signed locally; needs no IAM permission) | The secret access key in the same file |
  | Azure Storage account keys | Blob service *Get Service Properties* (settings only, no data) | The connection string's `AccountName` (public Azure cloud only) |

  Anything inconclusive (network errors, rate limits, a storage firewall) is recorded as *unknown* and does not change the score. At most 25 secrets are checked per scan.

**Turning scanners off:** every scanner runs by default. Turn one off for a repository under **Repository → Monitoring settings → Scanners**, or in `.argus.yml` (below).

## Risk score

Each finding starts from a **base score** that reflects the nature of the issue:

| Issue | Base |
|---|---|
| Vulnerability | CVSS v3 base score × 10. For advisories with only a label: critical 95, high 75, moderate 50, low 25. |
| Secret | Private key 90 · cloud keys 85 · service tokens 80 · JWT / generic secret 55 |
| End of life | Already EOL 70 · within 90 days 50 · within the warning window 35 |
| Certificate | Expired 60 · expiring within the warning window 55 · within 90 days 35 · weak key 45 · committed key store 55 |
| License | Not allowed 50 · needs review 25 |
| Deprecated package | 30 |

**Adjustments** (defaults; change them under **Administration → Scanning settings**):

| Factor | Points |
|---|---|
| Known exploited in the wild (CISA KEV) | +15 |
| Exploit probability (EPSS) | up to +15 (EPSS × 15) |
| Repository is public | +10 |
| Business criticality | low −10 · high +5 · critical +10 |
| Development-only dependency | −20 |
| Transitive dependency | −5 |
| In test or example code (`test/`, `fixtures/`, `*.spec.ts`, …) | −25 |

The result is clamped to 0–100 and mapped to a severity:

| Score | Severity |
|---|---|
| 90–100 | **critical** |
| 70–89 | **high** |
| 40–69 | medium |
| 15–39 | low |
| below 15 | info |

Open a finding to see exactly which factors produced its score.

## Finding lifecycle

| Status | Meaning |
|---|---|
| **Open** | The latest scan still finds it. |
| **Suppressed** | It matches a suppression (accepted risk or false positive). It stays visible but doesn't count as open risk. |
| **Fixed** | A later scan, in which its scanner completed successfully, no longer finds it. |

**AI hints.** If AI triage is turned on, new secret findings can be marked *likely a real secret*, *likely a false positive* or *uncertain*, and vulnerable packages *likely affected* or *likely not affected*. Each hint shows the model's confidence and reasoning. Hints only help you prioritise: they never change a finding's status, score or suppression. See [AI assistance](ai-assistance.md).

**Re-detection.** If a fixed issue comes back, its finding is reopened and keeps its history (first seen, last seen).

**Partial scans are safe.** If a scanner could not complete, its previous findings are left as they were rather than being marked fixed. This happens when a vulnerability feed is unreachable, for example. The scan log and the scan-run view show which scanners were `ok`, `partial`, `failed` or `skipped`.

**Identity across scans.** A finding keeps the same identity (fingerprint) across scans even when line numbers move:
- a vulnerability: manifest + package + advisory
- a secret: file + keyed hash of the secret value
- a certificate: file + certificate fingerprint

## Suppressions

Use suppressions for false positives and accepted risks.

**From a finding.** Administrators and Security Managers can choose **Suppress** on a finding. A suppression matches on rule, package or path, applies to this repository or all repositories, needs a justification, and can have an expiry date. It applies immediately to existing findings and to every future scan.

**Rule matching.** A suppression by rule also matches the advisory's aliases, so suppressing `CVE-2021-23337` covers `GHSA-35jh-r3h4-6jhm`.

**Removing a suppression** reopens the findings it covered.

**Audit.** Creating and removing suppressions is recorded in the audit log.

### `.argus.yml`

Repository owners can keep scan configuration next to the code, in `.argus.yml` at the repository root:

```yaml
ignore:
  paths:                     # never scanned (globs; "docs/" means the folder and everything in it)
    - docs/
    - "test/fixtures/**"
scanners:
  licenses: false            # turn individual scanners off for this repository
suppress:
  - rule: GHSA-35jh-r3h4-6jhm   # or a CVE id
    package: lodash
    reason: template() is never called with user input; tracked in PAY-123
    expires: 2027-01-31
  - scanner: secrets
    path: "test/**"
    reason: Throwaway keys used only by unit tests
```

Every suppress entry needs a `reason` and at least one of `scanner`, `rule`, `path` or `package`. An invalid file is ignored as a whole, and the problem is reported in the scan log.

Suppressions from `.argus.yml` are labelled as such on the finding. Administrators can review them through the repository's history.

## Dependencies and SBOM

**Dependencies tab.** A repository's **Dependencies** tab lists every package version from the latest scan, with:
- direct or transitive, and dev-only
- license
- latest available version
- deprecation
- number of known vulnerabilities

**SBOM.** **SBOM (CycloneDX)** downloads a [CycloneDX 1.5](https://cyclonedx.org) JSON document containing the components (with package URLs) and the open vulnerabilities that affect them. Each export is audited.

## Package search

**Package search** answers "which repositories use this package?" across everything you can see. You can add a version range, for example `lodash` with `<4.17.21`. It reads the latest inventory of each repository, so no rescan is needed.

## Data sources, caching and offline mode

| Source | Used for | Sent from Argus |
|---|---|---|
| OSV.dev (`api.osv.dev`) | Vulnerabilities in npm, NuGet, PyPI, Maven, Go and Cargo packages | Package names and versions |
| CISA KEV (`www.cisa.gov`) | Known-exploited CVEs | Nothing (the whole catalogue is downloaded) |
| FIRST EPSS (`api.first.org`) | Exploit probability | CVE ids |
| NVD (`services.nvd.nist.gov`) | CVSS for CVEs whose OSV record has no score | CVE ids |
| Argus advisories (your database) | Advisories approved from security news or entered by hand — see [Threat intelligence](threat-intelligence.md) | Nothing |
| endoflife.date | Release cycles and end-of-life dates | Product names (e.g. `dotnet`) |
| npm registry / NuGet API | Latest version, deprecation; NuGet licenses | Package names and versions (direct dependencies only, except NuGet licenses) |
| deps.dev (`api.deps.dev`) | Latest version, deprecation and license of PyPI, Maven, Go and Cargo packages | Package names and versions |

**No source code, file contents or secrets are ever sent to these services.** Responses are cached in the database; for example, advisories are kept for 24 hours and the KEV catalogue for 12 hours. Several workers share this cache. If a source is temporarily unreachable, Argus serves cached data for up to a week.

**Mirrors and air-gapped networks:**
- Every source URL is configurable (`ARGUS_OSV_URL`, `ARGUS_NPM_REGISTRY_URL`, `ARGUS_DEPSDEV_URL`, …), so internal mirrors can be used.
- `ARGUS_OFFLINE=true` turns off all outbound intel lookups. The secrets and certificates scanners still work fully. Dependency, framework and license results are then partial, and they never mark existing findings as fixed.

**Administration → Scanning settings** (and the Threat intel overview) shows when each source was last used successfully and whether Gitleaks is installed.

Between scans, [continuous re-matching](threat-intelligence.md#continuous-re-matching) re-checks every repository's stored inventory for newly published advisories.
