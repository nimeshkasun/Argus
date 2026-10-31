# Configuration

Argus is configured with environment variables, validated at startup. If a value is invalid, the process prints every problem and exits without starting. Empty values are treated as unset.

Runtime policies (password rules, MFA, sessions) are set in the UI under **Administration → Security settings** and stored in the database.

## Environment variables

### Required

| Variable | Description |
|---|---|
| `ARGUS_DB_TYPE` | `postgres` or `mongodb`. |
| `ARGUS_DB_URL` | Connection string, for example `postgres://user:pass@host:5432/argus?sslmode=require` or `mongodb+srv://user:pass@cluster/?retryWrites=true`. |
| `ARGUS_MASTER_KEY` | At least 32 characters. The root key for encryption at rest and token signing. Generate it with `openssl rand -base64 48`. **Changing it invalidates every session, MFA enrollment and stored credential.** See [security](security.md#1-secrets-and-credentials-at-rest). |

### Optional

| Variable | Default | Description |
|---|---|---|
| `ARGUS_DB_NAME` | from the URL, else `argus` | MongoDB database name. |
| `ARGUS_ROLE` | `all` | `all` runs API, UI and worker. `api` runs HTTP only. `worker` runs background processing only. See [architecture](architecture.md#runtime-roles). |
| `ARGUS_ADMIN_PASSWORD` | generated | Initial password for the default `admin` account. Used **only** when the database has no users. It must be changed at first sign-in. |
| `ARGUS_PUBLIC_URL` | — | External URL, for example `https://argus.example.com`. Used for links in emails, notifications and Jira issues, and to enable `Secure` cookies and HSTS when it starts with `https://`. Required for [sign-in links by email](features/user-management.md#sign-in-links-by-email). |
| `ARGUS_COOKIE_SECURE` | `auto` | `auto` is secure when the public URL is HTTPS (or, without a public URL, when `NODE_ENV=production`). Can also be `true` or `false`. |
| `ARGUS_TRUST_PROXY` | `1` | Express `trust proxy` setting, so client IPs are correct behind a load balancer or App Service front end. Accepts a hop count, `true`, `false`, or a subnet list. |
| `ARGUS_AUTH_RATE_LIMIT` | `10` | Requests per minute per client IP for each credential endpoint (login, MFA verification, password change). Raise it if many users share one egress IP (corporate NAT). |
| `ARGUS_WORKER_CONCURRENCY` | `2` | Maximum number of background jobs (scans, syncs) one worker process runs at the same time. |
| `ARGUS_SCAN_WORKDIR` | `<os temp>/argus-scans` | Parent directory for the temporary scan checkouts. Each scan uses a subdirectory, deleted when the scan ends. Needs free space for your largest repository. |
| `ARGUS_SCAN_TIMEOUT_MINUTES` | `30` | Maximum time a clone may take. |
| `ARGUS_SCHEDULER_INTERVAL_SECONDS` | `30` | How often the scheduler checks for due scans and stale sources. |
| `ARGUS_OFFLINE` | `false` | `true` turns off every outbound threat-intelligence lookup (OSV, KEV, EPSS, NVD, endoflife.date, registries), news feed fetching, and the AI providers' public APIs (a provider with a private base URL keeps working). See [offline mode](features/scanners-and-findings.md#data-sources-caching-and-offline-mode). |
| `SCAN` | `true` | `false` stops this instance from running repository scans, for example in local development against a shared database. Scheduled and requested scans are still queued, and an instance with `SCAN=true` runs them. If no instance has it, they wait. |
| `ARGUS_GITLEAKS_PATH` | `gitleaks` | Gitleaks binary used by the secrets scanner. The Docker image includes it. Without Gitleaks, built-in rules are used. |
| `ARGUS_OSV_URL` | `https://api.osv.dev` | OSV API base URL, or an internal mirror. |
| `ARGUS_KEV_URL` | CISA feed URL | URL of the CISA Known Exploited Vulnerabilities JSON feed. |
| `ARGUS_EPSS_URL` | `https://api.first.org/data/v1/epss` | FIRST EPSS API. |
| `ARGUS_EOL_URL` | `https://endoflife.date` | endoflife.date base URL. |
| `ARGUS_NPM_REGISTRY_URL` | `https://registry.npmjs.org` | npm registry, or an internal proxy such as Artifactory or Azure Artifacts. |
| `ARGUS_NUGET_URL` | `https://api.nuget.org/v3-flatcontainer` | NuGet flat-container endpoint. |
| `ARGUS_DEPSDEV_URL` | `https://api.deps.dev` | [deps.dev](https://deps.dev) API, used for the latest version, deprecation and license of PyPI, Maven, Go and Cargo packages. |
| `ARGUS_NVD_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE API 2.0, used for CVSS scores that OSV does not provide. |
| `ARGUS_METRICS_TOKEN` | — | Enables Prometheus metrics at `/metrics`; scrapers send it as a bearer token. At least 16 characters. |
| `ARGUS_NVD_API_KEY` | — | Optional [NVD API key](https://nvd.nist.gov/developers/request-an-api-key). Raises NVD's rate limit from 5 to 50 requests per 30 seconds, so more scores are filled in per scan. Treat it as a secret. |
| `ARGUS_GRAPH_URL` | `https://graph.microsoft.com` | Microsoft Graph endpoint. Change it for sovereign clouds, e.g. `https://graph.microsoft.us` (GCC High). |
| `ARGUS_ENTRA_LOGIN_URL` | `https://login.microsoftonline.com` | Entra ID token endpoint, e.g. `https://login.microsoftonline.us`. |
| `HTTPS_PROXY` / `NO_PROXY` | — | Outbound proxy. Git uses it directly; also set `NODE_USE_ENV_PROXY=1` so API calls use it. |
| `NODE_EXTRA_CA_CERTS` / `GIT_SSL_CAINFO` | — | CA bundle for code hosts that use a private certificate authority (API calls and git respectively). |
| `ARGUS_WEB_DIR` | bundled | Directory containing the built web UI. |
| `PORT` | `8080` | HTTP port. |
| `WEBSITES_PORT` | — | Takes precedence over `PORT`. Set by Azure App Service. |
| `ARGUS_NEW_MASTER_KEY` | — | Only for the `rotate-master-key` command; see [Rotating the master key](deployment/docker.md#rotating-the-master-key). |
| `LOG_LEVEL` | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace` or `silent`. Logs are JSON on stdout. |

## In-app security settings

Under **Administration → Security settings**, visible to administrators and security managers, and editable by administrators:

| Setting | Default | Range |
|---|---|---|
| Require MFA for all users | off | — |
| Minimum password length | 12 | 8–128 |
| Required character classes | 3 | 1–4 |
| Lock after failed attempts | 5 | 3–50 |
| Lockout duration (minutes) | 15 | 1–1440 |
| Access token lifetime (minutes) | 15 | 5–60 |
| Session lifetime (days of inactivity) | 7 | 1–90 |

Every change is recorded in the audit log, with the before and after values.

## In-app scanning settings

Under **Administration → Scanning settings**:

- **Risk score adjustments.** These are the points added or removed for KEV, EPSS, public repositories, business criticality, dev and transitive dependencies, and test paths. See [risk score](features/scanners-and-findings.md#risk-score).
- **License policy.** SPDX ids that are not allowed (default: AGPL, GPL-2.0, GPL-3.0, SSPL, CPAL, OSL-3.0) or that need review (default: LGPL, MPL-2.0, EPL, CDDL, UNLICENSED).
- **Early warnings.**
  - Framework end-of-life warning: default 180 days.
  - Certificate and token expiry warning: default 30 days.
- **Secrets.** Live verification of detected secrets with their issuer (off by default), and how many recent commits to scan for secrets that were committed and later deleted (default 0: only the current code). See [Secrets: git history and live verification](features/scanners-and-findings.md#secrets-git-history-and-live-verification).
- **Threat-intelligence status.** When each source was last used, any errors, and whether Gitleaks is installed.

Changes apply from the next scan.

## System: branding and the configuration file

Under **Administration → System** (administrators):

- **Branding.**
  - The **product name** (default "Argus", up to 40 characters) is shown in the sidebar, on the sign-in page, in the browser tab, in email subjects (`[Contoso Security] …`) and footers, and as the label in authenticator apps for MFA set up afterwards.
  - An optional **sign-in notice** (plain text) is shown below the sign-in form, for example an acceptable-use statement.
- **Configuration file.** **Export settings** downloads a JSON file with the security, scanning, ticketing and SLA, retention, threat-intelligence and branding settings, plus the news sources.
  - The file **never contains secrets**: credentials, API keys, and email, webhook and Entra ID secrets stay encrypted in the installation that holds them.
  - It leaves out installation data: sources, repositories, users, teams and notification rules.
  - **Import settings…** replaces each section that is in the file and leaves the others untouched. News sources whose URL is already configured are skipped. The import is validated as a whole first: an invalid file changes nothing.
  - Use it to copy a configuration from a test installation to production, or to keep settings under version control.
  - Exports and imports are recorded in the audit log.
