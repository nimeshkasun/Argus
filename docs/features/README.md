# Features

Status legend: ✅ available · 🔜 planned (phase shown)

## Platform & administration

| Feature | Status | Docs |
|---|---|---|
| Local user accounts, default system administrator on a new database | ✅ | [User management](user-management.md) |
| Roles (Administrator, Security Manager, Developer, Viewer) and teams | ✅ | [User management](user-management.md) |
| Invite links with a preset role and teams, an expiry date, optional invited addresses (each emailed its own link) and a use limit | ✅ | [User management](user-management.md#invite-links) |
| TOTP multi-factor authentication, recovery codes, org-wide enforcement | ✅ | [User management](user-management.md#multi-factor-authentication) |
| Sign-in links by email (one-time, 15 minutes; MFA still applies) | ✅ | [User management](user-management.md#sign-in-links-by-email) |
| Password policy, account lockout, session management | ✅ | [Configuration](../configuration.md#in-app-security-settings) |
| Audit log with filtering and CSV export | ✅ | [User management](user-management.md#audit-log) |
| PostgreSQL or MongoDB storage | ✅ | [Architecture](../architecture.md#data-layer) |
| Single Docker image; Azure Web App support | ✅ | [Docker](../deployment/docker.md), [Azure](../deployment/azure.md) |
| Personal API tokens for CI/automation (scoped, expiring, default-deny) | ✅ | [API and automation](api-and-automation.md) |
| OpenAPI description generated from the code; Prometheus metrics | ✅ | [API and automation](api-and-automation.md) |
| In-app documentation (these guides, searchable) and a readable API reference | ✅ | [Documentation](../README.md) |
| Branding (product name, sign-in notice); configuration export and import without secrets | ✅ | [Configuration](../configuration.md#system-branding-and-the-configuration-file) |
| Data retention settings; master-key rotation tool; Azure Bicep template | ✅ | [Dashboards…](dashboards-and-reports.md#data-retention), [Docker](../deployment/docker.md#rotating-the-master-key), [Azure](../deployment/azure.md) |

## Sources & scanning

See [Sources, repositories and scans](sources-and-repositories.md).

| Feature | Status |
|---|---|
| GitHub (github.com and Enterprise Server, with a personal access token or as a GitHub App) and Bitbucket (Cloud and Data Center) connections, verified before saving, with daily and on-demand repository sync | ✅ |
| List repositories in a source and activate them individually or in bulk; auto-activate new repos matching a pattern | ✅ |
| Per-repository scan schedule (hourly, daily, weekly or custom cron), manual "Scan now", scan-on-push webhooks (HMAC-verified) | ✅ |
| Repository settings: branch, business criticality, owning team, Jira project, notification recipients | ✅ |
| Team-scoped visibility of repositories and scans | ✅ |
| Activity indicator for running and queued scans and other background work | ✅ |
| Scan runs: ephemeral shallow clone, commit, ecosystem and manifest inventory, log, history | ✅ |
| Per-repository choice of scanners | ✅ |
| `.argus.yml` repo-level configuration (ignore paths, scanner switches, suppressions) — see [Scanners and findings](scanners-and-findings.md#argusyml) | ✅ |
| **Secret detection** (Gitleaks, with built-in rules as a fallback) | ✅ |
| Live verification of detected GitHub, GitLab, Slack and npm tokens, AWS access keys and Azure Storage keys with their issuer (opt-in) | ✅ |
| Secrets in recent git history (configurable number of commits, opt-in) | ✅ |
| **npm vulnerabilities, deprecations and latest versions** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`) | ✅ |
| **NuGet vulnerabilities and latest versions** (`PackageReference`, central package management, `packages.lock.json`, `packages.config`) | ✅ |
| **PyPI, Maven/Gradle, Go and Cargo vulnerabilities, deprecations, latest versions and licenses** (`poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml`, `pom.xml`, `gradle.lockfile`, `build.gradle`, version catalogs, `go.mod`, `Cargo.lock`, `Cargo.toml`) | ✅ |
| **Framework / runtime end-of-life** (.NET, .NET Framework, Node.js, Angular, React, Vue, Next.js, NestJS) | ✅ |
| **Certificate and credential expiry** (certificates, weak keys, key stores and expiring JWTs in repositories) | ✅ |
| **Code weaknesses (static analysis)** with Opengrep and the community security rules (bundled), or your own rules | ✅ |
| **Infrastructure-as-code misconfigurations** (Terraform, Kubernetes, Helm, Dockerfiles, CloudFormation, Azure ARM) with Trivy | ✅ |
| **Container image vulnerabilities** for images referenced in Dockerfiles, Compose and Kubernetes manifests, with Trivy (opt-in) | ✅ |
| License compliance policy: not allowed, needs review and always-allowed licenses, an allow-list-only mode, and approved packages (also from a finding) | ✅ |
| NuGet license data (from package .nuspec files) | ✅ |
| CycloneDX SBOM per repository; organisation-wide package search | ✅ |
| **Pull request scans from CI** (GitHub Actions, Bitbucket Pipelines, any CI): only issues the pull request introduces, a severity gate for the build, and one self-updating comment on the pull request with fixes — see [Pull request scans](pull-request-scans.md) | ✅ |
| AI fix suggestions on pull request comments (opt-in) | ✅ |
| Credential inventory (tracked secrets with expiry notices; Microsoft Entra ID app secrets and certificates imported daily) — see [Dashboards, reports and credentials](dashboards-and-reports.md#credential-inventory) | ✅ |

## Risk & tickets

| Feature | Status |
|---|---|
| Findings with open, suppressed and fixed states, automatic fix detection and re-opening, and suppressions with justification and expiry — see [Scanners and findings](scanners-and-findings.md) | ✅ |
| 0–100 explainable risk score combining CVSS, EPSS, CISA KEV, dependency type, test paths, exposure and repository criticality; configurable weights | ✅ |
See [Tickets, email, Jira and notifications](tickets-and-notifications.md).

| Built-in tickets (one per issue) with statuses Open, Triaged, In progress, Resolved, Closed, Risk accepted, False positive and Reopened | ✅ |
| Automatic resolution when a later scan no longer finds the issue, and automatic re-opening if it returns | ✅ |
| SLA due dates by severity, overdue flagging, assignment, watchers, labels, comments, activity timeline, bulk actions, CSV export, saved (and shared) views | ✅ |
| Risk acceptance and false positives backed by ticket-scoped, optionally expiring suppressions | ✅ |
| Email from a ticket via Microsoft Graph, Microsoft 365 SMTP (OAuth2 or password) or Google SMTP | ✅ |
| Create a Jira issue from a ticket (Jira Cloud or Data Center, in the project linked to the repository), with status sync | ✅ |
| Notification rules: email, Microsoft Teams (Adaptive Cards), Slack, signed webhooks; weekly digests | ✅ |

## AI

See [AI assistance](ai-assistance.md).

| Feature | Status |
|---|---|
| Choice of provider (Anthropic Claude, OpenAI, Google Gemini), configured by an administrator, with optional private endpoints and per-feature routing | ✅ |
| AI remediation suggestions on tickets (regenerate, post as comment) | ✅ |
| AI drafting of Jira issues and ticket emails | ✅ |
| AI triage during scans: likely false-positive secrets, and whether a vulnerable package is used in an affected way | ✅ |
| Guardrails: secret redaction, context cap, per-repository opt-out, schema-validated answers, usage and cost tracking with a monthly budget, audit; see [security](../security.md#7-ai-guardrails) | ✅ |

## Threat intelligence

See [Threat intelligence](threat-intelligence.md).

| Feature | Status |
|---|---|
| Advisory sources: OSV.dev (including the GitHub Advisory Database), CISA KEV, FIRST EPSS, endoflife.date, with database caching, stale fallback, configurable mirrors and offline mode | ✅ |
| NVD as an additional CVSS source, for CVEs whose OSV record has no score | ✅ |
| Security news feeds (RSS/Atom), with AI extraction of package advisories into a review queue (optional auto-approval) | ✅ |
| Argus advisories: approved from news or entered by hand, matched by every scan | ✅ |
| Continuous re-matching of new advisories against every repository's stored dependency inventory, without re-scanning; emerging-threat notifications | ✅ |

## Reporting

| Feature | Status |
|---|---|
| Organisation, team and repository dashboards (risk trend, found vs fixed, MTTR, SLA compliance, riskiest repositories, expiring credentials, EOL exposure) | ✅ |
| Report as PDF download and printable page, findings CSV export, monthly report by email with the PDF attached | ✅ |
| Prometheus metrics, OpenAPI documentation | ✅ |

See [Dashboards, reports and credentials](dashboards-and-reports.md).

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0. Foundation | Monorepo, PostgreSQL and MongoDB data layer, authentication with MFA, roles and teams, audit log, web UI shell, Docker, CI, documentation | ✅ |
| 1. Sources & scheduling | GitHub and Bitbucket connectors, repository activation, job queue, scheduler, scan runs, push webhooks | ✅ |
| 2. Scanners & risk | Advisory sources, all scanners, findings, risk scoring, SBOM, package search, suppressions | ✅ |
| 3. Tickets & integrations | Ticket lifecycle, SLAs, email providers, Jira, notification rules, digests | ✅ |
| 4. AI | Providers, triage, remediation, drafting, guardrails | ✅ |
| 5. Threat intel | News crawler, AI extraction, review queue, Argus advisories, continuous re-matching, NVD | ✅ |
| 6. Enterprise polish | Dashboards, reports, credential inventory, API tokens, metrics, OpenAPI, retention, key rotation, NuGet licenses, secret verification, Azure Bicep | ✅ |
