# Security model

For a chapter-by-chapter mapping against OWASP ASVS 5.0, including known gaps, see the [ASVS self-assessment](asvs-checklist.md).

Argus holds some of the most sensitive data in an engineering organisation: source-control tokens, findings about leaked secrets, and the vulnerability map of every repository. This page describes how Argus protects that data.

Each control is labelled:

- **✅ Implemented**: built and covered by automated tests.
- **🔜 Phase *N***: a design commitment for a feature that is not built yet. It becomes ✅ when that phase ships.

If you find a vulnerability, please report it privately to the maintainers rather than opening a public issue.

---

## 1. Secrets and credentials at rest

| Control | Status |
|---|---|
| **One master key.** Everything sensitive is protected by keys derived from `ARGUS_MASTER_KEY` (at least 32 characters). HKDF-SHA256 derives a separate sub-key for each purpose (encryption, token signing, keyed hashing), so no key is reused across algorithms. | ✅ |
| **Authenticated encryption.** Stored secrets are encrypted with AES-256-GCM, using a fresh random 96-bit IV per value and a versioned envelope (`v1.iv.tag.ciphertext`). Any tampering is detected on decryption. This covers TOTP secrets, source-control tokens, webhook secrets, integration credentials and AI provider keys. | ✅ |
| GitHub and Bitbucket access tokens and per-source webhook secrets are stored with this encryption. | ✅ |
| SMTP passwords, Microsoft Graph and OAuth2 client secrets, Teams/Slack webhook URLs, webhook signing secrets and Jira tokens are stored with the same encryption, and are write-only: the API shows only a hint (`••••abcd` or the webhook host). | ✅ |
| AI provider keys (Anthropic, OpenAI, Gemini) are stored with the same encryption and are write-only (`••••abcd`). They are sent only to the provider's configured endpoint, never logged, and redacted from any error message. | ✅ |
| **Master-key rotation** (`rotate-master-key` CLI) re-encrypts every stored credential with a new key and keeps keyed hashes valid; it is idempotent and reports anything it cannot decrypt. See [Docker deployment](deployment/docker.md#rotating-the-master-key). | ✅ |
| **Credential inventory** records what a credential is, its owner and expiry, never its value. The Microsoft Entra ID import secret is encrypted and write-only, and Graph paging links are followed only on the Graph host. | ✅ |
| **Write-only credentials.** The API never returns a stored credential; for source tokens it shows only the last four characters (`••••abcd`). Changing a token or connection setting re-tests the connection before saving. A webhook secret is shown once, when it is created or rotated. | ✅ |
| **Detected secrets are never stored in full.** A leaked secret found in a repository is kept only as a masked preview (for example `AKIA…MPLE`; private keys show only "PEM private key") plus an HMAC-SHA256 hash, keyed by this installation, which is used to recognise the same secret across files and scans. Gitleaks' raw report is deleted as soon as it has been read. Argus never becomes a second copy of your leaked secrets. | ✅ |
| Passwords are hashed with **argon2id** (19 MiB memory, 2 iterations; the OWASP recommendation). They are never stored reversibly or logged. | ✅ |
| Refresh tokens and MFA recovery codes are stored only as keyed HMAC-SHA256 hashes. | ✅ |

> **Protect and back up `ARGUS_MASTER_KEY`.** Without it, encrypted credentials and MFA enrollments cannot be recovered. Store it in a secret manager (for example as an Azure Key Vault reference), never in source control.

## 2. Authentication

| Control | Status |
|---|---|
| Local accounts with a configurable **password policy** (default: at least 12 characters, 3 of 4 character classes, must not contain the username). The same policy code runs in the browser for live feedback and on the server for enforcement. | ✅ |
| **Default administrator.** On a fresh database, Argus creates `admin` with a password from `ARGUS_ADMIN_PASSWORD`, or generates a strong one and logs it **once**. The password **must be changed at first sign-in**. | ✅ |
| **Every admin-set password is temporary.** Users created or reset by an administrator must choose their own password before they can do anything else. | ✅ |
| **Account lockout** after N consecutive failures (default: 5 failures, 15 minutes). Failed MFA codes and failed "current password" checks count too. Administrators can unlock accounts. | ✅ |
| **Username enumeration resistance.** Unknown and disabled accounts get the same error, and an argon2 verification still runs against a dummy hash so response times match. | ✅ |
| **TOTP multi-factor authentication** (RFC 6238; works with Microsoft Authenticator, Google Authenticator, 1Password and others). | ✅ |
| **TOTP replay protection.** A code that has already been accepted cannot be used again, even within its 30-second window. | ✅ |
| **Recovery codes:** 10 single-use codes, shown once and stored as keyed hashes. | ✅ |
| **Organisation-wide MFA enforcement.** When enabled, users without MFA must enroll before doing anything else, and they cannot turn MFA off. | ✅ |
| Per-IP **rate limiting** on credential endpoints (`ARGUS_AUTH_RATE_LIMIT`, default 10 per minute). | ✅ |
| **Personal API tokens** for CI and automation: random 256-bit tokens with a recognisable prefix (`argus_pat_`), shown once and stored only as a keyed hash; chosen scopes, always limited to the owner's current role; mandatory expiry (7–365 days); revocable by the owner or an administrator; last use (time and IP) recorded. | ✅ |
| **Sign-in links by email** (off by default) replace only the password: users with MFA still enter their code. Each link carries a random 256-bit token in the URL fragment, stored only as a keyed hash; it works once, expires after 15 minutes, and a newer link cancels older ones (at most one per account per minute). The request endpoint answers the same way, equally fast, whether or not the account exists, and shares the sign-in rate limit. Links are only built from `ARGUS_PUBLIC_URL`, never from the request's Host header, so a forged request cannot point a link at another site. | ✅ |
| **Invite links** carry a random 256-bit token in the URL fragment (`/invite#…`), which browsers never send to the server, so it stays out of server and proxy logs. Only a keyed hash is stored. Links expire (at most 365 days), have a use limit taken atomically, can be limited to a list of email addresses (each usable once) and revoked at any time. Emailing a link needs the token from the administrator's browser, since the server never keeps it. Unknown, used, expired and revoked links all get the same answer, and the lookup and sign-up endpoints share the sign-in rate limit. Only signed-in administrators (not API tokens) can create them. | ✅ |
| **API tokens are default-deny.** They only reach endpoints that declare the permissions they need, and are refused on sign-in, MFA, password and token-management endpoints, so a leaked token cannot mint or hide other tokens. A token stops working when its owner is disabled or must change their password or enrol in MFA. | ✅ |

## 3. Sessions

| Control | Status |
|---|---|
| **Short-lived access tokens** (HS256 JWT, default 15 minutes) in an **HttpOnly, SameSite=Strict** cookie. JavaScript cannot read them. | ✅ |
| **Rotating refresh tokens** (opaque, 256-bit) in an HttpOnly cookie scoped to `/api/v1/auth`. Each use issues a new token and revokes the old one. | ✅ |
| **Refresh-token reuse detection.** Presenting an already-rotated refresh token revokes the whole session family and is audited as possible token theft. | ✅ |
| **CSRF protection.** On top of SameSite=Strict cookies, every state-changing request that carries a session must echo a double-submit token in the `X-CSRF-Token` header. | ✅ |
| **Immediate revocation:**<br>• Disabling a user, resetting their password or resetting their MFA signs out all of their sessions at once.<br>• Access tokens issued before a password change stop working.<br>• Role changes take effect on the next request, because the user is reloaded on every request. | ✅ |
| `Secure` cookies and HSTS are enabled automatically when `ARGUS_PUBLIC_URL` uses `https://`. | ✅ |

## 4. Authorisation

| Control | Status |
|---|---|
| **Role-based access control** with four roles: Administrator, Security Manager, Developer and Viewer. Each endpoint declares the permissions it needs, and the server checks them on every request. The UI hides what you cannot do, but the server is the authority. | ✅ |
| **Team scoping.** Developers and Viewers only see repositories, scan runs, findings, dependency inventories, package-search results and suppressions owned by their teams. Anything outside their teams returns *404 Not found* rather than *403*, so its existence is not revealed. When a repository moves to another team, its findings, inventory and scan history move with it. Tickets follow the same rule from Phase 3. | ✅ |
| **Suppressing findings needs triage rights** (Administrator or Security Manager). Every suppression carries a justification and an optional expiry, and is audited. | ✅ |
| **Tickets follow team scoping.** Developers can work tickets of their teams and assign them only to themselves. Closing a ticket, accepting a risk or marking a false positive needs triage rights. Risk acceptance creates an audited, optionally expiring suppression for exactly that issue. | ✅ |
| **Self-lockout and last-admin protection.** Administrators cannot disable themselves or change their own role, and the last active administrator cannot be removed. | ✅ |

## 5. Audit trail

| Control | Status |
|---|---|
| Append-only **audit log** of security-relevant events: sign-ins (success and failure, with reason), lockouts, password changes and resets, MFA changes, user and team changes, settings changes, audit exports, and refresh-token reuse. | ✅ |
| Each entry records the actor, target, outcome, source IP and structured details. **Secrets are never written to the audit log.** | ✅ |
| CSV export is protected against spreadsheet formula injection (cells beginning with `=`, `+`, `-` or `@` are neutralised). | ✅ |
| Source changes are audited: creation, edits (including token rotation), deletion, webhook-secret rotation, sync requests and sync results. So are repository setting changes, bulk changes, and manual scan requests. | ✅ |
| Suppression creation and removal, SBOM exports and scanning-settings changes are audited, with before and after values for settings. | ✅ |
| API token creation and revocation, report exports, credential inventory changes, Entra imports, retention runs and retention-settings changes are audited. | ✅ |
| Threat-intelligence actions are audited: news source changes, review decisions (including automatic approvals), Argus advisory creation, withdrawal and restoration, and intel settings changes. | ✅ |
| Ticket actions (status changes with justification, assignment, labels, emails sent, Jira issues created, exports) are recorded both in the ticket's activity and in the audit log. So are changes to channels, notification rules, Jira and SLA settings. | ✅ |
| AI actions are audited: every provider request (`ai.request`: use case, provider, model, repository, token counts, estimated cost, number of redactions, outcome), AI settings changes (including which keys changed, never the keys) and connection tests. Prompt and answer contents are never audited or logged. | ✅ |

## 6. Source-code handling

| Control | Status |
|---|---|
| Repositories are **shallow-cloned into an ephemeral directory** (`ARGUS_SCAN_WORKDIR/<run id>`) for the duration of a scan and **always deleted afterwards**, including when the scan fails. Source code is never stored in the database. | ✅ |
| **Tokens never appear in URLs or command lines.** Git receives the credential as an HTTP header through its environment (`GIT_CONFIG_*`), so it cannot leak through process listings, git error messages or a stored remote URL. | ✅ |
| **Clone-host allowlist.** Before any credential is attached, a clone URL must use HTTPS and point to the source's own host (for example github.com, bitbucket.org, or your server). A tampered or unexpected clone URL is refused. | ✅ |
| **API calls are pinned to the configured server.** Pagination links returned by a provider are followed only if they stay on the same origin, so a token is never sent to another host. Redirects are not followed. | ✅ |
| **Hardened git.** Git runs with: <br>• no user or system git configuration<br>• no interactive prompts<br>• HTTPS/HTTP transports only<br>• symbolic links checked out as plain files<br>• Git LFS downloads disabled<br>• no submodules or tags<br>• a timeout (`ARGUS_SCAN_TIMEOUT_MINUTES`)<br>Repository hooks are never executed. | ✅ |
| **Redacted scan logs.** Scan logs and error messages are scrubbed of the token, the authorisation header and any `user:password@` URL credentials before they are stored or shown. | ✅ |
| Source servers must use **HTTPS**. Plain HTTP is accepted only for loopback addresses (local development). | ✅ |
| Only findings and the dependency inventory (package names, versions and licenses, for SBOMs and package search) are persisted. File contents are not stored; a finding records only its path and line. | ✅ |
| **Untrusted repository content is parsed defensively.**<br>• XML (`.csproj`, `packages.config`, `pom.xml`) is parsed without DTDs or external entities.<br>• YAML (`pnpm-lock.yaml`, `yarn.lock`, `.argus.yml`) is parsed with alias-expansion limits.<br>• TOML (`Cargo.lock`, `poetry.lock`, `pyproject.toml`) is parsed as data only.<br>• Files are read with size caps, and binary files are skipped.<br>• Symbolic links are never followed.<br>• Nothing from a repository is ever executed. | ✅ |
| **Threat-intelligence lookups never send code or secrets.** OSV, deps.dev and the npm/NuGet registries receive package names and versions, EPSS and NVD receive CVE ids, and endoflife.date receives product names. The full list is in [Data sources](features/scanners-and-findings.md#data-sources-caching-and-offline-mode). `ARGUS_OFFLINE=true` turns all of these lookups off, and each URL can point at an internal mirror. | ✅ |
| **Security news is fetched defensively.** Feeds must be HTTPS, redirects to plain HTTP are refused, responses are capped at 5 MB and 200 entries, XML is parsed without DTDs or external entities, and HTML (including scripts) is reduced to plain text before it is stored, shown or sent to AI. Links are kept only if they are http(s). | ✅ |
| **Git-history secret scanning is opt-in** and limited to a configured number of recent commits. History is read from the same ephemeral clone, which is deleted after the scan. | ✅ |
| **GitHub App sources** keep only the app's private key (encrypted). Argus mints installation tokens that expire within an hour, holds them in memory only, and redacts them from scan logs. JWTs are valid for under ten minutes. | ✅ |
| **Live secret verification is opt-in** (off by default). When enabled, a detected GitHub, GitLab, Slack or npm token, AWS access key or Azure Storage account key is sent only to its own issuer's official API, in one read-only request, with redirects refused and nothing logged; at most 25 per scan. AWS and Azure requests are signed locally (SigV4 / Shared Key), so the secret key itself never leaves Argus; they call STS `GetCallerIdentity` and the blob service's *Get Service Properties*, which read no data. | ✅ |
| **Continuous re-matching never clones.** It reads the stored dependency inventory (package names and versions) and asks OSV and NVD about package versions and CVE ids only. | ✅ |
| The bundled **Gitleaks and Trivy are built from pinned source** when the image is built: the release's exact commit (verified), a current Go toolchain pinned by image digest, and patched Go modules pinned by version and verified against the Go checksum database. Upstream release binaries are not used because they carry CVEs from their older toolchain. | ✅ |
| **Code, infrastructure and image scanners run without a shell.** Opengrep and Trivy are started directly with fixed arguments, in the scan's temporary checkout, with a time limit; their reports are deleted after reading. Code findings never store the matched code (it may contain secrets), only a hash of it. The bundled Trivy is built from pinned source like Gitleaks (below); Opengrep is the official release binary, verified against a pinned SHA-256 checksum; and the rules are pinned to a commit. | ✅ |
| **Pull request scans trust nothing from the caller.** The pipeline names a repository and a pull request number, with an API token that needs `scans:run` and is limited to what its owner can see. Argus reads the pull request's commit, branches and changed files from the provider with the source's own credentials, and fetches the code from the provider's hosts only. Their findings are a preview and never change the repository's findings or tickets. | ✅ |
| **Pull request comments are injection-safe.** File names and finding text come from the pull request (possibly from a fork), so they are escaped: no links, images, HTML or @mentions can be added through them, code is fenced so it cannot break out, and only http(s) reference links are shown. The comment never contains secret values. | ✅ |
| **Container image scanning is opt-in** (off by default). When on, the images a repository names are pulled from their registries by Trivy; no repository content is sent anywhere. Registry credentials, if needed, are Trivy's own environment variables and never stored by Argus. | ✅ |
| **Lean runtime image.** npm, npx, corepack and Yarn, which ship with the Node base image but are never used at runtime, are removed. CI fails the build on any fixable high or critical vulnerability found by Trivy. | ✅ |
| **Read-only tokens are enough.** The [sources guide](features/sources-and-repositories.md#access-tokens) lists the minimum permissions for each provider. | ✅ |

## 7. AI guardrails

AI features are optional and switched off until an administrator configures a provider (Anthropic Claude, OpenAI or Google Gemini). Every request goes through one gateway (`AiService`) that applies all of the controls below; no feature can call a provider directly. Details: [AI assistance](features/ai-assistance.md).

| Control | Status |
|---|---|
| **Secrets are always redacted before any prompt is sent.** The detected secret value itself, private key blocks, URL credentials and `Authorization` headers, every pattern of Argus's secret detector, credential-like assignments and long random-looking tokens are replaced with `[REDACTED:…]` markers before text leaves Argus. Secret triage never sends the value, only its characteristics (length, entropy, character classes). | ✅ |
| **Minimal context.** Remediation and drafting send ticket and finding facts, not source code. Scan triage sends only a few lines around a finding or around imports of a vulnerable package. Every prompt is capped at the configured context limit (default 12,000 characters). | ✅ |
| **Per-repository opt-out.** A repository with *Allow AI assistance* turned off is never sent to a provider, by any feature. | ✅ |
| **Per-use-case switches** (remediation, drafting, secret triage, vulnerability applicability), each routable to a chosen provider. Token usage and estimated cost are recorded per request, and requests stop once the monthly budget cap is reached. | ✅ |
| **Humans decide.** AI output is always labelled *AI-assisted* with the model and its reasoning. AI can suggest a fix or flag a likely false positive, but it **never changes a ticket's status, suppresses a finding or alters a risk score**. Drafts are only filled into a form for a person to edit and send. | ✅ |
| **Strict output validation.** Providers are asked for JSON matching a schema, and every answer is validated again in Argus (required fields, ranges, allowed verdicts). Anything else is discarded and counted as a failure. | ✅ |
| **Prompt-injection mitigation.** Repository and advisory content is wrapped in tags, and the model is told to treat it as untrusted data and not follow instructions in it. Since this cannot be guaranteed, AI output is advisory only (see *Humans decide*). | ✅ |
| **Hardened provider calls.** Custom endpoints must be HTTPS (plain HTTP only on loopback), redirects are refused for OpenAI and Gemini, and requests time out after 2 minutes. `ARGUS_OFFLINE=true` blocks the providers' public APIs; only a configured private endpoint stays usable. Generating suggestions and drafts is rate-limited (10/min per client). | ✅ |
| Every AI request is audited (see [Audit trail](#5-audit-trail)); prompt and answer contents are not logged. | ✅ |
| **AI extraction of advisories from security news** sees only the news item (title, link, text), never repository content. Proposals land in a review queue; auto-approval is off by default and, when enabled, only applies above a confidence threshold and is audited. Proposals with unparseable version ranges or malformed CVE ids are dropped before review. | ✅ |

## 8. Platform hardening

| Control | Status |
|---|---|
| **Strict Content Security Policy** (`default-src 'self'`, no inline scripts, `frame-ancestors 'none'`), plus `X-Content-Type-Options`, a Referrer-Policy and the other Helmet defaults. | ✅ |
| Request bodies are limited to 1 MB (25 MB for signed push webhooks, which can be large) and validated against schemas. Unknown fields are stripped. | ✅ |
| **Structured logs never contain credentials.** Cookies, `Authorization` headers, CSRF tokens and `Set-Cookie` headers are redacted. Request bodies are not logged. | ✅ |
| Configuration is validated at startup, and a misconfigured instance refuses to start. | ✅ |
| The container runs as a **non-root user**, with `tini` as PID 1 and a health check. | ✅ |
| **Dependency hygiene.** CI fails on high or critical `npm audit` findings in production dependencies, and the image is scanned with Trivy. | ✅ |
| **Inbound push webhooks are authenticated** with an HMAC-SHA256 signature (`X-Hub-Signature-256` / `X-Hub-Signature`) over the raw request body, using a per-source random secret. Signatures are compared in constant time, and unsigned or mis-signed calls are rejected with 401. | ✅ |
| Source-connection tests have their own rate limit (20/min), so Argus cannot be used to amplify requests to third-party APIs. | ✅ |
| **Outbound webhooks are HMAC-signed** (`X-Argus-Signature` over timestamp and body), so receivers can verify origin and reject replays. | ✅ |
| **Outbound calls to configured services are hardened.**<br>• Graph, Entra ID, Jira, Teams, Slack and webhooks: HTTPS only (plain HTTP only on loopback), redirects refused so a credential never follows a redirect elsewhere, 15-second timeouts.<br>• Email: TLS 1.2+ only.<br>• Errors shown to administrators are redacted of secrets. | ✅ |
| **Notification content is escaped for each format.**<br>• HTML email escapes every value.<br>• Subjects are single-line, preventing header injection.<br>• Slack text escapes `&`, `<` and `>` so values cannot inject links or mentions.<br>• Jira descriptions use Atlassian Document Format text nodes. | ✅ |
| **Prometheus metrics are off by default** and, when enabled, require their own bearer token (`ARGUS_METRICS_TOKEN`), compared in constant time; sessions and API tokens do not grant access. Metrics contain counts only. | ✅ |
| **Configuration exports contain no secrets.** The settings file holds policies and news-source URLs only; stored credentials never leave the installation, and importing a file cannot set a secret. Exports and imports need *settings:manage* and are audited. | ✅ |
| The **branding** product name is validated (no markup or control characters) and HTML-escaped wherever it appears, including emails. | ✅ |
| **Data retention** is configurable (scan runs, fixed findings, audit log, news items, AI usage); the audit log is kept forever unless an administrator chooses otherwise. | ✅ |
| **Azure template defaults are hardened:** HTTPS only, TLS 1.2+, FTP disabled, secrets in Key Vault (RBAC, purge protection) read through the web app's managed identity with the least-privilege *Key Vault Secrets User* role, logs to Log Analytics. | ✅ |
| Actions that call third parties (email, Jira, channel tests, AI requests) are rate-limited per client. A failing third party returns HTTP 502 with a redacted, human-readable message. | ✅ |

## 9. Operator checklist

1. Generate a strong `ARGUS_MASTER_KEY` (`openssl rand -base64 48`), keep it in a secret store, and back it up.
2. Serve Argus over HTTPS and set `ARGUS_PUBLIC_URL=https://…`.
3. Sign in as `admin` immediately and set a new password. Then enable MFA and consider **Require MFA for all users**.
4. Create named administrator accounts for real people, and use `admin` only for break-glass access.
5. Restrict database network access to the Argus containers only, and enable encryption at rest on the database.
6. Review the audit log regularly, or export it to your SIEM.
7. Enable Prometheus metrics only with a long random `ARGUS_METRICS_TOKEN`, and give CI pipelines API tokens with the fewest scopes and the shortest lifetime that work.
8. Rotate `ARGUS_MASTER_KEY` if it may have been exposed (see [Docker deployment](deployment/docker.md#rotating-the-master-key)).
9. If you enable AI assistance, set a monthly budget, turn on only the features you need, and clear **Allow AI assistance** on repositories whose code must not leave your network. Prefer a provider account or gateway that does not retain or train on API data.
