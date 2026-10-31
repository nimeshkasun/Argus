# OWASP ASVS 5.0 self-assessment

This page maps Argus against the [OWASP Application Security Verification Standard 5.0.0](https://github.com/OWASP/ASVS/tree/master/5.0/en) (May 2025), chapter by chapter.

**What this is:**
- It is a **self-assessment by the maintainers**, aimed at **Level 2** ("most applications should be striving to achieve this level").
- It is **not** an independent verification or a certification. No external penetration test has been done yet.
- Each row names the controls Argus uses and links to where they are described. Gaps are listed openly at the end, so that operators can weigh them.

Status: ✅ in place · ◐ partly in place (see the gaps) · — not applicable.

| Chapter | Status | How Argus addresses it |
|---|---|---|
| **V1 Encoding and Sanitization** | ✅ | React escapes all rendered text, and no HTML from users or feeds is rendered as markup. Emails are HTML-escaped value by value, and subjects are stripped of line breaks (header injection). CSV exports neutralise spreadsheet formulas. The PDF writer escapes PDF string syntax. Untrusted XML (RSS/Atom feeds, `.nuspec`, `.csproj`) has its DOCTYPE stripped before parsing (XXE). YAML (`.argus.yml`) is parsed with an alias limit. Data access goes through Kysely's parameterised queries or the MongoDB driver's typed filters; search terms are escaped for `LIKE` and regular expressions. Git is run with argument arrays, never a shell. |
| **V2 Validation and Business Logic** | ✅ | Every API input is validated with a zod schema (types, ranges, lengths, enums) before a handler runs, and invalid requests change nothing. Business rules are enforced on the server: the ticket status state machine, risk acceptance needing a justification and an expiry, SLA dates, and per-list limits (e.g. 50 saved views). Rate limits apply globally, to sign-in, and to actions that call third parties or AI providers. |
| **V3 Web Frontend Security** | ✅ | A strict Content-Security-Policy (`default-src 'self'`, no inline scripts or styles, `object-src 'none'`, `frame-ancestors 'none'`) is enforced and checked by the browser tests, which fail on any CSP violation. Helmet's headers are set (no sniffing, referrer policy, and so on). HSTS is sent when served over HTTPS. Cookies are `HttpOnly`, `SameSite=Strict` and `Secure` behind HTTPS. State-changing requests also carry a double-submit CSRF token. |
| **V4 API and Web Service** | ✅ | One versioned REST API (`/api/v1`). Its OpenAPI description is generated from the running code, including each endpoint's required permissions. Endpoints are default-deny for API tokens: a token reaches only endpoints that declare permissions within its scopes. Request bodies are limited in size. Webhooks are verified with HMAC-SHA256 in constant time, and outbound webhooks are signed with a timestamp against replay. |
| **V5 File Handling** | ✅ | Argus accepts no file uploads that it stores. The settings import is JSON, validated as a whole. Repository content is read from an ephemeral clone with size caps, symlinks checked out as plain files, and binary detection; the clone is deleted after every scan. Downloads (CSV, PDF, SBOM) carry explicit content types and `attachment` dispositions. |
| **V6 Authentication** | ◐ | Passwords are hashed with argon2id, and unknown accounts get the same timing and response as known ones. Accounts lock after repeated failures. Optional or enforced TOTP MFA. Forced password change for administrator-set passwords. Changing a password revokes every session. No default credentials: the first administrator password comes from configuration or is generated. Personal API tokens are random 256-bit values, stored as keyed hashes. See the gaps on password checks and phishing-resistant MFA. |
| **V7 Session Management** | ◐ | Short-lived access tokens (5–60 minutes) with rotating refresh tokens. Reuse of an old refresh token revokes the whole session family. Sessions end after a configurable period of inactivity, at sign-out, at password change and when an account is disabled. Session tokens are never placed in URLs. See the gaps on absolute session lifetime and on revoking access tokens. |
| **V8 Authorization** | ✅ | Role-based permissions (Admin, Security Manager, Developer, Viewer) are checked on the server for every endpoint. Team scoping limits Developers and Viewers to their teams' repositories, findings, tickets and reports, and returns *404* for anything outside them. API tokens are limited to the intersection of their scopes and the owner's current role. Saved views store filters only, so access is decided again for each viewer. |
| **V9 Self-contained Tokens** | ◐ | JWTs are HMAC-signed (HS256 only) with a key derived from the master key (HKDF). They are checked for signature, algorithm, issuer, audience (`argus:access`, `argus:mfa`) and expiry. The user is reloaded on every request, so disabling an account, changing a role or changing the password takes effect immediately. GitHub App JWTs are short (under ten minutes) and used only towards GitHub. See the gap on revoking access tokens. |
| **V10 OAuth and OIDC** | — | Argus does not act as an OAuth authorisation server or relying party: accounts are local by design. As an OAuth *client*, it uses the client-credentials flow only for Microsoft Graph and SMTP OAuth2. Those secrets are encrypted and write-only. |
| **V11 Cryptography** | ✅ | Stored credentials are encrypted with AES-256-GCM using a key derived from `ARGUS_MASTER_KEY`. A rotation tool re-encrypts everything. Detected secrets are stored only as an HMAC-SHA256 under an installation key, plus a masked preview. Random values come from the operating system CSPRNG. Comparisons of secrets (webhook signatures, metrics token) are constant-time. No custom cryptographic algorithms. |
| **V12 Secure Communication** | ◐ | Outbound calls require HTTPS, except loopback addresses for development. Redirects are refused wherever a credential is sent, so credentials cannot be bounced to another host. SMTP requires TLS 1.2+ (implicit or STARTTLS, never plain). Inbound TLS is terminated by the platform (Azure App Service is HTTPS-only with TLS 1.2+) or by your reverse proxy. See the gap on administrator-configured URLs. |
| **V13 Configuration** | ✅ | All configuration is validated at start-up, failing fast with clear messages. Secrets are read from the environment (Key Vault references on Azure), never from the repository. The container runs as a non-root user with a minimal runtime image: no npm, and Gitleaks and Trivy built from pinned source. CI runs `npm audit` and a Trivy image scan. The settings export never contains secrets. Errors returned to clients carry no stack traces or internal details. |
| **V14 Data Protection** | ✅ | Source code is never stored, and clones are deleted after each scan. Detected secrets are never stored in full; the Gitleaks report is deleted immediately. Secrets are redacted before any AI prompt, with a per-repository AI opt-out and a cap on context size. The API never returns stored credentials, only "configured" plus a hint. Retention periods are configurable for scan logs, fixed findings, news items, AI usage and the audit log. |
| **V15 Secure Coding and Architecture** | ✅ | Dependencies are pinned through a lockfile and audited in CI, and the image is scanned. The design is documented in [architecture](architecture.md) and [security](security.md). The data layer runs one contract test suite against both databases. End-to-end tests cover security behaviour (permissions, CSRF, token scopes, redaction), and the browser tests check the CSP. Background jobs are idempotent with de-duplication keys. |
| **V16 Security Logging and Error Handling** | ✅ | An append-only audit log records sign-ins, failures, lockouts, MFA changes, administration, configuration changes, exports, token use and ticket changes, with actor, time and IP. Prompts and secret values are never logged; structured JSON logs redact credentials, cookies and authorization headers. Errors are logged on the server and returned to clients as generic messages. |
| **V17 WebRTC** | — | Argus uses no WebRTC. |

## Gaps and recommendations

These are known differences from Level 2, recorded so that they can be planned or accepted:

1. **Password checks (V6).**
   - ASVS 5.0 recommends checking new passwords against common or breached passwords. Argus does not yet do this.
   - ASVS discourages composition rules. Argus uses them by default (3 of 4 character classes); an administrator can set *Required character classes* to 1 and rely on length.
2. **Phishing-resistant MFA (V6).** Only TOTP is supported. Passkeys/WebAuthn are not.
3. **Absolute session lifetime (V7).** Sessions end after inactivity, but there is no absolute maximum: an active session refreshes indefinitely.
4. **Revoking access tokens (V7 / V9).**
   - Signing out or revoking a session stops its refresh token at once.
   - The short-lived access token is not checked against the session, so it stays usable until it expires: at most the configured *Access token lifetime*, 15 minutes by default.
   - Disabling the user, or changing their password, does stop it immediately.
5. **Outbound requests to private addresses (V12 / SSRF).**
   - Administrator-configured URLs are not checked against private or link-local address ranges. These are the GitHub Enterprise and Bitbucket Data Center URLs, news feeds, webhooks, Jira and email endpoints, and they legitimately often point to internal servers.
   - Mitigations: only administrators can set them, HTTPS is required, redirects are refused and timeouts apply.
   - If your network policy needs it, restrict the container's egress at the network layer.
6. **Independent verification.** No third-party penetration test or code audit has been done yet.

Last reviewed: October 2026, against ASVS 5.0.0.
