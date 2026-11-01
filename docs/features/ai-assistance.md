# AI assistance

Argus can use a large language model to help people act on findings faster:

- **Remediation suggestions** on tickets: step-by-step fix guidance, the fixed version, and the risk of breaking changes.
- **Jira and email drafting**: fills in the Jira issue or email form from the ticket, for you to edit before sending.
- **Secret triage** during scans: flags detected secrets that look like test fixtures, documentation examples or placeholders.
- **Vulnerability applicability** during scans: judges, from how the code uses a vulnerable package, whether the repository is likely affected.
- **Pull request fix suggestions:** during [pull request scans](pull-request-scans.md), suggests a code change for new code and infrastructure issues, shown in the pull request comment for review. Off by default.
- **Advisory extraction** from security news: proposes package advisories for review — see [Threat intelligence](threat-intelligence.md).

AI only ever **advises**. It never changes a ticket's status, suppresses a finding or alters a risk score. Every AI output is labelled *AI-assisted*, with the model that produced it and its reasoning.

AI is **off by default**. Nothing is sent to an AI provider until an administrator turns it on.

## Providers

| Provider | API used | Structured output |
|---|---|---|
| Anthropic Claude | Messages API (official Anthropic SDK) | JSON schema (`output_config.format`) |
| OpenAI | Chat Completions | JSON schema, strict mode |
| Google Gemini | `generateContent` | JSON schema (`responseJsonSchema`) |

Configure them under **Administration → AI assistance**:

- **API key.** Stored encrypted (AES-256-GCM) and write-only. The page only shows the last four characters.
- **Model.** Suggested models are listed, but you can enter any model your account offers. Argus defaults to `claude-opus-5-5`, `gpt-6.1-sol` and `gemini-3.8-flash`. Check your provider's model list, because names change.
- **Base URL (optional).** Point a provider at a gateway or private endpoint, such as an internal proxy or an OpenAI-compatible service. It must be HTTPS; plain HTTP is accepted only for loopback addresses.
- **Prices (optional).** Used for cost estimates. When left empty, Argus uses its built-in list prices, which can go out of date.
- **Test saved settings** sends a tiny request to check the key, model and endpoint.

You choose a **default provider**, and can route each feature to a different one. For example, you might use a fast, inexpensive model for scan triage and a stronger one for remediation advice.

On the public Claude API, requests to `claude-opus-5-5`, `claude-opus-5`, `claude-fable-5-1` and `claude-sonnet-5-5` use Anthropic's server-side fallback: if the model declines a request, Anthropic re-runs it on a suitable fallback model. The answer is labelled with the model that actually produced it. Fallback is not requested when a custom base URL is set.

## Features and switches

Each feature can be switched on or off independently:

| Feature | When it runs | Who can use it | Stored as |
|---|---|---|---|
| Remediation suggestions | When someone clicks **Suggest a fix** on a ticket | Developers, Security Managers, Administrators (`ai:use`) | The latest suggestion per ticket, with author, provider, model and time. **Regenerate** replaces it; **Add as comment** posts it to the ticket, labelled AI-assisted. |
| Jira and email drafting | **Draft with AI** in the Jira and email dialogs | Same, and the user must be able to work on tickets | Not stored. The text is only filled into the form. |
| Secret triage | During scans, for new secret findings (default off) | Automatic | A hint on the finding: *likely a real secret*, *likely a false positive* or *uncertain*, with confidence and reasoning. |
| Vulnerability applicability | During scans, for new medium, high and critical package vulnerabilities (default off) | Automatic | A hint on the finding: *likely affected*, *likely not affected* or *uncertain*. |
| Advisory extraction | For each new news item (default off) | Automatic; reviewed by Security Managers / Administrators | Proposed advisories on the news item, until approved or rejected. |

Scan-time checks run while the clone still exists, after findings and tickets are updated. Each finding is assessed once. The number of checks per scan is capped (**AI checks per scan**, default 20); the riskiest findings go first, and the rest are picked up by later scans. If the budget runs out, or a provider fails, triage stops for that scan and the scan itself still succeeds.

Hints appear next to findings in the findings list, the finding details and the ticket's findings. They help you prioritise. To act on a likely false positive, mark the ticket **False positive** yourself.

## What is sent

| Feature | Sent to the provider |
|---|---|
| Remediation, drafting | Ticket key, title, severity, risk score, due date, repository name, visibility and criticality. For up to 10 of its findings: rule, file path and line, package and version, advisory id, summary and exploitability data, and the scanner's own fix guidance. **No source code.** |
| Secret triage | Rule, file path and line, and the value's *characteristics*, such as length, entropy, character classes and whether it contains words like "example". **Never the value itself.** Also ±4 lines of surrounding code, with the value removed. |
| Vulnerability applicability | Package, version, dependency type, the advisory, and up to five short excerpts (±4 lines) where the code imports or references the package. |
| Advisory extraction | The news item's title, link, date and plain text (HTML removed). Nothing from your repositories. |

Before anything is sent:

1. **Secrets are redacted.** These are replaced with `[REDACTED:…]` markers:
   - the exact detected value
   - private key blocks
   - URL credentials and `Authorization` headers
   - every pattern of Argus's secret detector
   - credential-like assignments (`password = …`, `apiKey: …`)
   - long random-looking tokens
2. **Context is capped** at the **context limit** (default 12,000 characters).
3. **Repositories that opted out are excluded.** Under the repository's settings, clearing **Allow AI assistance** keeps everything from that repository away from AI providers.

Repository content is wrapped in tags, and the model is instructed to treat it as untrusted data and never follow instructions inside it. This is a mitigation against prompt injection from scanned code. It is not a guarantee, which is one reason AI output is advisory only.

## Validation, budget and audit

- **Strict output.** Every answer must be JSON that matches the feature's schema, including required fields, value ranges and allowed verdicts. Anything else is discarded, the user sees *"The AI answer did not match the expected format"*, and the failure is counted.
- **Monthly budget.** Argus records the provider, model, feature, user, repository, token counts and an estimated cost of every request. Once the estimated spend for the calendar month (UTC) reaches **Monthly budget**, AI requests stop until the next month or until the budget is raised. **Usage this month** on the settings page shows the breakdown.
- **Audit.** Every request is written to the audit log as `ai.request`, with the use case, provider, model, repository, token counts, cost, the number of redactions and the outcome. **Prompts and answers are never logged or audited.** Settings changes (`settings.ai_updated`, including which keys changed, never the keys themselves) and connection tests (`ai.provider_tested`) are audited too.
- **Rate limits.** Generating suggestions and drafts is limited to 10 requests per minute per client.

## Offline and restricted networks

With `ARGUS_OFFLINE=true`, providers that use their public API are unavailable. A provider with a **base URL** (for example a self-hosted or private endpoint) keeps working.

Behind a proxy, set `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1`. To allow-list outbound hosts, use the base URLs in use, by default:
- `api.anthropic.com`
- `api.openai.com`
- `generativelanguage.googleapis.com`

## Permissions

| Action | Viewer | Developer | Security Manager | Administrator |
|---|---|---|---|---|
| See AI suggestions and hints | ✓ | ✓ | ✓ | ✓ |
| Generate suggestions, draft with AI | | ✓ | ✓ | ✓ |
| Configure providers, features, budget; see usage | | | | ✓ |
| Exclude a repository from AI | | | ✓ | ✓ |
