# Threat intelligence

Argus keeps its vulnerability knowledge current between scans. It does this in three ways:

- **Continuous re-matching.** Argus re-checks every repository's stored dependency inventory against newly published advisories, without cloning anything. When something new matches, findings and tickets open straight away and an *emerging threat* notification is sent.
- **Security news.** Argus reads RSS and Atom feeds. If AI assistance is on, AI proposes package advisories (npm, NuGet, PyPI, Maven, Go, Cargo) from new items, and a person reviews them.
- **Argus advisories.** Advisories approved from news, or entered by hand, are matched by every scan and by re-matching, exactly like public advisories.

Open **Threat intel** in the navigation. Everyone who can see findings can see the overview, the news, and Argus advisories. Security Managers and Administrators (`intel:manage`) can review items, manage advisories and sources, and trigger a re-check.

## Where vulnerability data comes from

| Source | What it provides |
|---|---|
| OSV.dev | npm, NuGet, PyPI, Maven, Go and crates.io advisories, including the whole GitHub Advisory Database. This is the primary source. |
| CISA KEV | Whether a CVE is known to be exploited. |
| FIRST EPSS | How likely a CVE is to be exploited. |
| NVD (CVE API 2.0) | CVSS scores for CVEs whose OSV record has none, which is common for very fresh CVEs. A score from NVD is shown as `CVSS 9.8 (NVD)`. |
| Argus advisories | Your own advisories, from approved news items or entered by hand. |

**NVD rate limits.** NVD allows 5 requests per 30 seconds without an API key, and 50 with one. Argus paces its requests to stay within these limits and caches every score for a week. CVEs that NVD hasn't scored yet are checked again daily. To look up more CVEs per scan, set a free [API key](https://nvd.nist.gov/developers/request-an-api-key) in `ARGUS_NVD_API_KEY`.

If an Argus advisory duplicates a CVE that OSV already reports for the same package, OSV's record wins and only one finding is opened.

## Continuous re-matching

Each repository keeps the inventory from its latest scan (the same data as its SBOM). Re-matching checks those inventories against current advisory data:

| Trigger | What happens |
|---|---|
| Schedule (default every 24 hours) | OSV is asked again about every package version in use, bypassing the 12-hour cache. |
| **Re-check now** on the overview | Same as the schedule, on demand. |
| A new or restored Argus advisory | Inventories are matched against it immediately. |

New matches become ordinary dependency findings, with the same identity a scan would give them, so the next scan keeps them open rather than duplicating them.

- Tickets follow the usual rules.
- Suppressions stored in Argus apply.
- `.argus.yml` suppressions apply at the next scan, because re-matching doesn't read the repository.

A repository that is being scanned at that moment is skipped; its scan brings it up to date.

**Emerging threats.** Each advisory that matched between scans is listed on the overview, with the number of repositories and findings. A notification rule can send it on: in **Integrations → Notification rules**, choose the *Emerging threat* event. A team-scoped rule only lists its team's repositories.

## News sources

Under **Threat intel → Sources & settings**, add RSS 2.0, RSS 1.0 or Atom feeds and choose how often to fetch each one (15 minutes to 7 days). New installations list a few suggestions, switched off:
- the GitHub Blog security feed
- Node.js vulnerability announcements
- the Microsoft Security Response Center update guide
- the .NET Blog

Check that a suggestion suits you before you enable it.

Fetching is hardened:
- Feeds must use HTTPS, and redirects to plain HTTP are refused.
- Feeds over 5 MB are rejected.
- At most 200 entries are read per fetch.
- HTML, scripts and styles are stripped. Items are kept as plain text, capped at 4,000 characters.

Each item is stored once per source. Fetching the same item again does nothing.

`ARGUS_OFFLINE=true` stops all fetching. You can also pause fetching with **Fetch news sources** in the settings.

## AI extraction and review

When the **Advisory extraction** feature is enabled under [AI assistance](ai-assistance.md), each new item is sent to the AI model. The model receives only the item's title, link, date and text; nothing from your repositories. It answers whether the item announces a vulnerability in a package from a supported ecosystem, and if so, proposes advisories. Each proposal has:
- the package and the affected version range
- the fixed version
- the severity and CVE ids
- a title and summary

Proposals are checked before anyone sees them:
- A proposal with a version range Argus can't parse is dropped.
- Malformed CVE ids are removed.
- The item's link becomes the reference.

Items then show one of these statuses:

| Status | Meaning |
|---|---|
| Not analysed | New, or AI extraction is off. You can still **Create advisory from this item** by hand, or click **Analyse with AI**. |
| No package impact | The model found nothing to act on, with its reasoning shown. |
| Awaiting review | Proposals are waiting. Edit them if needed, then **Approve** or **Reject**. |
| Approved | Advisories were created, and repositories are being re-checked. |
| Rejected | Dismissed. |
| Analysis failed | The model's answer was unusable. Try **Analyse with AI** again. |

**Auto-approval** is off by default. When it is on, proposals at or above the confidence threshold (default 0.9) are approved without review, labelled *auto-approved*, and audited. Use it with care: a wrong advisory opens findings in every repository it matches.

AI never changes the status of findings or tickets. Approving an advisory is a human decision, unless auto-approval is on.

## Argus advisories

You can also enter an advisory under **Argus advisories → New advisory**. For example, from a vendor bulletin, a security mailing list or your own testing, before it reaches public databases. Each advisory gets a key such as `ARGUS-2026-0001`, shows how many repositories match today, and is used by every scan from then on.

**Withdraw** an advisory that turns out to be wrong. It stops matching, and the next scan of each repository marks its findings as fixed. **Restore** brings it back.

Affected ranges use npm syntax:
- `<4.17.21`
- `>=2.0.0 <2.3.1`
- `>=1.0.0 <1.0.5 || >=2.0.0 <2.0.2`

Versions are compared by each ecosystem's own rules. For npm, NuGet, Go and Cargo any npm range works (including `^` and `~`). For PyPI and Maven, use comparators (`<`, `<=`, `>`, `>=`, `=`) separated by spaces or commas, and `||` between alternatives, for example `>=2.0-beta9 <2.15.0` or `>=4.2, <4.2.16`. Maven package names are `groupId:artifactId`, and Go package names are module paths.

## Audit

These actions are recorded in the audit log:

| Action | Audit entry |
|---|---|
| Source changes | `intel.source_created`, `intel.source_updated`, `intel.source_deleted` |
| Reviews | `intel.item_approved`, `intel.item_rejected`, `intel.item_auto_approved` |
| Advisory changes | `intel.advisory_created`, `intel.advisory_withdrawn`, `intel.advisory_restored` |
| Settings changes | `settings.intel_updated` |
| AI requests | `ai.request`, as for every AI feature |
