# Sources, repositories and scans

A **source** is a connection to a code host:

- a GitHub organisation (github.com or GitHub Enterprise Server)
- a Bitbucket Cloud workspace
- a Bitbucket Data Center / Server instance

Argus lists the repositories that a source can see. You decide which of them to **monitor**, who owns them, and how often they are scanned.

## Connecting a source

Go to **Administration → Sources → Connect source**. Only administrators can manage sources.

| Field | GitHub | Bitbucket Cloud | Bitbucket Data Center |
|---|---|---|---|
| Server URL | Empty for github.com; `https://github.example.com` for Enterprise Server | — | `https://bitbucket.example.com` (include any context path) |
| Scope | Organisation (optional) | Workspace (required) | Project key (optional) |
| Username | — | Account email for an API token / app password; empty for access tokens | Empty for HTTP access tokens |
| Token | Personal access token | API token, app password, or workspace/repository access token | HTTP access token |

When you save, Argus does three things:

1. It **tests the connection**. A failing source cannot be saved, and the error says what is wrong: bad credentials, a missing permission, an unknown organisation, or an unreachable server.
2. It **encrypts the token**. From then on the token is never shown again; the UI only displays `••••` followed by its last four characters. To replace it, edit the source and paste a new token. Leave the field empty to keep the current one.
3. It **lists the source's repositories** in the background, and again every 24 hours or when you click **Sync now**.

### Access tokens

Argus only reads code, so give it read-only credentials.

| Provider | Recommended credential | Minimum permissions |
|---|---|---|
| GitHub | Fine-grained personal access token (or a token for a dedicated machine user) | Repository access to the repositories to monitor, with **Contents: read** and **Metadata: read**. A classic token needs the `repo` scope. |
| Bitbucket Cloud | Workspace access token | **Repositories: read** |
| Bitbucket Data Center | HTTP access token (project- or user-level) | **Project read** or **Repository read** |

### GitHub App (alternative to a personal access token)

For organisations, a GitHub App is often preferable: it is not tied to a person, repository access is chosen when it is installed, and Argus only ever holds tokens that expire within an hour.

1. In GitHub, create an app (**Settings → Developer settings → GitHub Apps → New GitHub App**). Give it the repository permissions **Contents: read** and **Metadata: read**. It needs no other permissions or events.
2. Generate a **private key** on the app's settings page and download the `.pem` file.
3. **Install** the app on the organisation (or user account), for all repositories or selected ones.
4. In Argus, add a GitHub source, choose **Authentication → GitHub App**, and enter:
   - the organisation or account it is installed on
   - the **App ID** (on the app's settings page)
   - the private key: paste the whole `.pem` file.

How Argus uses it:
- The private key is encrypted like any other source credential and never returned.
- Argus signs a short JWT with the key, finds the installation on the organisation, and mints an installation token (valid for one hour). Tokens are reused while valid, and are used for API calls and for cloning.
- Repository sync lists exactly the repositories the installation was granted. To add or remove repositories, change the installation in GitHub.
- **Push webhooks:** a GitHub App has a single webhook. To scan on push, set the app's webhook URL and secret to the source's payload URL and secret (below), and subscribe it to **Push** events.
- GitHub Enterprise Server is supported the same way; enter its URL as for tokens.

### Auto-activation and default team

- **Auto-activate new repositories:** comma-separated patterns matched against the full repository name. `*` matches anything, and matching ignores case. Examples: `payments/*` or `*-api, platform/core`. A matching repository starts being monitored as soon as it is discovered. Archived repositories are never auto-activated.
- **Default team:** assigned as the owner of newly discovered repositories.

### When repositories disappear

If a repository is deleted, or the token loses access to it, the next sync marks it **removed**. Argus then:

- stops monitoring it
- hides it from lists
- keeps its history

If the repository comes back, it is restored but stays unmonitored until you turn monitoring on again.

## Repositories

**Repositories** lists everything you are allowed to see. Developers and Viewers see only repositories owned by their teams; Administrators and Security Managers see all of them.

You can filter by name, source, team, and whether a repository is monitored. Administrators and Security Managers can select several repositories to:

- start or stop monitoring them
- assign a team
- set a schedule
- set a business criticality

### Repository settings

Open a repository to change:

| Setting | Meaning |
|---|---|
| Monitor this repository | Scans run on the schedule (and on push, if enabled). Turning monitoring on queues a first scan within a minute. |
| Owning team | Controls who can see the repository, and later its findings and tickets. |
| Business criticality | Low, medium, high or critical. From Phase 2 it feeds the risk score of the repository's findings. |
| Scan schedule | Every hour, day or week; manual only; or a custom cron expression. |
| Branch | The branch to scan. Empty means the repository's default branch. |
| Scan on push | Scan when a push to that branch is reported by the source's webhook. |
| Jira project key | Where Jira issues for this repository will be created (Phase 3). |
| Notification recipients | Email addresses for alerts about this repository (Phase 3). |

**Schedules.** All schedule times are in **UTC**.

- The hourly, daily and weekly presets are spread across repositories automatically, at a fixed minute between 01:00 and 05:59 UTC, so that hundreds of repositories don't all start at once.
- A custom cron expression uses five fields (minute, hour, day, month, weekday) and may run at most every 15 minutes. For example, `0 3 * * 1-5` means 03:00 UTC on weekdays.

## Scans

A scan does the following:

1. It **shallow-clones** the chosen branch (one commit, no tags, no submodules, no LFS files) into a temporary directory.
2. It records the commit, the number of files, the size, and the detected ecosystems and manifests:
   - npm: `package.json` and lockfiles
   - NuGet: `*.csproj`, `packages.config`, `Directory.Packages.props`, `packages.lock.json`
   - PyPI: `pyproject.toml`, `poetry.lock`, `uv.lock`, `Pipfile`, `Pipfile.lock`, `requirements*.txt`
   - Maven/Gradle: `pom.xml`, `build.gradle(.kts)`, `gradle.lockfile`, `*.versions.toml`
   - Go: `go.mod`
   - Cargo: `Cargo.toml`, `Cargo.lock`
   - .NET SDK (`global.json`) and Node version files
   - Dockerfiles
   - certificate files
3. From Phase 2, it runs the security scanners on that checkout.
4. It **deletes the temporary directory**, whether or not the scan succeeded.

A scan is started by its schedule, a push webhook, **Scan now** (Developers and above, for repositories they can see), or monitoring being turned on. Only one scan per repository is queued or running at a time; further requests join the existing one.

If a scan fails for a transient reason, such as a network error, it is retried once a minute later. Authentication problems and refused clone URLs fail immediately with a clear message.

**Activity indicator.** While scans are running or waiting, or Argus is doing other background work (discovering repositories, matching new advisories, reading security news, sending notifications), an indicator at the top of the sidebar says so. Open it to see which repositories are being scanned, with links to them, how many scans are waiting, and what else is running. It only lists scans of repositories you can see, and it disappears when Argus is idle.

Each repository page shows its **scan history**. Open a run to see its status, commit, duration, detected ecosystems and log. Scan runs are kept for 90 days.

## Push webhooks (optional)

With a push webhook, Argus scans as soon as code is pushed rather than waiting for the schedule.

1. When you connect a source, Argus shows a **Payload URL** (`https://<argus>/api/v1/webhooks/<source id>`) and a **secret**. The secret is shown once; **New webhook secret** on the source card replaces it.
2. Add a webhook at the organisation, workspace or project level (or on individual repositories):
   - **GitHub:** content type `application/json`, paste the secret, choose *Just the push event*.
   - **Bitbucket Cloud:** paste the URL and secret, and select the trigger *Repository → Push*.
   - **Bitbucket Data Center:** paste the URL and secret, and select the event *Repository → Push*.

Argus rejects any call that is not signed with the secret. It ignores:

- pushes to repositories that are not monitored, or that have scan on push turned off
- pushes to branches other than the scanned branch
- tag pushes and branch deletions

Argus must be reachable from the code host for webhooks to work. Without webhooks, the schedule still applies.

## Network requirements

Argus needs outbound HTTPS to:

- `api.github.com` and `github.com`, or your GitHub Enterprise Server
- `api.bitbucket.org` and `bitbucket.org`, or your Bitbucket Data Center server

For vulnerability and lifecycle data it also needs:

- `api.osv.dev`
- `www.cisa.gov`
- `api.first.org`
- `endoflife.date`
- `registry.npmjs.org`
- `api.nuget.org`
- `api.deps.dev`

You can point these at mirrors, or turn them off with `ARGUS_OFFLINE=true`. See [data sources](scanners-and-findings.md#data-sources-caching-and-offline-mode).

**Behind an HTTP proxy:** set `HTTPS_PROXY` (and `NO_PROXY` as needed). Git honours these directly; for API calls, also set `NODE_USE_ENV_PROXY=1`.

**Private certificate authority:** if your server's certificate comes from a private CA, mount the CA bundle and set both of these to it:

- `NODE_EXTRA_CA_CERTS`, for API calls
- `GIT_SSL_CAINFO`, for clones
