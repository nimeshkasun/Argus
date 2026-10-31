# Architecture

Argus is a TypeScript monorepo that produces **one Docker image**. The same image serves the web UI and REST API and runs the background worker. A single environment variable (`ARGUS_ROLE`) decides which of these a container does.

```
┌──────────────────────── argus image (node:24, non-root) ────────────────────────┐
│                                                                                 │
│  ARGUS_ROLE=all (default)          ARGUS_ROLE=api          ARGUS_ROLE=worker    │
│  ┌──────────────┐ ┌─────────────┐  ┌──────────────┐        ┌─────────────┐      │
│  │ API + web UI │ │   Worker    │  │ API + web UI │        │   Worker    │      │
│  └──────┬───────┘ └──────┬──────┘  └──────┬───────┘        └──────┬──────┘      │
└─────────┼────────────────┼────────────────┼───────────────────────┼─────────────┘
          └────────────────┴───────┬────────┴───────────────────────┘
                                   │  DataStore interface
                    ┌──────────────┴──────────────┐
             PostgreSQL adapter             MongoDB adapter
           (Kysely + migrations)      (driver + index bootstrap)
```

## Components

| Path | What it is |
|---|---|
| `apps/server` | NestJS application. Its entrypoint (`main.ts`) starts the HTTP API, the worker, or both, depending on `ARGUS_ROLE`. |
| `apps/web` | React single-page app (Vite, Tailwind CSS, TanStack Query). Built to static files, which the API serves in production. |
| `packages/shared` | Types, roles, permissions, validation schemas (zod) and the password policy. Shared by the server and the browser, so both enforce the same rules. |
| `packages/data` | The `DataStore` interface and its two adapters: PostgreSQL and MongoDB. |
| `deploy/` | Dockerfile, docker compose files and the Azure Bicep template (`deploy/azure/main.bicep`). |

## Runtime roles

- **`all`**: API, web UI and worker in one process. The simplest deployment, and the one recommended for a single Azure Web App.
- **`api`**: HTTP only. Run several replicas behind a load balancer.
- **`worker`**: background processing only, with no HTTP port.
  - Today: the job runner (repository syncs and scans), the scheduler, and housekeeping (worker heartbeat, cleanup of expired sessions, old jobs and old scan runs).
  - Later phases add advisory-feed ingestion, notifications and Jira sync.

Every role needs only the database. There is **no Redis or message broker**, so an Azure deployment stays at "one container plus one database".

## Job queue and scheduler

Background work is a row (PostgreSQL) or document (MongoDB) in `jobs`:

- **Claiming.** Workers claim jobs atomically: `FOR UPDATE SKIP LOCKED` on PostgreSQL, `findOneAndUpdate` on MongoDB. Higher priority goes first, then older jobs. Priorities: manual scans > push scans > first scans > scheduled scans.
- **Leases.** A claimed job holds a 5-minute lease that its worker renews while it runs. If the worker dies, the lease expires and another worker picks the job up.
- **Retries.** A failing job is retried with exponential backoff (1, 4, 16 minutes…) up to its attempt limit. Permanent errors, such as bad credentials or a refused clone URL, fail immediately.
- **De-duplication.** At most one queued or running job may hold a given key. That key is `scan:<repo>` for scans and `sync:<source>` for syncs, so duplicate requests join the existing job.
- **Concurrency.** `ARGUS_WORKER_CONCURRENCY` limits how many jobs one worker process runs at once.

The **scheduler** runs in every worker, but a database lease in `locks` makes sure only one instance acts at a time. If that instance dies, another takes over within about a minute. Every `ARGUS_SCHEDULER_INTERVAL_SECONDS` (default 30), the active scheduler:

- queues scans for monitored repositories whose next scan time has passed, and computes their next run from the schedule
- queues a repository sync for every source not synced in the last 24 hours
- hourly, deletes finished jobs older than 7 days and scan runs older than 90 days

## Data layer

The application never talks to a database driver directly. It depends on the `DataStore` interface (`packages/data/src/store.ts`), which exposes repositories (`users`, `teams`, `sessions`, `audit`, `settings`, and more in later phases).

| | PostgreSQL | MongoDB |
|---|---|---|
| Library | Kysely + `pg` | Official `mongodb` driver |
| Schema | Versioned, append-only migrations, applied at startup under a lock | Idempotent index bootstrap, version tracked in `_meta` |
| Compatible services | PostgreSQL 14+, Azure Database for PostgreSQL Flexible Server | MongoDB 6+, MongoDB Atlas, Azure Cosmos DB for MongoDB (vCore) |

Both adapters:

- use string UUID identifiers and real timestamps, so the rest of the code is database-neutral
- turn unique-constraint violations into the same `DuplicateKeyError`

The same **contract test suite** (`packages/data/test/contract.test.ts`) runs against a real PostgreSQL container and a real MongoDB container on every CI run. Any behavioural difference between the two is treated as a bug.

The database is chosen with `ARGUS_DB_TYPE`. Data cannot be moved between the two automatically; pick one per installation.

## Request flow (API)

Every request goes through these global guards, in order:

1. **Rate limit**:
   - 300 requests/min per IP in general
   - 10 requests/min per IP on login, MFA and password endpoints (configurable)
2. **CSRF check**: a state-changing request that carries session cookies must echo the CSRF cookie in an `X-CSRF-Token` header.
3. **Authentication**:
   - verifies the short-lived access token (an HttpOnly cookie)
   - **reloads the user from the database**, so a disabled account or a role change takes effect on the very next request
   - rejects tokens issued before the user's last password change
4. **Account restrictions**: accounts that must change their password or enroll in MFA can only reach the endpoints needed to do that.
5. **Authorisation**: each endpoint declares the permissions it needs (for example `users:manage`), and these are checked against the user's role.

Request bodies and query strings are validated with the zod schemas from `packages/shared`.

## Domain events

Modules communicate through a small in-process event bus (`DomainEvents`) rather than calling each other, so features stay decoupled:

| Event | Published by | Handled by |
|---|---|---|
| `scan.completed` | scan pipeline | tickets (open / update / resolve) |
| `scan.failed` | scan executor | notifications |
| `findings.changed` | suppressions | tickets (accept / reopen) |
| `ticket.created`, `ticket.reopened`, `ticket.sla_breached` | tickets | notifications |
| `intel.emerging_threats` | continuous re-matching | notifications |
| `credential.expiring` | credential inventory (daily) | notifications |
| `scheduler.tick` | leader scheduler | SLA checks, Jira sync, weekly digests, news-feed fetching, scheduled re-matching |

Notifications are delivered through the job queue (`notification.deliver`), with retries. In split deployments, events are handled in the process that raises them (scans in workers, suppression changes in the API), and delivery always runs on a worker.

## Scan lifecycle

A scan runs as follows:

1. Clone the repository.
2. List its files, skipping vendored folders and `.argus.yml` ignore paths.
3. Run the scanners in order:
   1. secrets
   2. dependencies (which builds the inventory)
   3. licenses (which reuses that inventory)
   4. frameworks
   5. certificates
4. Turn each scanner result into findings: compute the risk score, apply suppressions from the database and from `.argus.yml`, then reconcile with the stored findings.
5. Replace the repository's dependency inventory, and publish `scan.completed` (tickets are opened, updated and resolved).
6. If AI triage is enabled, assess new secret and vulnerability findings while the checkout still exists (capped per scan; never fails the scan).
7. Delete the workspace.

Scanners talk to the outside world only through `IntelService`, which caches every lookup in the database (`intel_cache`). See [Scanners and findings](features/scanners-and-findings.md).

```
schedule / manual / push webhook
        │
        ▼
 job queued in DB ──► worker leases job ──► shallow clone into /tmp/argus/<run>
                                                   │
                         scanners (secrets, packages, frameworks, certificates)
                                                   │
                       findings + dependency inventory (SBOM) stored ◄─┘
                                                   │
                      workspace deleted ─► risk scoring ─► tickets opened/updated/resolved
```

Source code is cloned only for the duration of a scan and is never persisted (see [security](security.md#source-code-handling)).

## Threat intelligence

Background jobs, all through the job queue:

| Job | Triggered by | Does |
|---|---|---|
| `intel.crawl` | scheduler, per due news source; **Fetch now** | Fetches an RSS/Atom feed and stores new items. |
| `intel.extract` | new items, when AI extraction is on | Asks AI for package advisories, in batches of 10, into the review queue. |
| `intel.rematch` | schedule (OSV refresh), **Re-check now**, new Argus advisories | Matches every stored inventory; opens findings, publishes `findings.changed` and `intel.emerging_threats`. |

Scans and re-matching share one matcher (`scanning/vulnerability-matcher.ts`) and one finding builder (`scanning/observe.ts`), so the same vulnerability always gets the same fingerprint. See [Threat intelligence](features/threat-intelligence.md).

## Operations

- **API tokens** authenticate in the same guard as sessions (`Authorization: Bearer argus_pat_…`); the permissions guard then requires the endpoint's permissions in both the owner's role and the token's scopes.
- **`/metrics`** (Prometheus) and **`/api/v1/openapi.json`** are served by the API role. The OpenAPI document is generated at runtime from the controllers' route metadata and the zod schemas of their validation pipes.
- **Dashboards** are computed on request from lean finding and ticket rows (`statsRows`), so no separate history store is needed.
- **Retention** runs in the scheduler's housekeeping.
- **`apps/server/dist/cli.js`** holds offline tools; today `rotate-master-key`.

## AI gateway

Every AI request, whatever the feature, goes through `AiService` (`apps/server/src/ai`):

```
feature (ticket suggestion, draft, scan triage)
   │  facts + repository excerpts
   ▼
AiService ── switches: AI on? feature on? repository opted in? provider configured? budget left?
   │        redact secrets ─► cap context ─► add untrusted-data preamble
   ▼
provider client (Anthropic SDK · OpenAI Chat Completions · Gemini generateContent), JSON-schema output
   │
   ▼
validate answer (zod) ─► record usage + cost ─► audit (no content) ─► return / store insight
```

Security news is processed the same way (`advisory_extraction`), without a repository. Results that are kept (ticket suggestions, finding hints) are stored in `ai_insights`, one per subject and use case. Token usage and estimated cost go to `ai_usage`. See [AI assistance](features/ai-assistance.md) and [security](security.md#7-ai-guardrails).

## Technology choices

- **Node.js 24 LTS and TypeScript.** One language across API, worker and UI. npm is the native environment for analysing npm packages.
- **NestJS 11.** Modules, dependency injection and guards suit a large enterprise codebase.
- **React 19, Vite, Tailwind CSS.** A fast, accessible UI with light and dark modes.
- **argon2id** (`@node-rs/argon2`) for password hashing, and `node:crypto` for every other primitive.
