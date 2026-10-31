# Argus

**Continuous security and dependency monitoring for code repositories.**

Argus connects to your GitHub and Bitbucket organisations and continuously watches the repositories you choose. It detects:

- leaked secrets
- vulnerable packages (npm, NuGet, PyPI, Maven/Gradle, Go and Cargo)
- outdated or end-of-life frameworks
- expiring certificates and credentials

Each finding gets a risk score and becomes a ticket inside Argus. From a ticket you can:

- send email alerts
- raise a Jira issue
- ask an AI model (Claude, OpenAI or Gemini) for remediation advice

A threat-intelligence feed keeps Argus up to date with newly published vulnerabilities.

Argus is self-hosted. It ships as a single Docker image, runs on Azure Web App for Containers, and stores its data in **PostgreSQL** or **MongoDB**.

> **Status:** All phases (0–6) are complete: foundation, sources and scheduling, scanners and risk scoring, tickets and integrations, AI assistance, threat intelligence, and enterprise features (dashboards, reports, credential inventory, API tokens, metrics, Azure Bicep). See the [roadmap](docs/features/README.md#roadmap) for what is built and what is coming.

## Quick start (Docker)

```bash
cp .env.example .env
# Set ARGUS_MASTER_KEY in .env, e.g.:  openssl rand -base64 48
docker compose -f deploy/docker/docker-compose.postgres.yml --env-file .env up -d --build
docker compose -f deploy/docker/docker-compose.postgres.yml logs argus | grep "DEFAULT ADMIN"
```

Open <http://localhost:8080> and sign in as `admin` with the temporary password from the log. You will be asked to choose a new password straight away.

If you prefer MongoDB, use `deploy/docker/docker-compose.mongo.yml` instead.

## Documentation

| Topic | |
|---|---|
| [Architecture](docs/architecture.md) | Components, runtime roles, data layer, request flow |
| [Security model](docs/security.md) | How Argus protects credentials, sessions, source code and AI prompts |
| [Features](docs/features/README.md) | Feature catalogue and roadmap |
| [User management](docs/features/user-management.md) | Roles, teams, MFA, lockout, audit log |
| [Sources, repositories and scans](docs/features/sources-and-repositories.md) | Connecting GitHub/Bitbucket, token permissions, schedules, webhooks |
| [Scanners, findings and risk scoring](docs/features/scanners-and-findings.md) | What is detected, how risk is scored, suppressions, `.argus.yml`, SBOM, data sources |
| [Tickets, email, Jira and notifications](docs/features/tickets-and-notifications.md) | Ticket lifecycle and SLAs, Graph/SMTP email setup, Jira, Teams/Slack/webhook rules |
| [Threat intelligence](docs/features/threat-intelligence.md) | Security news with AI extraction and review, Argus advisories, continuous re-matching, NVD |
| [Dashboards, reports and credentials](docs/features/dashboards-and-reports.md) | Trends, MTTR, SLA compliance, printable reports, credential inventory with Entra ID import, data retention |
| [API and automation](docs/features/api-and-automation.md) | Personal API tokens, OpenAPI, Prometheus metrics |
| [AI assistance](docs/features/ai-assistance.md) | Claude, OpenAI or Gemini: fix suggestions, drafts, scan triage, and what is (and is never) sent |
| [Configuration](docs/configuration.md) | Every environment variable and in-app setting |
| [Docker deployment](docs/deployment/docker.md) | Compose, scaling out, backups |
| [Azure Web App deployment](docs/deployment/azure.md) | Running the image on Azure App Service |
| [Development](docs/development.md) | Local setup, tests, project layout |

## License

[Apache License 2.0](LICENSE)
