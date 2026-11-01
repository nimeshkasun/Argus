# Argus documentation

This documentation is also built into Argus: choose **Documentation** at the bottom of the sidebar. It always matches the version you are running and works without internet access. It includes a searchable copy of these pages and a readable reference of the REST API.

- **[Architecture](architecture.md):** how Argus is put together. Covers the single image and its runtime roles, the database-agnostic data layer, and the lifecycle of a request and of a scan.
- **[Security model](security.md):** what Argus protects and how. Covers encryption at rest, authentication, sessions, auditing, source-code handling and AI guardrails.
- **[OWASP ASVS 5.0 self-assessment](asvs-checklist.md):** Argus mapped against each ASVS chapter, with the known gaps.
- **[Features](features/README.md):** the feature catalogue, with the delivery status of each feature.
  - [User management](features/user-management.md)
  - [Sources, repositories and scans](features/sources-and-repositories.md)
  - [Scanners, findings and risk scoring](features/scanners-and-findings.md)
  - [Pull request scans](features/pull-request-scans.md)
  - [Tickets, email, Jira and notifications](features/tickets-and-notifications.md)
  - [AI assistance](features/ai-assistance.md)
  - [Threat intelligence](features/threat-intelligence.md)
  - [Dashboards, reports and credentials](features/dashboards-and-reports.md)
  - [API and automation](features/api-and-automation.md)
- **[Configuration](configuration.md):** environment variables and in-app settings.
- **Deployment**
  - [Docker and docker compose](deployment/docker.md)
  - [Azure Web App for Containers](deployment/azure.md)
  - [Windows without Docker](deployment/windows.md)
- **[Development](development.md):** working on Argus itself.
