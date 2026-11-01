# API and automation

## Personal API tokens

Use API tokens to call Argus from CI pipelines and scripts. Create one under **Profile → API tokens**:

- **Shown once.** The token (`argus_pat_…`) is displayed when it is created and never again. Argus stores only a keyed hash of it.
- **Scoped.** Choose the permissions the token may use (a *read-only* preset is offered). A token can never do more than its owner's role allows. The check is made on every request, so if the owner's role is lowered, the token loses those permissions too.
- **Expiring.** 7, 30, 90, 180 or 365 days. There are no tokens without an expiry.
- **Tied to its owner.** A token stops working when its owner is disabled, or must change their password or enrol in MFA.
- **Revocable.** The owner revokes it under Profile; an administrator can revoke any token under **Security settings → API tokens (all users)**.
- **Audited.** Creating and revoking tokens are audited (`api_token.created`, `api_token.revoked`), and each token shows when and from which IP it was last used.

Call the API with the token as a bearer token:

```bash
curl -H "Authorization: Bearer $ARGUS_TOKEN" https://argus.example.com/api/v1/findings?severity=critical,high
```

API tokens are **default-deny**. They work only on endpoints that declare the permissions they need, and never on these:
- sign-in, MFA and password endpoints
- token management, so a leaked token cannot create other tokens or hide itself

Token requests carry no cookies, so CSRF protection does not apply to them.

To scan pull requests from a CI pipeline, use a token with the **CI pull request scans** preset: see [Pull request scans](pull-request-scans.md).

## OpenAPI

`GET /api/v1/openapi.json` returns an OpenAPI 3.1 description of the REST API, generated from the running code. To read it in Argus, open **Documentation → API reference**. It lists every endpoint by area, with its method, path, required permissions, parameters and JSON body, and you can filter it. For every endpoint it gives:
- the path and method
- the request body and query parameters, from the same validation schemas the server enforces
- the permissions it requires (`x-argus-permissions`)
- whether API tokens may call it

Response bodies are described in prose. Load the document into any OpenAPI tool (Swagger Editor, Postman, Insomnia, client generators).

Useful endpoints for automation:

| Endpoint | Purpose | Permission |
|---|---|---|
| `GET /api/v1/findings` | Findings, filterable by repository, scanner, severity, status, search | `findings:read` |
| `GET /api/v1/repos` | Repositories and their last scan status | `repos:read` |
| `POST /api/v1/repos/{id}/scans` | Start a scan | `scans:run` |
| `GET /api/v1/dashboard` | Dashboard figures (organisation, team or repository) | `reports:read` |
| `GET /api/v1/reports/findings.csv` | Open findings as CSV | `reports:read` |
| `GET /api/v1/packages/search?name=lodash` | Which repositories use a package | `repos:read` |
| `GET /api/v1/tickets` | Tickets | `tickets:read` |

## Prometheus metrics

Set `ARGUS_METRICS_TOKEN` (at least 16 characters) to enable `GET /metrics`. Prometheus sends the token as a bearer token. Browser sessions and API tokens do not grant access to metrics. See [Docker deployment → Prometheus](../deployment/docker.md#prometheus) for the scrape configuration and the list of metrics.
