# Deploying to Azure Web App for Containers

Argus runs on Azure App Service (Linux) from its Docker image. A typical production layout:

```
Azure Front Door / App Gateway (optional, WAF)
            │ HTTPS
   App Service (Linux) ── Web App: argus (container image from ACR or GHCR)
            │ VNet integration / private endpoint
   Azure Database for PostgreSQL Flexible Server
     or Azure Cosmos DB for MongoDB (vCore)
            │
   Key Vault: ARGUS_MASTER_KEY, ARGUS_DB_URL (referenced from app settings)
```

## Quick start: Bicep

`deploy/azure/main.bicep` provisions everything in one resource group:

| Resource | Notes |
|---|---|
| App Service plan (Linux) and Web App | Runs the Argus image. HTTPS only, TLS 1.2+, FTP off, Always On, health check on `/healthz`, system-assigned managed identity. |
| Key Vault | RBAC, soft delete and purge protection. Holds the master key, the database URL and (optionally) the initial admin password. The web app reads them through Key Vault references and only has the *Key Vault Secrets User* role. |
| Database | PostgreSQL Flexible Server 16 (Burstable B1ms, database `argus`, TLS required), or Cosmos DB for MongoDB vCore (M10) with `databaseType=mongodb`. |
| Log Analytics | Receives console, HTTP and platform logs and metrics from the web app. |

```bash
cp deploy/azure/main.parameters.example.json deploy/azure/main.parameters.json   # fill in the secrets; do not commit it
az group create -n argus-rg -l westeurope
az deployment group what-if -g argus-rg -f deploy/azure/main.bicep -p @deploy/azure/main.parameters.json
az deployment group create  -g argus-rg -f deploy/azure/main.bicep -p @deploy/azure/main.parameters.json
```

The outputs include the URL, the web app and the Key Vault names.

- **Private images:** pass `registryServer`, `registryUsername` and `registryPassword` (or grant the web app's identity *AcrPull* on your registry).
- **First start:** the role assignment that lets the web app read Key Vault can take a few minutes to propagate. If the first start fails to resolve the Key Vault references, restart the web app.
- **Network:** the template allows Azure services to reach the database (firewall rule `0.0.0.0`), which is convenient but broad. For production, add VNet integration to the web app and a private endpoint to the database, then remove that rule.
- **Custom domain:** set `publicUrl` so cookies, links in notifications and the OpenAPI document use it.

The template is checked with `az bicep build` and the Bicep linter. Always run `what-if` in your subscription first: resource availability (SKUs, Cosmos DB for MongoDB vCore regions) differs between regions.

## Manual setup with the Azure CLI

The same result, step by step.

## 1. Push the image to Azure Container Registry

```bash
az acr create -g argus-rg -n argusacr --sku Basic
az acr build -r argusacr -t argus:0.2.0 -f deploy/docker/Dockerfile .
```

## 2. Create the database

**PostgreSQL (recommended):**

```bash
az postgres flexible-server create -g argus-rg -n argus-pg --tier Burstable --sku-name Standard_B1ms \
  --version 16 --admin-user argusadmin --admin-password '<strong-password>'
az postgres flexible-server db create -g argus-rg -s argus-pg -d argus
```

The connection string uses TLS:
`postgres://argusadmin:<password>@argus-pg.postgres.database.azure.com:5432/argus?sslmode=require`

**MongoDB:** create an *Azure Cosmos DB for MongoDB (vCore)* cluster and use its connection string, with `ARGUS_DB_TYPE=mongodb`.

## 3. Store secrets in Key Vault

```bash
az keyvault create -g argus-rg -n argus-kv
az keyvault secret set --vault-name argus-kv -n argus-master-key --value "$(openssl rand -base64 48)"
az keyvault secret set --vault-name argus-kv -n argus-db-url --value 'postgres://…?sslmode=require'
```

## 4. Create the Web App

```bash
az appservice plan create -g argus-rg -n argus-plan --is-linux --sku P1v3
az webapp create -g argus-rg -p argus-plan -n argus-web \
  --deployment-container-image-name argusacr.azurecr.io/argus:0.2.0
az webapp identity assign -g argus-rg -n argus-web
# Let the app pull from ACR and read Key Vault with its managed identity
# (grant AcrPull on the registry and "Key Vault Secrets User" on the vault).
az webapp config set -g argus-rg -n argus-web --always-on true
```

## 5. App settings

```bash
az webapp config appsettings set -g argus-rg -n argus-web --settings \
  WEBSITES_PORT=8080 \
  ARGUS_DB_TYPE=postgres \
  ARGUS_DB_URL='@Microsoft.KeyVault(VaultName=argus-kv;SecretName=argus-db-url)' \
  ARGUS_MASTER_KEY='@Microsoft.KeyVault(VaultName=argus-kv;SecretName=argus-master-key)' \
  ARGUS_PUBLIC_URL='https://argus-web.azurewebsites.net' \
  WEBSITES_ENABLE_APP_SERVICE_STORAGE=false
```

| Setting | Why |
|---|---|
| `WEBSITES_PORT=8080` | Tells App Service which container port to route to. Argus reads it automatically. |
| `ARGUS_PUBLIC_URL` (https) | Enables `Secure` cookies and HSTS. |
| `WEBSITES_ENABLE_APP_SERVICE_STORAGE=false` | Argus needs no persistent file storage; scan workspaces are temporary. |
| Always On | Keeps the background worker running between web requests. |

App Service sits behind a front end that adds `X-Forwarded-For`. The default `ARGUS_TRUST_PROXY=1` makes Argus record the real client IP.

## 6. First sign-in

Open the **Log stream** for the Web App and look for `DEFAULT ADMIN CREATED`. Alternatively, set `ARGUS_ADMIN_PASSWORD` (as a Key Vault reference) **before** the first start. Sign in as `admin` and change the password.

Configure the App Service health check path as `/healthz` (liveness). `/readyz` also checks the database, so a brief database outage would make App Service recycle every instance; use it for external monitoring instead.

## Scaling out on Azure

- **Simple:** scale the single Web App (`ARGUS_ROLE=all`) up, to a larger SKU.
- **Larger:** create two Web Apps from the same image that share the database and master key:
  - `argus-web` with `ARGUS_ROLE=api`, scaled out to N instances
  - `argus-worker` with `ARGUS_ROLE=worker`, with Always On and no public ingress
