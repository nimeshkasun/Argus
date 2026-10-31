# Windows without Docker

On a Windows server or VM without Docker, `argus.bat` in the repository root builds Argus and runs the production server in the background. One process serves the web UI, the API and the background worker.

## Requirements

- Node.js 24 or later, and git (the scanners clone repositories with it).
- Optional: [Gitleaks](https://github.com/gitleaks/gitleaks) on the `PATH`, or set `ARGUS_GITLEAKS_PATH`. Without it, the secrets scanner uses built-in rules.
- Optional: [Trivy](https://trivy.dev) on the `PATH`, or set `ARGUS_TRIVY_PATH`, for infrastructure-as-code and container image scanning. Without it, those scanners are skipped.
- Optional: [Opengrep](https://github.com/opengrep/opengrep/releases) (`opengrep_windows_x86.exe`, not the `opengrep-core` engine) for code analysis, with `ARGUS_OPENGREP_PATH` pointing at it and `ARGUS_OPENGREP_RULES` at a folder of rules. See [Code, infrastructure and container images](../features/scanners-and-findings.md#code-infrastructure-and-container-images) for the rules the Docker image bundles. Without it, the code scanner is skipped.
- A PostgreSQL or MongoDB database.

## First run

1. Copy `.env.example` to `.env` in the repository root, and set at least `ARGUS_DB_TYPE`, `ARGUS_DB_URL` and `ARGUS_MASTER_KEY`.
2. Set `PORT` if another service already uses 8080, and set `ARGUS_PUBLIC_URL` to the address people open, for example `http://argus-vm:8081`.
3. Run `argus.bat`, choose **6 Install**, then **1 Start**.
4. Allow the port through Windows Firewall so other machines can reach it (as Administrator):
   ```powershell
   New-NetFirewallRule -DisplayName "Argus" -Direction Inbound -Protocol TCP -LocalPort 8081 -Action Allow
   ```

## The menu

| Option | What it does |
|---|---|
| **1 Start** | Builds the server and web UI (`npm run build`), then starts `npm start -w @argus/server` hidden in the background and waits until `/readyz` answers. |
| **2 Stop** | Stops the server and its child processes. |
| **3 Restart** | Stop, then Start. Use it after changing `.env` or pulling new code. |
| **4 Status** | Whether the process runs, and what `/readyz` reports: version, database and the worker's last heartbeat. |
| **5 Live log** | Follows the log as readable lines (time, level, message). Press Ctrl+C, then **N**, to return to the menu. |
| **6 Install** | `npm ci`. Run it after a `git pull` that changes dependencies, then Restart. |
| **0 Exit** | Closes the menu. Argus keeps running. |

The log is written to `logs\argus.log`. Each start moves the previous log to `logs\argus.previous.log`.

## Notes

- **Not a Windows service.** Argus started from the menu does not start again after a reboot. To run it at boot, use a service wrapper (for example [NSSM](https://nssm.cc) running `node --env-file=.env apps\server\dist\main.js` in the repository root), or Task Scheduler.
- **Settings come from `.env`.** `npm start` reads it from the repository root; variables already set in the Windows environment take precedence.
- **Several instances can share one database.** Use the same `ARGUS_MASTER_KEY` on each. Set `SCAN=false` on instances that should not run scans (see [Configuration](../configuration.md)).
