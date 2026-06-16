# Click2Fix

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20712097.svg)](https://doi.org/10.5281/zenodo.20712097)

Click2Fix is a SOC operations and response platform for Wazuh-managed environments.  
It gives IT/security teams one console for triage, response, remote command execution, verification, and audit evidence.

## Current Release

- Latest published stable tag: `v1.1.10`
- Stable deployment model: appliance installer + Docker images (GHCR)
- Active implementation track in this repo: `v2 foundation / native services MVP`

## Research and Citation

Click2Fix is published as a citable research artifact:

- DOI: [`10.5281/zenodo.20712097`](https://doi.org/10.5281/zenodo.20712097)
- Paper: **Click2Fix: Design and Implementation of an Open-Source SOAR Platform for Automated SOC Operations**

If you use Click2Fix in research, evaluation, or derivative work, cite:

```bibtex
@misc{click2fix2026,
  title        = {Click2Fix: Design and Implementation of an Open-Source SOAR Platform for Automated SOC Operations},
  author       = {Sudani, Heli},
  year         = {2026},
  doi          = {10.5281/zenodo.20712097},
  url          = {https://doi.org/10.5281/zenodo.20712097}
}
```

## Current Product State

- Stable shipped line: `v1.1.10` remains the current release baseline for the Wazuh-centric product flow.
- Built in code today: `/api/v2/agents/*`, `/api/v2/events/*` (search, raw, ingest, queue, replay, lifecycle), extracted `agent-manager`, `event-indexer`, `alert-service`, `case-service`, `soar-service`, `ingest-gateway`, and a partial native `endpoint-agent`.
- Still remaining before a production-ready v2 claim: full detection-service extraction, incidents extraction, zero-trust service auth, mTLS, signed command/policy envelopes, HA/DR validation, unified console depth, and deeper own-agent EDR/XDR features.

## What's New in v1.1.10 (Current Codebase)

- Detection and analyst workflow upgrades:
  - IOC enrichment extraction/normalization and confidence scoring hardening
  - deeper MITRE ATT&CK mapping with ranking and confidence persistence
  - tighter analyst summary/recommendation generation in analytics outputs
  - incident correlation/grouping, assignment, priority, SLA, and due-state lifecycle workflows
- Response and verification upgrades:
  - winget-backed Windows package remediation with bootstrap fallback and cleaner verification output
  - Global Shell command-file execution on Windows, reusable shell sessions, and optional assistant-guided command planning/retry
  - org-level AI runtime configuration from Org Admin (provider/key/model) for Global Shell assistant, playbook generation, and analytics insights
  - post-action verification reconciliation for already-satisfied package states and pending SCA verification loops
  - scheduler jobs API parity with lifecycle actions (`create`, `update`, `run-now`, pause/resume via toggle)
  - fleet and per-agent SCA rollups + recommendation APIs
  - circuit-breaker transition telemetry, audit events, and execution reconciliation improvements
- Console and operations UX upgrades:
  - upgraded analytics/agents chart rendering pipeline and visual polish for SOC-facing dashboards
  - Cases IOC graph loading reliability hardening and render-path cleanup
  - Actions workspace reflow: vertical target selection on top, action catalog on the left, execution plan on the right
  - Executions workspace filtering cleanup: removed module filter, added user-friendly time presets (`24h`, `7d`, `30d`) and custom date/time range filtering
  - Execution detail keeps playbook snapshot visibility for long-term auditability and retrospective analysis

## What Click2Fix Does

- Ingests and operationalizes Wazuh alerts, vulnerabilities, and agent data.
- Executes response actions across endpoints with approvals and audit trails.
- Provides Global Shell for direct `PowerShell` / `CMD` execution on selected Windows agents, with reusable session IDs and optional assistant-guided command generation.
- Tracks execution lifecycle with evidence, endpoint output, post-action verification, and result summaries.
- Supports scheduler-driven jobs (health checks, recurring operations).
- Preserves forensic integrity workflows and chain-of-custody evidence handling.
- Keeps governance visibility through approvals, audit logs, changes, and case tracking.
- Includes appliance control workflows for first-time setup, reconfigure, start/stop/restart, logs, and upgrade.

## How It Works

1. Click2Fix connects to Wazuh Manager and Wazuh Indexer APIs.
2. Analysts triage alerts/vulnerabilities in the frontend.
3. Analysts/admins launch actions or Global Shell commands against selected agents.
4. Backend executes through endpoint connectors, captures stdout/stderr and structured evidence.
5. Results, approvals, and audit records are persisted and visible in execution history.

## SCA Hardening API (v1.1)

- `GET /api/agents/{agent_id}/sca`
  - supports `include_checks`, `checks_limit`, `recommendation_limit`
  - returns full policy/check payload and per-agent ranked failed checks when `include_checks=true`
- `GET /api/agents/sca/fleet`
  - supports `group`, `agent_ids`, `status`, `platform`, `limit_agents`
  - supports `sca_limit`, `checks_limit`, `recommendation_limit`, `fleet_recommendation_limit`, `parallelism`
  - returns:
    - per-agent SCA rollup + recommendations
    - fleet-wide ranked failed-check recommendations

## MITRE Intelligence API (v1.1)

- `GET /mitre/alert/{alert_id}`
  - returns all mapped techniques for an alert including `confidence`, `source`, `mapping_rank`
  - marks top-ranked mapping as `is_primary=true`
- `GET /analytics/alert/{alert_id}`
  - includes `mitre.primary` and `mitre.mappings` for confidence-based triage context

## IOC Intelligence API (v1.1)

- `GET /ioc/{alert_id}`
  - returns per-source IOC enrichment evidence rows with score, verdict, details, and observation timestamp
  - supports `include_summary=true` to return:
    - deduplicated unique indicators
    - high-confidence/suspicious counts
    - top indicator context for triage
- `GET /analytics/alert/{alert_id}`
  - includes `ioc_summary` (unique counts + top indicators) for context-aware alert narratives

## Incident Correlation API (v1.1)

- `POST /incidents/correlate`
  - correlates alerts by time window + agent/entity/tactic/IOC overlap
  - can persist grouped incidents and attach correlated alerts
- `GET /incidents`
  - incident queue with filters for status/owner/priority/due state
  - supports `include_alerts` and `include_history` for analyst workflow visibility
- `PATCH /incidents/{incident_id}`
  - updates status/priority/owner/due/escalation fields and writes workflow/SLA events
- `POST /incidents/{incident_id}/assign`
  - explicit assignment handoff endpoint with assignment + SLA history persistence

## Governance Automation Context API (v1.1)

- `POST /governance/automation-context/profiles`
  - creates trusted automation context profiles for action/actor/target/tactic matching
- `GET /governance/automation-context/profiles`
  - lists automation context profiles (supports `enabled_only=true`)
- `POST /governance/automation-context/validate`
  - validates execution context, classifies related alerts, and can persist correlation records
- `GET /governance/alerts/correlated?execution_id={id}`
  - returns correlated alerts for an execution and auto-generates them when missing

## Scheduler API Parity (v1.1)

- `GET /scheduler/jobs`
- `POST /scheduler/jobs`
- `PATCH /scheduler/jobs/{job_id}`
- `POST /scheduler/jobs/{job_id}/run-now`
- Backward-compatible routes remain available:
  - `GET /scheduler`
  - `POST /scheduler`
  - `POST /scheduler/{job_id}/run`
  - `POST /scheduler/{job_id}/toggle`

## Core Modules

- `frontend/`: React (Vite) SOC console UI.
- `backend/`: FastAPI APIs, orchestration, execution engine, scheduler, integrations.
- `services/`: extracted v2-native services (`agent-manager`, `event-indexer`, `ingest-gateway`, `alert-service`, `case-service`, `soar-service`, and detection-service scaffold).
- `agents/`: native endpoint-agent MVP.
- `deploy/`: Wazuh active-response artifacts and appliance packaging/install tooling.
- `docker/`: container build files and compose stack for runtime deployment.

## Tech Stack

- Backend: Python, FastAPI, SQLAlchemy, APScheduler
- Frontend: React, Vite
- Datastores: PostgreSQL, SQLite/WAL, optional OpenSearch for v2 event indexing
- Integrations: Wazuh API, Wazuh Indexer API
- Packaging/Runtime: Docker, Docker Compose, GitHub Releases + GHCR

## Deployment Paths

### 1. Appliance Installer (Customer-Friendly)

Use release assets from:

- `https://github.com/helisudani0/click2fix/releases/latest`

Depending on release packaging, assets may include:

- `click2fix-appliance-installer-<version>.zip`
- optional: `click2fix-appliance-<version>.ova` for direct VM import

Customer flow:

1. Download `click2fix-appliance-installer-<version>.zip`
2. Extract on target host
3. Run `setup.cmd` (Windows) or `setup.sh` (Linux)
4. Provide Wazuh, Indexer, and endpoint connector credentials when prompted
5. Access UI on the deployed host IP/port

After first setup, running `setup.cmd` / `setup.sh` opens the Control Center for lifecycle operations.

No-ZIP bootstrap path:

- Windows:

```powershell
$version = "v1.1.10"
Invoke-WebRequest "https://raw.githubusercontent.com/helisudani0/click2fix/$version/deploy/appliance/bootstrap-from-github.ps1" -OutFile .\bootstrap-from-github.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap-from-github.ps1 -Owner helisudani0 -Repo click2fix -Version $version -InstallDir C:\Click2Fix -PullImages
```

- Linux:

```bash
VERSION=v1.1.10
curl -fsSL "https://raw.githubusercontent.com/helisudani0/click2fix/${VERSION}/deploy/appliance/bootstrap-from-github.sh" -o ./bootstrap-from-github.sh
chmod +x ./bootstrap-from-github.sh
OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix PULL_IMAGES=true ./bootstrap-from-github.sh
```

### 1A. Windows CMD-Only Path (No ZIP, No PowerShell)

Use this path when endpoint policy blocks `.zip` extraction and/or `.ps1` execution.

Full command reference (install + manage + troubleshooting):

- `deploy/appliance/CMD_INSTALL_AND_MANAGE.md`

1. Prepare folder and download required appliance runtime files from GitHub raw:

```cmd
set C2F_VERSION=v1.1.10
mkdir C:\Click2Fix
cd /d C:\Click2Fix
curl -fL -o docker-compose.yml https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/docker-compose.appliance.yml
curl -fL -o .env.appliance.template https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/.env.appliance.template
curl -fL -o nginx.conf https://raw.githubusercontent.com/helisudani0/click2fix/%C2F_VERSION%/deploy/appliance/nginx.conf
copy /Y .env.appliance.template .env.appliance
```

2. Edit environment values:

```cmd
notepad .env.appliance
```

3. Set required values in `.env.appliance`:

```env
C2F_BACKEND_IMAGE=ghcr.io/helisudani0/click2fix-backend
C2F_FRONTEND_IMAGE=ghcr.io/helisudani0/click2fix-frontend
C2F_IMAGE_TAG=1.1.10
COMPOSE_PROJECT_NAME=click2fix
POSTGRES_PASSWORD=<strong-db-password>
JWT_SECRET=<long-random-secret>
WAZUH_URL=https://<wazuh-host>:55000
WAZUH_USER=<wazuh-user>
WAZUH_PASSWORD=<wazuh-password>
INDEXER_URL=https://<indexer-host>:9200
INDEXER_USER=<indexer-user>
INDEXER_PASSWORD=<indexer-password>
C2F_BOOTSTRAP_ADMIN_USERNAME=admin
C2F_BOOTSTRAP_ADMIN_PASSWORD=<strong-admin-password>
```

4. Optional GHCR login (required only if your GHCR packages are private):

```cmd
set GHCR_USER=<github-username>
set GHCR_PAT=<github-pat-with-read:packages>
echo %GHCR_PAT%| docker login ghcr.io -u %GHCR_USER% --password-stdin
set GHCR_PAT=
```

5. Pull and start services:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml pull
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans
```

6. Bootstrap/reset admin user explicitly (same behavior install scripts run):

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml exec -T -w /app backend python -m tools.bootstrap_admin --username admin --password <strong-admin-password> --role admin
```

7. Verify runtime:

```cmd
docker compose --env-file .env.appliance -f docker-compose.yml ps
docker compose --env-file .env.appliance -f docker-compose.yml logs --tail 120 backend
docker compose --env-file .env.appliance -f docker-compose.yml logs --tail 120 c2f-lb
```

8. Access URLs:

```text
Frontend UI: http://localhost:5173
Backend API docs: http://localhost:8000/docs
Backend Ops: http://localhost:8000/ops
```

Important notes:

- Use `C2F_IMAGE_TAG=1.1.10` (without `v`) for current published images.
- Always pass `--env-file .env.appliance` on `docker compose` commands, or create `.env` from `.env.appliance`.
- If you see `...click2fix-backend:local`, your `.env.appliance` still has default local image values.
- If you see an `nginx.conf` mount error, ensure `C:\Click2Fix\nginx.conf` exists as a file.

CMD equivalents for `setup.cmd` / Control Center operations:

```cmd
:: Start stack
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans

:: Stop stack
docker compose --env-file .env.appliance -f docker-compose.yml stop

:: Restart stack
docker compose --env-file .env.appliance -f docker-compose.yml restart

:: Status
docker compose --env-file .env.appliance -f docker-compose.yml ps

:: Tail backend logs
docker compose --env-file .env.appliance -f docker-compose.yml logs -f backend

:: Upgrade to a new image tag
notepad .env.appliance
:: set C2F_IMAGE_TAG=<new-tag>
docker compose --env-file .env.appliance -f docker-compose.yml pull
docker compose --env-file .env.appliance -f docker-compose.yml up -d --remove-orphans --force-recreate backend frontend
docker compose --env-file .env.appliance -f docker-compose.yml ps
```

Current `v1.1.10` appliance image set:

- `ghcr.io/helisudani0/click2fix-backend:<version>`
- `ghcr.io/helisudani0/click2fix-frontend:<version>`
- `postgres:16`

VM/OVA path for environments where Windows security policies block ZIP/script delivery:

- build the current-version OVA stage bundle from `deploy/appliance/ova/`
- import that staged appliance tree into an Ubuntu VM
- install the bundled first-boot service
- export the VM as an OVA for customer import
- publish that `.ova` + `.ova.sha256` as release assets for direct customer download

One-click release asset publish for OVA:

- run GitHub Actions workflow `.github/workflows/publish-ova-asset.yml`
- inputs:
  - `version` (for example `v1.1.10`)
  - `ova_url` (HTTPS URL to your exported `.ova`)
- workflow attaches:
  - `click2fix-appliance-<version>.ova`
  - `click2fix-appliance-<version>.ova.sha256`

Important:

- raw bootstrap and OVA packaging reduce Windows download friction
- they do not replace Authenticode signing if you want SmartScreen reputation on Windows-delivered scripts/installers

### 2. Developer/Local Stack

From `docker/`:

```bash
docker compose up -d --build
```

Notes:

- API traffic is served through the local gateway on `http://localhost:8000`.
- Scale backend replicas with: `docker compose up -d --scale backend=3`
- Redis is included to fan out execution WebSocket events across replicas.

## Minimum Prerequisites (Typical 50-Agent Baseline)

- Docker + Docker Compose
- 4 vCPU / 8 GB RAM / SSD-backed storage
- Reachability from Click2Fix backend to:
  - Wazuh Manager API
  - Wazuh Indexer API
  - Endpoint management ports (WinRM/SSH, based on connectors in use)

Required configuration (environment-driven):

- Wazuh API URL + credentials
- Indexer URL + credentials
- JWT secret
- Endpoint connector credentials (global and optional per-agent overrides)

## AI Enablement (v1.1.10)

Default behavior:

- AI is disabled by default until a valid provider API key is configured.

Enable using environment variables:

- `C2F_AI_FEATURES_ENABLED=true`
- `C2F_LLM_API_KEY=<your-key>`
- optional: `C2F_LLM_PROVIDER`, `C2F_LLM_MODEL`, `C2F_LLM_BASE_URL`

Enable from frontend (Org Admin):

- Open **Org Admin -> Platform AI Configuration**
- Set `enabled`, provider/model, and API key
- Save configuration
- Changes apply immediately for AI-enabled areas (Global Shell assistant, Playbooks AI generation, Analytics AI insights) without container restart

## Security Notes

- Keep deployment single-tenant and inside internal network/VPN.
- Rotate all bootstrap/test credentials before go-live.
- Disable demo users in production.
- Restrict UI access to authorized admin/analyst roles.
- Back up database volumes and operational evidence stores.

## Release Status

- Current repo target version: `v1.1.10`
- Latest published release: `v1.1.10`
- Published images:
  - `ghcr.io/helisudani0/click2fix-backend:<version>`
  - `ghcr.io/helisudani0/click2fix-frontend:<version>`
  - `postgres:16`
- Alternate delivery paths for the current line:
  - raw GitHub bootstrap (no ZIP required)
  - OVA stage-builder for VM-based delivery
