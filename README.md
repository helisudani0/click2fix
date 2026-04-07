# Click2Fix

Click2Fix is a SOC operations and response platform for Wazuh-managed environments.  
It gives IT/security teams one console for triage, response, remote command execution, verification, and audit evidence.

## Current Release

- Latest published stable tag: `v1.1.4`
- Stable deployment model: appliance installer + Docker images (GHCR)
- Active implementation track in this repo: `v2 foundation / native services MVP`

## Current Product State

- Stable shipped line: `v1.1.4` remains the current release baseline for the Wazuh-centric product flow.
- Built in code today: `/api/v2/agents/*`, `/api/v2/events/*` (search, raw, ingest, queue, replay, lifecycle), extracted `agent-manager`, `event-indexer`, `alert-service`, `case-service`, `soar-service`, `ingest-gateway`, and a partial native `endpoint-agent`.
- Still remaining before a production-ready v2 claim: full detection-service extraction, incidents extraction, zero-trust service auth, mTLS, signed command/policy envelopes, HA/DR validation, unified console depth, and deeper own-agent EDR/XDR features.

## What's New in v1.1.4 (Current Codebase)

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
$version = "v1.1.4"
Invoke-WebRequest "https://raw.githubusercontent.com/helisudani0/click2fix/$version/deploy/appliance/bootstrap-from-github.ps1" -OutFile .\bootstrap-from-github.ps1
powershell -ExecutionPolicy Bypass -File .\bootstrap-from-github.ps1 -Owner helisudani0 -Repo click2fix -Version $version -InstallDir C:\Click2Fix -PullImages
```

- Linux:

```bash
VERSION=v1.1.4
curl -fsSL "https://raw.githubusercontent.com/helisudani0/click2fix/${VERSION}/deploy/appliance/bootstrap-from-github.sh" -o ./bootstrap-from-github.sh
chmod +x ./bootstrap-from-github.sh
OWNER=helisudani0 REPO=click2fix VERSION=${VERSION} INSTALL_DIR=/opt/click2fix PULL_IMAGES=true ./bootstrap-from-github.sh
```

Current `v1.1.4` appliance image set:

- `ghcr.io/helisudani0/click2fix-backend:<version>`
- `ghcr.io/helisudani0/click2fix-frontend:<version>`
- `postgres:16`

VM/OVA path for environments where Windows security policies block ZIP/script delivery:

- build the current-version OVA stage bundle from `deploy/appliance/ova/`
- import that staged appliance tree into an Ubuntu VM
- install the bundled first-boot service
- export the VM as an OVA for customer import
- publish that `.ova` + `.ova.sha256` as release assets for direct customer download

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

## AI Enablement (v1.1.4)

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

- Current repo target version: `v1.1.4`
- Latest published release: `v1.1.4`
- Published images:
  - `ghcr.io/helisudani0/click2fix-backend:<version>`
  - `ghcr.io/helisudani0/click2fix-frontend:<version>`
  - `postgres:16`
- Alternate delivery paths for the current line:
  - raw GitHub bootstrap (no ZIP required)
  - OVA stage-builder for VM-based delivery
