# Click2Fix

Click2Fix is a SOC operations and response platform for Wazuh-managed environments.  
It gives IT/security teams one console for triage, response, remote command execution, verification, and audit evidence.

## Current Release

- Current codebase target: `v1.1.0`
- Latest published stable tag: `v1.0.2`
- Deployment model: appliance installer + Docker images (GHCR)

## What's New in v1.1.0 (Current Codebase)

- SOC signal quality upgrades:
  - IOC enrichment extraction/normalization and confidence scoring hardening
  - deeper MITRE ATT&CK mapping with ranking and confidence persistence
  - tighter analyst summary/recommendation generation in analytics outputs
- Incident and governance upgrades:
  - incident correlation/grouping + queue workflows
  - assignment, priority, SLA, and due-state lifecycle endpoints
  - trusted automation context profiles and execution-alert correlation
- Response and operations upgrades:
  - dry-run simulation semantics and audit trail hardening
  - verification correctness and execution reconciliation improvements
  - scheduler jobs API parity with lifecycle actions (`create`, `update`, `run-now`, pause/resume via toggle)
  - fleet and per-agent SCA rollups + recommendation APIs
  - circuit-breaker transition telemetry and audit events

## Remaining v1.1 Scope (Single Backlog)

- `docs/V1_1_REMAINING.md` is the only active remaining-work document.
- Archived references:
  - `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`
  - `docs/REQUESTED_IMPROVEMENTS_ROADMAP.md`

## What Click2Fix Does

- Ingests and operationalizes Wazuh alerts, vulnerabilities, and agent data.
- Executes response actions across endpoints with approvals and audit trails.
- Provides Global Shell for direct `PowerShell` / `CMD` execution on selected Windows agents.
- Tracks execution lifecycle with evidence, endpoint output, and result summaries.
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
- `deploy/`: Wazuh active-response artifacts and appliance packaging/install tooling.
- `docker/`: container build files and compose stack for runtime deployment.
- `docs/`: operations docs, release safety checklist, roadmap/planning notes.

## Tech Stack

- Backend: Python, FastAPI, SQLAlchemy, APScheduler
- Frontend: React, Vite
- Database: PostgreSQL
- Integrations: Wazuh API, Wazuh Indexer API
- Packaging/Runtime: Docker, Docker Compose, GitHub Releases + GHCR

## Deployment Paths

### 1. Appliance Installer (Customer-Friendly)

Use release assets from:

- `https://github.com/helisudani0/click2fix/releases/latest`

Customer flow:

1. Download `click2fix-appliance-installer-<version>.zip`
2. Extract on target host
3. Run `setup.cmd` (Windows) or `setup.sh` (Linux)
4. Provide Wazuh, Indexer, and endpoint connector credentials when prompted
5. Access UI on the deployed host IP/port

After first setup, running `setup.cmd` / `setup.sh` opens the Control Center for lifecycle operations.

### 2. Developer/Local Stack

From `docker/`:

```bash
docker compose up -d --build
```

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

## Security Notes

- Keep deployment single-tenant and inside internal network/VPN.
- Rotate all bootstrap/test credentials before go-live.
- Disable demo users in production.
- Restrict UI access to authorized admin/analyst roles.
- Back up database volumes and operational evidence stores.

## Documentation Index

- Appliance install/upgrade: `deploy/appliance/README.md`
- OVA packaging blueprint: `deploy/appliance/OVA_BUILD_BLUEPRINT.md`
- v1.1 remaining work (active): `docs/V1_1_REMAINING.md`
- v1.1 archived blueprint: `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`
- v1.1 archived roadmap: `docs/REQUESTED_IMPROVEMENTS_ROADMAP.md`
- Safe GitHub publish checklist: `docs/SAFE_GITHUB_PUBLISH.md`

## Release Status

- Current repo target version: `v1.1.0`
- Latest published release: `v1.0.2`
- Published images:
  - `ghcr.io/helisudani0/click2fix-backend:<version>`
  - `ghcr.io/helisudani0/click2fix-frontend:<version>`
