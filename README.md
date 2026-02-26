# Click2Fix

Click2Fix is a SOC operations and response platform for Wazuh-managed environments.  
It gives IT/security teams one console for triage, response, remote command execution, verification, and audit evidence.

## What Click2Fix Does

- Ingests and operationalizes Wazuh alerts, vulnerabilities, and agent data.
- Executes response actions across endpoints with approvals and audit trails.
- Provides Global Shell for direct `PowerShell` / `CMD` execution on selected Windows agents.
- Tracks execution lifecycle with evidence, endpoint output, and result summaries.
- Supports scheduler-driven jobs (health checks, recurring operations).
- Preserves forensic integrity workflows and chain-of-custody evidence handling.
- Keeps governance visibility through approvals, audit logs, changes, and case tracking.

## How It Works

1. Click2Fix connects to Wazuh Manager and Wazuh Indexer APIs.
2. Analysts triage alerts/vulnerabilities in the frontend.
3. Analysts/admins launch actions or Global Shell commands against selected agents.
4. Backend executes through endpoint connectors, captures stdout/stderr and structured evidence.
5. Results, approvals, and audit records are persisted and visible in execution history.

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
- vNext implementation blueprint (detailed planning): `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`
- Safe GitHub publish checklist: `docs/SAFE_GITHUB_PUBLISH.md`
- Requested improvements roadmap: `docs/REQUESTED_IMPROVEMENTS_ROADMAP.md`

## Release Status

- Latest release: `v1.0.1`
- Published images:
  - `ghcr.io/helisudani0/click2fix-backend:<version>`
  - `ghcr.io/helisudani0/click2fix-frontend:<version>`