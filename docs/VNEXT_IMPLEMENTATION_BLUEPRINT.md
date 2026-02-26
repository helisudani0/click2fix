# Click2Fix vNext Blueprint (Implementation Plan)

This document captures the next-version blueprint and planning scope.  
It is preserved for future guidance and does not represent the exact current shipped state.

## Product Intent

Click2Fix should operate as a production-grade SOAR control plane where:

- Analysts can execute `PowerShell` and `CMD` remotely as-is across selected agents.
- Automated remediations are verifiable, auditable, and resilient at 50+ agent scale.
- Security telemetry remains visible, but trusted automation noise is classified correctly.
- SCA/CIS findings move from passive visibility to policy-driven correction workflows.

## Scope for Next Version

### 1. Platform Stability and Resource Governance

- Add Docker resource `reservations` and `limits` for `db`, `backend`, `frontend`.
- Make limits environment-driven through `.env` for small and large fleets.
- Enforce backend circuit breaker in executor ingestion:
  - if memory usage exceeds threshold (default 90% of configured limit), pause new ingestion.
  - resume automatically when usage drops below threshold.
  - always emit audit/evidence events during pause/resume.

### 2. Session Pooling and Performance

- Refactor `WazuhClient` and `IndexerClient` to use persistent `requests.Session`.
- Configure keep-alive and retry/backoff policy for transient API failures.
- Measure and expose per-execution API latency statistics in execution metadata.

### 3. Playbook and Action Dry-Run

- Use JSON request field only: `dry_run: true|false`.
- Do not use `X-Dry-Run` header in v1 path.
- Persist dry-run events as `playbook_simulated` with actor, target set, and resolved plan.
- Dry-run must never perform endpoint-side changes.

### 4. Closed-Loop Remediation Verification

- After successful remediation actions (`patch-windows`, `package-update`, related), trigger SCA rescan.
- Restart/rescan targets in bulk when API supports multi-agent payloads.
- Poll verification state with exponential backoff to reduce manager pressure.
- Validate scan freshness:
  - capture pre-remediation scan timestamp.
  - accept verification only if post-rescan timestamp is newer.
- Persist outcome as `verified`, `not_verified`, or `stale_scan`.

### 5. Scheduler and Policy Jobs

- Complete scheduler APIs and persistence semantics.
- Add default recurring fleet health-check policy (every 6-12 hours configurable).
- Add periodic forensic integrity sweep job:
  - recompute hash for stored artifacts.
  - compare with baseline hash.
  - log drift as high-priority audit events.

### 6. Forensic Integrity / Chain of Custody

- Compute SHA-256 at artifact ingest.
- Re-verify hash on lock/download/export.
- Record immutable integrity verification timeline per artifact.

### 7. Threat Intel Enrichment (Custom Connectors)

- Replace placeholder enrichment with direct feed connectors (AlienVault OTX, Abuse.ch).
- Extract IOC keys during ingestion (IP, hash, domain where available).
- Normalize feed responses into unified confidence/risk scoring model.
- Store enrichment evidence and timestamp for analyst review.

### 8. Cross-Platform Connector Parity

- Keep Windows connector as first-class path.
- Enable Linux execution paths (for example `patch-linux`, `firewall-drop`) with shared execution contract.
- Ensure action definitions remain agent-agnostic and target by platform capability.

### 9. Global Shell Principle (Critical)

- Global Shell is a command transport, not a command rewrite engine.
- User-provided command must execute exactly as entered for selected shell type.
- Backend may wrap only for transport, timeout, output capture, and evidence markers.
- No hidden hardcoded replacement logic for specific package/vendor commands.

### 10. Trusted Automation Context for Detection Tuning

- Maintain ATT&CK detections; do not suppress by default.
- Correlate detections with approved execution context:
  - actor
  - service account
  - source host
  - target
  - execution window
  - action family
- Classify into:
  - `expected_admin_activity`
  - `review_required`
  - `suspicious`
- Keep full original alert payload and ATT&CK mapping.

### 11. SCA/CIS Policy Remediation Layer

- Build control-to-remediation mapping catalog.
- Generate plan from failed controls with risk labels and reboot requirements.
- Support dry-run, approval, execute, verify, and score-delta report.
- Skip domain-managed controls by default unless explicitly overridden.

## Next Update Priorities

Before enabling broader vNext feature expansion, the next release focus is:

1. Tighten IOC enrichment quality and confidence handling.
2. Add SOC-grade MITRE ATT&CK mapping depth and coverage.
3. Tighten alert summaries and recommendations to improve accuracy and analyst usefulness.

After these are stabilized, delivery continues with the planned next-version scope in `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`.


## Proposed Architecture Changes

### Backend Modules

- `backend/core/endpoint_executor.py`
  - circuit breaker ingestion pause/resume
  - command transport normalization only
  - strict success/failure semantics from endpoint results
- `backend/core/wazuh_verification.py`
  - bulk rescan trigger
  - timestamp freshness validation
  - backoff policy
- `backend/core/scheduler.py`
  - recurring policy jobs for health-check and integrity sweep
- `backend/core/forensic_integrity.py`
  - baseline hash record + periodic sweep comparison
- `backend/core/enrichment.py`
  - custom IOC feed clients and score normalization
- `backend/api/actions.py`
  - dry-run behavior and simulation audit semantics
- `backend/api/scheduler.py`
  - policy job CRUD and execution telemetry
- `backend/api/vulnerabilities.py`
  - "open in manual shell" payload with exact target scoping

### Frontend Modules

- `frontend/src/pages/GlobalShell.jsx`
  - multi-agent selector parity with Actions/Vulnerabilities
  - clear command history: shell type, exact command, output preview
  - readable clean output section without dropping raw output
- `frontend/src/pages/Scheduler.jsx`
  - policy job management and run history
- vulnerabilities page
  - manual-shell handoff for selected vulnerability and affected targets only
- execution details views
  - timezone rendering (IST option/default if org configured)
  - stronger running/stuck indicators and stale-state reconciliation

## Data Model Additions (Proposed)

- `execution_context`
- `automation_context_profiles`
- `alert_execution_correlation`
- `sca_policy_profiles`
- `sca_control_mappings`
- `sca_policy_runs`
- `sca_control_run_results`
- `forensic_integrity_sweeps`
- `ioc_enrichment_records`

Required common fields: `org_id`, `created_at`, `updated_at`, `created_by`.

## API Blueprint (Proposed)

### Governance / Correlation

- `POST /governance/automation-context/profiles`
- `GET /governance/automation-context/profiles`
- `POST /governance/automation-context/validate`
- `GET /governance/alerts/correlated?execution_id={id}`

### SCA Policy Engine

- `GET /sca/policies`
- `GET /sca/agent/{agent_id}/results`
- `POST /sca/policies/{policy_id}/plan`
- `POST /sca/policies/{policy_id}/dry-run`
- `POST /sca/policies/{policy_id}/execute`
- `GET /sca/policies/{policy_id}/runs/{run_id}`

### Scheduler

- `GET /scheduler/jobs`
- `POST /scheduler/jobs`
- `PATCH /scheduler/jobs/{job_id}`
- `POST /scheduler/jobs/{job_id}/run-now`

## Delivery Plan

1. Stability first: resource limits + circuit breaker.
2. Performance: API session pooling.
3. Safety: dry-run + simulation audit.
4. Correctness: closed-loop verification with freshness checks.
5. Proactive ops: scheduler completion + default health-check and integrity sweep.
6. Analyst value: IOC enrichment and SCA policy remediation.
7. Platform breadth: Linux connector parity.
8. Detection clarity: trusted automation context classification.

## Acceptance Criteria

- Global Shell executes entered command unchanged for both `PowerShell` and `CMD`.
- Executor does not OOM under configured 60-worker stress window.
- Rescan verification does not mark stale pre-remediation SCA data as success.
- Partial package upgrades report partial success, not blanket failure.
- Every dry-run emits `playbook_simulated` audit event.
- Integrity sweep detects modified evidence and creates alertable audit records.
- Vulnerability-to-manual-shell flow scopes execution only to impacted agents.

## Risks and Controls

- Over-tuning ATT&CK alerts:
  - enforce multi-signal matching and keep review tier.
- Endpoint variance (different package managers, policies, permissions):
  - provide explicit per-endpoint output and reason codes.
- Long-running OS update workflows:
  - report asynchronous progress and avoid false "still running" status.

## Notes

- This is the implementation blueprint for the next version and should be treated as the source-of-truth planning document.
- Current production behavior may differ until each phase is completed.

## Deployment Model (50+ Agents)

Use a single-tenant deployment inside the company's internal network (or over site-to-site VPN), not on the public internet.

Recommended placement:

- Click2Fix host (Docker) on an internal management subnet.
- Network path from Click2Fix backend to:
  - Wazuh Manager API
  - Wazuh Indexer API
  - Endpoint management ports (WinRM/SSH)
- Access to Click2Fix UI restricted to IT/SOC admins via VPN, bastion, or corporate reverse proxy.

## Prerequisites Checklist

### 1. Core Infrastructure

- Linux or Windows host with Docker + Docker Compose.
- Minimum baseline for ~50 active agents:
  - 4 vCPU
  - 8 GB RAM
  - SSD-backed storage for DB volume/logs
- Stable DNS or fixed IPs for Wazuh manager/indexer and endpoints.

### 2. Wazuh Integration Prerequisites

- Wazuh Manager API URL/port reachable from Click2Fix backend.
- Wazuh Indexer URL/port reachable from Click2Fix backend.
- Dedicated Wazuh API user for Click2Fix with required permissions (recommended: scoped role; temporary bootstrap can be admin-equivalent during setup).
- TLS strategy decided:
  - preferred: trusted certificates + SSL verification enabled
  - lab fallback: verification disabled (not recommended for production)

### 3. Click2Fix Configuration Prerequisites

- Set and validate backend environment values:
  - `WAZUH_URL`
  - `WAZUH_USER`
  - `WAZUH_PASSWORD`
  - `INDEXER_URL`
  - `INDEXER_USER`
  - `INDEXER_PASSWORD`
- Set secure auth/session values:
  - `JWT_SECRET` (long random secret)
  - trusted hosts and allowed CORS origins in `backend/config/settings.yaml`
- Configure Docker resource limits in `docker/.env`:
  - DB/Backend/Frontend CPU + memory reservations and limits
  - circuit breaker thresholds

### 4. Endpoint Connectivity Prerequisites (Windows)

- Endpoints must be online and connected in Wazuh.
- WinRM enabled and listening on each managed endpoint (`5985` HTTP or `5986` HTTPS).
- Remote PowerShell execution enabled (`Enable-PSRemoting` and policy as required).
- Firewall allows inbound WinRM from Click2Fix backend host.
- Credentials configured:
  - global: `C2F_WINRM_USERNAME` / `C2F_WINRM_PASSWORD`
  - per-agent override when needed: `C2F_WINRM_USERNAME_<AGENTID>` / `C2F_WINRM_PASSWORD_<AGENTID>`
- Service account privilege model:
  - local admin rights for patching/OS actions
  - least privilege + auditing for lower-risk actions
- If using "Run as SYSTEM", execution account must have rights to create/start scheduled tasks.

### 5. Endpoint Connectivity Prerequisites (Linux, if enabled)

- Set `C2F_LINUX_CONNECTOR_ENABLED=true`.
- SSH reachable from backend to endpoints (default port 22 unless overridden).
- Configure `C2F_SSH_USERNAME` + password or key.
- Ensure non-interactive privilege escalation path exists for remediation commands (sudo policy).

### 6. Network/Firewall Port Matrix

- User browser -> Frontend: `5173` (or reverse-proxy HTTPS port).
- Frontend -> Backend API/WebSocket: `8000`.
- Backend -> PostgreSQL: `5432` (internal Docker network by default).
- Backend -> Wazuh Manager API: `55000` (typical).
- Backend -> Wazuh Indexer: `9200` (typical).
- Backend -> Windows endpoints: `5985/5986`.
- Backend -> Linux endpoints: `22` (if enabled).

### 7. Security and Operations Prerequisites

- Disable demo users in production (`allow_demo_users: false`).
- Rotate all bootstrap/default/test credentials before go-live.
- Restrict platform access by role (`admin`, `analyst`, `superadmin`) and audit all action execution.
- Configure backups:
  - PostgreSQL volume backups
  - evidence/attachment storage backups
- Define change-control rules for high-risk actions (`patch-*`, `custom-os-command`, OS update flows).

## Launch Procedure (Docker)

1. Populate `docker/.env` and backend env values (Wazuh/Indexer/connector credentials).
2. From the `docker/` directory:

```powershell
docker compose up -d --build
```

3. Validate containers are healthy:

```powershell
docker compose ps
docker compose logs -f backend
```

4. Open frontend UI and log in with a provisioned non-demo admin account.

5. In Click2Fix:
  - verify connector status
  - verify agent list sync
  - run `endpoint-healthcheck` on a pilot group
  - run one low-risk Global Shell command
  - verify execution evidence and audit log entries

## Go-Live Validation for 50+ Agents

- Connectivity success rate target:
  - >=95% on pilot batch before fleet-wide rollout
- Validate:
  - action queue throughput under expected concurrency
  - circuit breaker behavior under memory pressure
  - no false "running forever" executions
  - SCA rescan loop updates vulnerability status as expected
- Roll out in phases:
  - pilot group -> department group -> full fleet

## Appliance Packaging Path

For customer handover (Wazuh-style VM appliance), use artifacts in `deploy/appliance`:

- `deploy/appliance/docker-compose.appliance.yml`
- `deploy/appliance/.env.appliance.template`
- `deploy/appliance/install.sh`
- `deploy/appliance/install.ps1`
- `deploy/appliance/upgrade.sh`
- `deploy/appliance/upgrade.ps1`
- `deploy/appliance/build-local-images.sh`
- `deploy/appliance/build-local-images.ps1`
- `deploy/appliance/export-images.sh`
- `deploy/appliance/export-images.ps1`
- `deploy/appliance/import-images.sh`
- `deploy/appliance/import-images.ps1`
- `deploy/appliance/README.md`
- `deploy/appliance/OVA_BUILD_BLUEPRINT.md`

This keeps demo/dev workflow untouched while enabling customer installation without source-code operations.

GitHub distribution path:

- Release page: `https://github.com/<owner>/<repo>/releases/latest`
- Customer downloads installer zip from release assets and runs `setup.cmd` / `setup.sh`.
- Automation workflow: `.github/workflows/release-appliance.yml`
- Safe publish checklist: `docs/SAFE_GITHUB_PUBLISH.md`
