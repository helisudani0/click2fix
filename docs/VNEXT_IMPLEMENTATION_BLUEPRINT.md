# Click2Fix v1.1 Final Upgrade Plan

This document is the final scope and execution plan for the next upgrade.
It supersedes earlier draft notes for v1.1 planning and focuses on shipping a SOC-grade release.

## Product Definition for v1.1

Click2Fix v1.1 is a Wazuh-centered SOC decision and response platform, not only a remediation runner.

Core product promise:

- Raise analyst decision quality with better context, confidence, and mapping.
- Execute actions safely with approval, verification, and evidence.
- Operate reliably at enterprise scale (50+ agents baseline, expandable).

## Upgrade Objectives

1. Improve SOC triage quality (IOC enrichment, MITRE depth, alert narrative quality).
2. Improve incident-level operations (correlation, prioritization, assignment, SLA visibility).
3. Improve response correctness (dry-run, verification, idempotent outcomes, long-running task clarity).
4. Improve governance and trust (audit, automation context, chain-of-custody integrity).
5. Improve performance and operational resilience (resource governance, connection pooling, scheduler).

## In Scope

### 1) SOC Signal Quality Hardening

- IOC enrichment v2:
  - direct connectors for AlienVault OTX and Abuse.ch
  - normalized scoring with confidence and source weighting
  - support for IP, hash, domain, and URL IOCs
  - persisted enrichment evidence with timestamps
- MITRE ATT&CK mapping v2:
  - use native Wazuh ATT&CK fields first
  - add deterministic fallback mapping and keyword heuristics
  - allow multiple tactic/technique mappings per alert
  - confidence-scored primary mapping for triage screens
- Alert summary and recommendations v2:
  - context-aware summaries using rule, IOC, MITRE, recurrence, and host context
  - recommendation logic tied to tactic/risk and available action capabilities
  - false-positive estimation based on multi-signal evidence, not severity only

### 2) Incident and Analyst Operations

- Incident correlation model:
  - correlate alerts by time window, agent, identity, tactic, and IOC overlap
  - produce correlated incident groups from related alerts
- Incident queue operations:
  - status, owner, priority, due time, and escalation state
  - explicit analyst workflow: open -> investigate -> contain -> verified -> closed
- SLA and workload visibility:
  - aging and due-state indicators
  - assignment and handoff audit history

### 3) Response Safety and Verification

- Dry-run standardization:
  - `dry_run: true|false` in request JSON only
  - persist `playbook_simulated` events with actor, targets, and resolved plan
- Closed-loop remediation verification:
  - trigger `sca-rescan` after relevant remediation actions
  - use exponential backoff and scan freshness checks
  - record verified/not_verified/stale_scan outcomes
- Execution state reliability:
  - preserve strict success/failed/partial semantics
  - improve handling for long-running update operations and asynchronous completion
- Global Shell guardrail:
  - command transport only; no hidden command rewrite behavior

### 4) Governance, Audit, and Detection Context

- Trusted automation context:
  - correlate alerts with approved execution context
  - classify events as `expected_admin_activity`, `review_required`, or `suspicious`
- Evidence integrity:
  - SHA-256 at ingest, re-verify on lock/download/export
  - periodic integrity sweep and drift events
- Change governance:
  - policy-driven approvals for high-risk actions
  - immutable audit log for request/approval/execution/verification chain

### 5) Platform Resilience and Scale

- Resource governance:
  - Docker reservations and limits for db/backend/frontend
  - environment-driven profiles via `.env`
  - backend circuit breaker under memory pressure
- Performance tuning:
  - persistent `requests.Session` for Wazuh and Indexer clients
  - retry/backoff and keep-alive tuning
  - latency stats in execution metadata
- Scheduler completion:
  - recurring health-check and forensic integrity sweep jobs
- Connector parity:
  - maintain Windows first-class path
  - strengthen Linux execution parity where capabilities exist

## Explicit Gaps Closed in v1.1 Plan

This final plan explicitly closes gaps that were previously under-defined:

1. Incident model and analyst queue are now first-class scope.
2. Correlation rules are defined around entity/time/tactic/IOC overlap.
3. Risk scoring includes context beyond severity.
4. Detection tuning loop is included in governance workflow.
5. KPI-driven release acceptance is now required.

## Data Model Additions (Finalized for v1.1)

- `execution_context`
- `automation_context_profiles`
- `alert_execution_correlation`
- `ioc_enrichment_records`
- `forensic_integrity_sweeps`
- `incidents`
- `incident_alerts`
- `incident_assignments`
- `incident_sla_events`
- `detection_tuning_suggestions`

Required common fields: `org_id`, `created_at`, `updated_at`, `created_by`.

## API Blueprint (v1.1)

### Correlation and Governance

- `POST /governance/automation-context/profiles`
- `GET /governance/automation-context/profiles`
- `POST /governance/automation-context/validate`
- `GET /governance/alerts/correlated?execution_id={id}`
- `POST /incidents/correlate`
- `GET /incidents`
- `PATCH /incidents/{incident_id}`
- `POST /incidents/{incident_id}/assign`

### SOC Summaries and Intelligence

- `GET /analytics/alert/{alert_id}`
- `GET /ioc/{alert_id}`
- `GET /mitre/alert/{alert_id}`
- `GET /mitre/heatmap`

### SCA Policy and Verification

- `GET /sca/policies`
- `POST /sca/policies/{policy_id}/plan`
- `POST /sca/policies/{policy_id}/dry-run`
- `POST /sca/policies/{policy_id}/execute`
- `GET /sca/policies/{policy_id}/runs/{run_id}`

### Scheduler

- `GET /scheduler/jobs`
- `POST /scheduler/jobs`
- `PATCH /scheduler/jobs/{job_id}`
- `POST /scheduler/jobs/{job_id}/run-now`

## Delivery Phases

### Phase 1: SOC Signal Quality (Priority 0)

- IOC enrichment v2
- MITRE mapping v2
- alert summary and recommendation v2

Exit criteria:

- summary/recommendation quality is analyst-usable across top recurring alert families
- MITRE coverage and confidence are visibly improved

### Phase 2: Incident Operations (Priority 1)

- incident correlation
- incident queue fields and assignment workflow
- SLA/aging indicators

Exit criteria:

- related alerts are grouped with measurable triage reduction
- analysts can assign and track incident ownership/SLA state

### Phase 3: Response Trust Layer (Priority 1)

- dry-run semantics and simulation audit
- closed-loop remediation verification
- trusted automation context classification

Exit criteria:

- remediation outcomes are verifiable and auditable end-to-end
- trusted automation context suppresses noise without hiding raw evidence

### Phase 4: Scale and Resilience (Priority 2)

- resource governance and circuit breaker hardening
- session pooling performance improvements
- scheduler completion and integrity sweep automation

Exit criteria:

- stable operation under target concurrency
- no recurring OOM or queue starvation under planned load profile

## Acceptance Criteria (Release Gate)

- Global Shell executes entered command unchanged for PowerShell and CMD transport paths.
- Executor remains stable under configured stress profile without OOM.
- Verification loop never marks stale SCA data as successful remediation.
- Dry-run emits auditable `playbook_simulated` events with actor and target set.
- MITRE mapping supports multi-technique persistence per alert.
- IOC enrichment stores normalized confidence and source evidence.
- Incident queue supports owner, priority, status, and SLA visibility.
- Alert summaries and recommendations are context-aware and not severity-only.

## KPI Targets (Go-Live Tracking)

- Reduce median analyst touches per incident.
- Improve triage confidence for high-severity incidents.
- Decrease false-positive escalation rate.
- Increase verified auto-remediation completion rate.
- Track MTTR improvement versus v1.0 baseline.

## Non-Goals for v1.1

- Replacing Wazuh as a detection engine.
- Full SOAR marketplace/integration ecosystem expansion.
- Major UI redesign unrelated to SOC workflow outcomes.

## Operational Notes

- Keep deployment single-tenant in internal network/VPN.
- Continue using appliance packaging path in `deploy/appliance`.
- Keep safe publish workflow from `docs/SAFE_GITHUB_PUBLISH.md`.
