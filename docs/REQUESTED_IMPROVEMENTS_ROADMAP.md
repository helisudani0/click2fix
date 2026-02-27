# Click2Fix v1.1 Execution Roadmap (Final)

This roadmap is the execution companion to `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`.
It defines release sequencing, ownership focus, and hard release gates.

## Release Objective

Ship v1.1 as a SOC-grade decision and response upgrade focused on:

1. Better triage quality.
2. Better incident operations.
3. Safer and verifiable automation.
4. Better reliability under scale.

## Workstream Priorities

## P0: SOC Signal Quality

- Tighten IOC enrichment quality and confidence handling.
- Add SOC-grade MITRE ATT&CK mapping depth and multi-mapping support.
- Tighten alert summaries and recommendations for analyst decision support.

## P1: Incident and Governance Layer

- Incident correlation and grouping.
- Incident assignment and SLA state tracking.
- Trusted automation context classification and alert correlation.

## P1: Response Correctness

- Dry-run contract (`dry_run` JSON only) + simulation audit events.
- Closed-loop remediation verification with freshness checks and backoff.
- Reliable long-running execution state semantics.

## P2: Resilience and Platform Operations

- Docker resource governance + backend circuit breaker.
- Wazuh/Indexer session pooling and retry/backoff tuning.
- Scheduler completion (health-check + integrity sweep).
- Linux connector parity hardening.

## Sequenced Delivery

1. P0 SOC Signal Quality
2. P1 Incident and Governance Layer
3. P1 Response Correctness
4. P2 Resilience and Platform Operations

## Definition of Done per Workstream

### P0 Done

- IOC, MITRE, and summary outputs are context-aware and operationally useful.
- Analysts can triage top recurring alert families without fallback to raw-only interpretation.

### P1 Incident/Governance Done

- Related alerts are correlated into incident records.
- Incidents have owner/priority/status/SLA fields and auditable assignment changes.
- Automation context classification is visible and queryable.

### P1 Response Done

- Dry-run paths never execute endpoint-side change.
- Verification outcomes persist as verified/not_verified/stale_scan.
- Long-running tasks do not report false failure when still in-progress.

### P2 Done

- Platform remains stable under planned concurrency profile.
- Circuit breaker and scheduler behaviors are observable and auditable.

## Release Gates (Must Pass)

- SOC quality gate: improved summary/recommendation fidelity for target alert families.
- Safety gate: dry-run and verification correctness validated end-to-end.
- Governance gate: full audit trace for high-risk actions and incident handoffs.
- Scale gate: no recurring OOM/queue stall under stress test baseline.

## KPI Tracking for v1.1

- MTTR trend versus v1.0 baseline.
- Analyst touches per incident.
- False-positive escalation rate.
- Verified remediation completion rate.
- Incident queue SLA compliance.

## Notes

- This roadmap intentionally prioritizes cyber operations value over patch-only workflows.
- Patch/remediation remains supported, but not the primary product identity.
- For full technical scope, data model, and API details use `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`.
