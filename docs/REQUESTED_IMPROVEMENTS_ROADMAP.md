Click2Fix Requested Improvements Roadmap (v1.1)
Purpose
This document captures all features and improvements requested for the next implementation phases to transform Click2Fix into a production-grade SOAR platform.
Global Decisions (Requested)
dry_run control will use request JSON (dry_run: true|false) in v1.
No X-Dry-Run header in v1 (single control path, no precedence ambiguity).
Docker Governance: Use both reservation and limit settings.
Environment-Driven: Docker limits must be tunable via .env to support different fleet sizes (50 vs 500 agents).
Requested Feature Backlog
1. Closed-Loop Remediation Verification
Feature Name: Post-Action Verification Loop
Logic: Automatically trigger follow-up verification after successful remediation.
Workflow: If patch-windows or package-update succeeds, the backend triggers sca-rescan via Wazuh API.
Resilience Nuance: Implement Exponential Back-off during the check phase to allow the Wazuh Manager time to process the scan results without flooding the API.
Goal: Move vulnerabilities from Active to Solved in Indexer without manual re-check.
2. Custom Threat Intel Enrichment (Built from Scratch)
Feature Name: Proprietary IOC Enrichment Engine
Logic: Replace stubs with custom connector logic to free community intel feeds (AlienVault OTX / Abuse.ch).
Workflow: Extract IOCs (IP/Hash) during ingestion, query feeds via raw requests, and store normalized scores.
Goal: Show risk scores to analysts before the remediation click path.
3. Forensic Integrity and Chain of Custody
Feature Name: Automated Evidence Hashing & Integrity Sweeps
Logic: Compute SHA-256 at ingest; verify on lock/download.
Advanced Nuance: Implement a "Periodic Integrity Sweep" via the scheduler to re-verify stored hashes against DB records to detect "Bit Rot" or unauthorized file changes.
Goal: Provide defensible digital chain of custody for legal/compliance auditability.
4. Policy-Based Scheduler (Health Check)
Feature Name: Fleet Health-Check Policy
Logic: Complete scheduler API for recurring policy jobs.
Workflow: Run endpoint-healthcheck every 6–12 hours across the fleet.
Goal: Shift from reactive-only operations to proactive fleet maintenance.
5. Infrastructure Governance & Resilience
Feature Name: Resource-Constrained Orchestration
Logic: Add CPU/memory reservations and limits for all core services (db, backend, frontend).
Resilience Nuance: Implement a "Circuit Breaker" in the ThreadPoolExecutor. If system memory exceeds 90% of the defined Docker limit, pause new task ingestion to prevent an OOM (Out of Memory) crash.
Goal: Ensure platform stability during high-concurrency (60-worker) execution windows.
6. Playbook Dry-Run Mode
Feature Name: Execution Simulation (Change Management)
Logic: Simulation mode with no endpoint-side effects.
Audit Requirement: Log audit event as playbook_simulated including actor, targets, and resolved plan.
Goal: Give admins a safe pre-flight guardrail before bulk updates.
7. Performance Tuning (Connection Pooling)
Feature Name: Persistent API Session Management
Logic: Refactor WazuhClient and IndexerClient to use requests.Session().
Workflow: Reuse TCP connections (Keep-Alive) to lower per-request latency during bulk runs.
8. Cross-Platform Parity (Linux Support)
Feature Name: Multi-OS Connector Enablement
Logic: Enable code-ready Linux endpoint paths (e.g., firewall-drop, patch-linux).
Goal: Operational cross-platform coverage and stronger platform credibility for the Irish market.
Recommended Delivery Order
Docker resource governance + Circuit Breaker (Stability first).
Session pooling in Wazuh/Indexer clients.
Playbook dry-run + playbook_simulated audit.
Closed-loop remediation verification (with Exponential Back-off).
Scheduler endpoint completion and health-check policy.
Forensic hash/verification chain (with Periodic Integrity Sweeps).
IOC enrichment connector replacement.
Linux connector enablement and validation.

## Next Update Priorities

Before enabling broader vNext feature expansion, the next release focus is:

1. Tighten IOC enrichment quality and confidence handling.
2. Add SOC-grade MITRE ATT&CK mapping depth and coverage.
3. Tighten alert summaries and recommendations to improve accuracy and analyst usefulness.

After these are stabilized, delivery continues with the planned next-version scope in `docs/VNEXT_IMPLEMENTATION_BLUEPRINT.md`.
