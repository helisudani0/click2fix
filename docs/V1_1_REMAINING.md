# Click2Fix v1.1 Remaining Work

This is the single active backlog document for unfinished v1.1 scope.
Completed items were intentionally removed from active planning docs.

## Remaining Scope

### 1) Wazuh/Indexer retry + latency telemetry

- Keep retries strictly failure-class aware:
  - retry: timeout, connection reset, HTTP 429, HTTP 5xx
  - do not retry: HTTP 401/403/404 and validation failures
- Persist per-call latency + retry counters into execution metadata.
- Surface retry/latency telemetry in execution APIs/UI for ops troubleshooting.

### 2) Linux connector parity hardening

- Align Linux action result semantics with Windows contract:
  - `success`, `partial`, `failed`
  - deterministic evidence shape
- Return explicit Linux failure classes:
  - network/connectivity failure
  - auth failure
  - sudo/privilege failure
  - command-not-found/unsupported action
- Close parity gaps for baseline response actions where Linux capability exists.

### 3) SCA policy workflow API block

- Implement missing API set:
  - `GET /sca/policies`
  - `POST /sca/policies/{policy_id}/plan`
  - `POST /sca/policies/{policy_id}/dry-run`
  - `POST /sca/policies/{policy_id}/execute`
  - `GET /sca/policies/{policy_id}/runs/{run_id}`
- Persist run lifecycle and evidence for SCA policy workflows.

### 4) Detection tuning loop activation

- Move `detection_tuning_suggestions` from schema-only to active workflow.
- Generate actionable suggestions from incident/governance/IOC/MITRE evidence.
- Add APIs/UI to list, approve, reject, and close suggestions.

### 5) Release gate verification

- Run and capture final v1.1 evidence for:
  - safety gate (dry-run + verification correctness)
  - governance gate (audit trace completeness)
  - scale gate (no recurring queue stall/OOM under baseline stress)

## Exit Criteria for v1.1 Complete

- Remaining scope items above are implemented and validated.
- README + release notes reflect final v1.1 shipped state.
- Tag and publish release as `v1.1.0`.
