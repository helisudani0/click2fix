from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "v2-events-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from api.v2 import events as v2_events  # noqa: E402


def _make_request(*, method: str, path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
        "root_path": "",
    }
    return Request(scope, receive)


@pytest.fixture(autouse=True)
def _stub_audit(monkeypatch):
    monkeypatch.setattr(v2_events, "log_v2_write_audit", lambda **kwargs: kwargs)


def test_search_events_reads_from_indexer(monkeypatch):
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "search_events",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "items": [{"event_id": "evt_1", "stream": "events"}],
                "total": 1,
                "limit": 50,
                "offset": 0,
            }
        },
    )

    response = v2_events.search_events(
        tenant_id=None,
        agent_id="agt_x",
        stream="events",
        category=None,
        severity=None,
        q="ransomware",
        start=None,
        end=None,
        limit=50,
        offset=0,
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert response.get("meta", {}).get("tenant_id") == 7
    assert data.get("total") == 1
    assert data.get("items", [{}])[0].get("event_id") == "evt_1"


def test_search_events_interprets_semantic_query(monkeypatch):
    captured = {}

    def fake_search_events(**kwargs):
        captured.update(kwargs)
        return {"data": {"items": [], "total": 0, "limit": 25, "offset": 0}}

    monkeypatch.setattr(v2_events.event_indexer_client, "search_events", fake_search_events)

    response = v2_events.search_events(
        tenant_id=7,
        agent_id=None,
        stream="events",
        storage_tier=None,
        category=None,
        severity=None,
        q="Show me all agents running unauthorized PowerShell in the last hour",
        start=None,
        end=None,
        limit=25,
        offset=0,
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert "powershell" in str(captured.get("q") or "").lower()
    assert captured.get("start")
    assert data.get("semantic_search", {}).get("enabled") is True


def test_get_raw_event_reads_from_indexer(monkeypatch):
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "get_event",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "event_id": "evt_raw_1",
                "stream": "alerts",
                "event": {"summary": "Critical ransomware precursor"},
            }
        },
    )

    response = v2_events.get_raw_event(
        event_id="evt_raw_1",
        tenant_id=4,
        agent_id=None,
        stream=None,
        user={"sub": "alice", "role": "analyst", "org_id": 4},
    )

    data = response.get("data", {})
    assert response.get("meta", {}).get("tenant_id") == 4
    assert data.get("item", {}).get("event_id") == "evt_raw_1"


def test_time_series_events_reads_from_indexer(monkeypatch):
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "time_series",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "bucket": "1h",
                "group_by": "severity",
                "series": [
                    {"bucket_start": "2026-03-09T09:00:00+00:00", "group": "high", "count": 3},
                    {"bucket_start": "2026-03-09T10:00:00+00:00", "group": "high", "count": 5},
                ],
                "totals": [{"group": "high", "count": 8}],
                "total_points": 2,
                "total_count": 8,
            }
        },
    )

    response = v2_events.time_series_events(
        tenant_id=None,
        agent_id=None,
        stream="events",
        storage_tier=None,
        category=None,
        severity=None,
        start=None,
        end=None,
        bucket="1h",
        group_by="severity",
        limit=500,
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert response.get("meta", {}).get("tenant_id") == 7
    assert data.get("bucket") == "1h"
    assert data.get("total_count") == 8
    assert data.get("series", [{}])[0].get("group") == "high"


def test_correlate_events_reads_from_indexer(monkeypatch):
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "correlate_events",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "window": "15m",
                "total_groups": 1,
                "correlated_events": 4,
                "groups": [
                    {
                        "window_start": "2026-03-09T10:15:00+00:00",
                        "correlation_key": "process|powershell_start|high",
                        "event_count": 4,
                    }
                ],
            }
        },
    )

    response = v2_events.correlate_events(
        tenant_id=7,
        agent_id=None,
        stream="events",
        storage_tier=None,
        category=None,
        severity=None,
        start=None,
        end=None,
        window="15m",
        min_group_size=2,
        max_groups=20,
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert data.get("window") == "15m"
    assert data.get("total_groups") == 1
    assert data.get("groups", [{}])[0].get("event_count") == 4


def test_correlate_events_cross_domain_engine(monkeypatch):
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "search_events",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "total": 4,
                "items": [
                    {
                        "agent_id": "agt_1",
                        "event": {
                            "event_id": "evt_1",
                            "time_utc": "2026-03-09T10:00:00Z",
                            "source_type": "endpoint",
                            "category": "process",
                            "name": "suspicious_powershell_detected",
                            "severity": "high",
                            "summary": "Encoded PowerShell execution",
                            "asset_id": "srv-01",
                            "identity_id": "alice",
                            "trace_id": "trace-123",
                            "mitre_techniques": ["T1059.001"],
                        },
                    },
                    {
                        "agent_id": "agt_1",
                        "event": {
                            "event_id": "evt_2",
                            "time_utc": "2026-03-09T10:03:00Z",
                            "source_type": "network",
                            "category": "network",
                            "name": "c2_traffic",
                            "severity": "high",
                            "summary": "Suspicious outbound C2 traffic",
                            "asset_id": "srv-01",
                            "identity_id": "alice",
                            "trace_id": "trace-123",
                            "mitre_techniques": ["T1071"],
                        },
                    },
                    {
                        "agent_id": "agt_1",
                        "event": {
                            "event_id": "evt_3",
                            "time_utc": "2026-03-09T10:05:00Z",
                            "source_type": "cloud",
                            "category": "cwpp",
                            "name": "role_assumption_anomaly",
                            "severity": "medium",
                            "summary": "Abnormal cloud role assumption",
                            "asset_id": "srv-01",
                            "identity_id": "alice",
                            "trace_id": "trace-123",
                        },
                    },
                    {
                        "agent_id": "agt_1",
                        "event": {
                            "event_id": "evt_4",
                            "time_utc": "2026-03-09T10:06:00Z",
                            "source_type": "identity",
                            "category": "identity",
                            "name": "privilege_escalation_risk_detected",
                            "severity": "high",
                            "summary": "Unexpected admin role assignment",
                            "asset_id": "srv-01",
                            "identity_id": "alice",
                            "trace_id": "trace-123",
                            "mitre_techniques": ["T1078"],
                        },
                    },
                ],
            }
        },
    )

    response = v2_events.correlate_events(
        tenant_id=7,
        agent_id=None,
        stream="events",
        storage_tier=None,
        category=None,
        severity=None,
        start="2026-03-09T09:30:00Z",
        end="2026-03-09T10:30:00Z",
        window="15m",
        min_group_size=2,
        cross_domain=True,
        min_domains=2,
        include_detections=True,
        max_groups=20,
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert data.get("cross_domain") is True
    assert data.get("total_groups", 0) >= 1
    assert len(data.get("groups") or []) >= 1
    assert (data.get("groups") or [{}])[0].get("source_type_count", 0) >= 2
    assert len(data.get("detections") or []) >= 1


def test_lifecycle_summary_reads_active_retention_policy(monkeypatch):
    monkeypatch.setattr(
        v2_events,
        "_get_retention_policy_or_404",
        lambda **kwargs: {  # noqa: ARG005
            "data_class": "events",
            "storage_backend": "event_indexer",
            "stream": "events",
            "warm_after_days": 14,
            "cold_after_days": 60,
            "archive_after_days": 365,
            "delete_after_days": 1095,
            "archive_backend": "object_store",
            "legal_hold": False,
            "status": "active",
        },
    )
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "lifecycle_summary",
        lambda **kwargs: {  # noqa: ARG005
            "data": {"counts": {"hot": 2, "warm": 3, "cold": 4, "archive": 5, "delete_eligible": 1}}
        },
    )

    response = v2_events.get_event_lifecycle_summary(
        tenant_id=None,
        data_class="events",
        user={"sub": "alice", "role": "analyst", "org_id": 7},
    )

    data = response.get("data", {})
    assert data.get("policy", {}).get("warm_after_days") == 14
    assert data.get("summary", {}).get("counts", {}).get("archive") == 5


def test_lifecycle_apply_uses_active_policy(monkeypatch):
    monkeypatch.setattr(
        v2_events,
        "_get_retention_policy_or_404",
        lambda **kwargs: {  # noqa: ARG005
            "data_class": "events",
            "storage_backend": "event_indexer",
            "stream": "events",
            "warm_after_days": 14,
            "cold_after_days": 60,
            "archive_after_days": 365,
            "delete_after_days": 1095,
            "archive_backend": "object_store",
            "legal_hold": False,
            "status": "active",
        },
    )
    monkeypatch.setattr(v2_events, "_mark_retention_policy_applied", lambda **kwargs: None)
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "apply_lifecycle",
        lambda **kwargs: {  # noqa: ARG005
            "data": {"changed": {"warm": 3}, "deleted": 1, "counts": {"total": 9}}
        },
    )

    response = v2_events.apply_event_lifecycle(
        payload=v2_events.EventLifecycleRunRequest(tenant_id=7, data_class="events", dry_run=False),
        request=_make_request(method="POST", path="/api/v2/events/lifecycle/apply"),
        user={"sub": "admin", "role": "admin", "org_id": 7},
    )

    data = response.get("data", {})
    assert data.get("policy", {}).get("archive_after_days") == 365
    assert data.get("result", {}).get("deleted") == 1


def test_lifecycle_apply_all_executes_active_policies(monkeypatch):
    monkeypatch.setattr(
        v2_events,
        "_list_event_indexer_retention_policies",
        lambda **kwargs: [  # noqa: ARG005
            {
                "data_class": "events",
                "storage_backend": "event_indexer",
                "stream": "events",
                "warm_after_days": 14,
                "cold_after_days": 60,
                "archive_after_days": 365,
                "delete_after_days": 1095,
                "archive_backend": "object_store",
                "legal_hold": False,
                "status": "active",
            },
            {
                "data_class": "alerts",
                "storage_backend": "event_indexer",
                "stream": "alerts",
                "warm_after_days": 7,
                "cold_after_days": 30,
                "archive_after_days": 180,
                "delete_after_days": 365,
                "archive_backend": "object_store",
                "legal_hold": False,
                "status": "active",
            },
        ],
    )
    monkeypatch.setattr(
        v2_events.event_indexer_client,
        "apply_lifecycle",
        lambda **kwargs: {  # noqa: ARG005
            "data": {"changed": {"warm": 2, "cold": 1}, "deleted": 0}
        },
    )
    monkeypatch.setattr(v2_events, "_mark_retention_policy_applied", lambda **kwargs: None)

    response = v2_events.apply_all_event_lifecycle(
        payload=v2_events.EventLifecycleBatchRunRequest(tenant_id=7, data_classes=["events", "alerts"], dry_run=False),
        request=_make_request(method="POST", path="/api/v2/events/lifecycle/apply-all"),
        user={"sub": "admin", "role": "admin", "org_id": 7},
    )

    data = response.get("data", {})
    assert data.get("requested") == 2
    assert data.get("applied") == 2
    assert data.get("failed") == 0
    assert len(data.get("results", [])) == 2


def test_search_events_requires_tenant_scope():
    with pytest.raises(HTTPException) as exc:
        v2_events.search_events(
            tenant_id=None,
            agent_id=None,
            stream=None,
            category=None,
            severity=None,
            q=None,
            start=None,
            end=None,
            limit=20,
            offset=0,
            user={"sub": "root", "role": "superadmin", "org_id": None},
        )
    assert exc.value.status_code == 400
    assert "tenant_id is required" in str(exc.value.detail)


def test_ingest_event_enqueues_for_async_processing(monkeypatch):
    monkeypatch.setattr(
        v2_events.ingest_gateway_client,
        "ingest_event",
        lambda payload: {  # noqa: ARG005
            "data": {
                "accepted": True,
                "deduplicated": False,
                "queue_event_id": "q_evt_1",
                "status": "PENDING",
                "trace_id": "trace-1",
                "attempt_count": 0,
                "max_attempts": 6,
                "tenant_id": 2,
                "stream": "events",
                "event_kind": "canonical_event",
                "event_id": "evt_ingest_1",
                "worker": {"enabled": True, "running": True, "batch_size": 25},
            }
        },
    )

    response = v2_events.ingest_event(
        payload=v2_events.EventIngestRequest(
            source_type="endpoint",
            raw_event={"event_name": "process_snapshot", "event_id": "evt_ingest_1"},
            publish=False,
        ),
        request=_make_request(method="POST", path="/api/v2/events/ingest"),
        user={"sub": "alice", "role": "analyst", "org_id": 2},
    )

    data = response.get("data", {})
    assert data.get("accepted") is True
    assert data.get("queue_event_id") == "q_evt_1"
    assert data.get("status") == "PENDING"
    assert data.get("worker", {}).get("running") is True


def test_replay_endpoint_queues_replay(monkeypatch):
    monkeypatch.setattr(
        v2_events.ingest_gateway_client,
        "replay_ingestion_events",
        lambda payload: {  # noqa: ARG005
            "data": {
                "requested": len(payload.get("queue_event_ids") or []),
                "accepted": len(payload.get("queue_event_ids") or []),
                "missing": [],
                "items": [{"queue_event_id": "replayed_1", "accepted": True}],
                "worker": {"enabled": True, "running": True},
            }
        },
    )

    response = v2_events.replay_queue_events(
        payload=v2_events.EventReplayRequest(queue_event_ids=["q_evt_1"]),
        request=_make_request(method="POST", path="/api/v2/events/ingestion/replay"),
        user={"sub": "admin", "role": "admin", "org_id": 2},
    )

    data = response.get("data", {})
    assert data.get("requested") == 1
    assert data.get("accepted") == 1
    assert data.get("worker", {}).get("running") is True
