from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, text
from starlette.requests import Request


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "v2-agents-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from db import database as db_database  # noqa: E402
from api import approvals as v1_approvals  # noqa: E402
from api.v2 import agents as v2_agents  # noqa: E402
from core.agent_runtime_state import STATE_NETWORK_PATH, clear_agent_runtime_state, get_agent_state  # noqa: E402


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
def _reset_state(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'agents-state.db'}", future=True)
    monkeypatch.setattr(db_database, "engine", engine)
    db_database.metadata.create_all(engine)
    clear_agent_runtime_state()
    monkeypatch.setattr(v2_agents, "log_v2_write_audit", lambda **kwargs: kwargs)


def test_enroll_agent_assigns_groups_and_scope(monkeypatch):
    assigned: list[tuple[str, str]] = []

    def fake_enroll_agent(*, name: str, ip: str, force: int):  # noqa: ARG001
        return {"data": {"affected_items": [{"id": "7", "key": "abc123"}]}}

    def fake_assign_group(agent_id: str, group_id: str):
        assigned.append((agent_id, group_id))
        return {"ok": True}

    monkeypatch.setattr(v2_agents.client, "enroll_agent", fake_enroll_agent)
    monkeypatch.setattr(v2_agents.client, "assign_agent_group", fake_assign_group)

    response = v2_agents.enroll_agent(
        payload=v2_agents.AgentEnrollmentRequest(
            name="win-laptop-01",
            groups=["blue-team"],
        ),
        request=_make_request(method="POST", path="/api/v2/agents/enroll"),
        user={"sub": "alice", "role": "admin", "org_id": 9},
    )

    data = response.get("data", {})
    assert data.get("agent_id") == "007"
    assert data.get("enrollment_key") == "abc123"
    assert data.get("groups_assigned") == ["blue-team"]
    assert response.get("meta", {}).get("tenant_id") == 9
    assert assigned == [("007", "blue-team")]


def test_apply_policy_updates_groups_and_command_policy(monkeypatch):
    removed: list[tuple[str, str]] = []
    assigned: list[tuple[str, str]] = []

    monkeypatch.setattr(v2_agents.client, "remove_agent_group", lambda a, g: removed.append((a, g)) or {"ok": True})
    monkeypatch.setattr(v2_agents.client, "assign_agent_group", lambda a, g: assigned.append((a, g)) or {"ok": True})
    monkeypatch.setattr(
        v2_agents.client,
        "get_agent",
        lambda agent_id: {"data": {"affected_items": [{"id": agent_id, "groups": ["default", "prod"]}]}},
    )

    response = v2_agents.apply_agent_policy(
        agent_id="1",
        request=_make_request(method="PUT", path="/api/v2/agents/1/policy"),
        payload=v2_agents.AgentPolicyApplyRequest(
            assign_groups=["prod"],
            remove_groups=["legacy"],
            command_policy={"enforce_allow_list": True, "allow_list": ["endpoint-healthcheck"]},
            metadata={"bundle": "policy-v1"},
        ),
        user={"sub": "alice", "role": "admin", "org_id": 3},
    )

    data = response.get("data", {})
    assert data.get("agent_id") == "001"
    assert data.get("policy_version") == 1
    assert "group_removed:legacy" in data.get("operations", [])
    assert "group_assigned:prod" in data.get("operations", [])
    assert removed == [("001", "legacy")]
    assert assigned == [("001", "prod")]

    fetched = v2_agents.get_agent_policy(
        agent_id="001",
        include_group_configuration=False,
        tenant_id=None,
        user={"sub": "alice", "role": "analyst", "org_id": 3},
    )
    policy = fetched.get("data", {}).get("command_policy", {})
    assert policy.get("enforce_allow_list") is True
    assert policy.get("allow_list") == ["endpoint-healthcheck"]


def test_dispatch_command_blocked_by_policy_allow_list(monkeypatch):
    v2_agents._state_set(  # noqa: SLF001
        v2_agents._POLICY_STATE,  # noqa: SLF001
        agent_id="001",
        tenant_id=5,
        value={
            "command_policy": {
                "enforce_allow_list": True,
                "allow_list": ["endpoint-healthcheck"],
            }
        },
    )
    monkeypatch.setattr(v2_agents, "get_action", lambda action_id: {"id": action_id, "command": action_id, "inputs": []})
    monkeypatch.setattr(v2_agents, "normalize_args", lambda action, args: [])  # noqa: ARG005
    monkeypatch.setattr(
        v2_agents,
        "resolve_action_dispatch",
        lambda action, args: {"command": action["command"], "arguments": args, "custom": False, "attempts": []},
    )

    with pytest.raises(HTTPException) as exc:
        v2_agents.dispatch_agent_command(
            agent_id="001",
            request=_make_request(method="POST", path="/api/v2/agents/001/commands"),
            payload=v2_agents.AgentCommandDispatchRequest(action_id="restart-wazuh"),
            user={"sub": "alice", "role": "admin", "org_id": 5},
        )

    assert exc.value.status_code == 403
    assert "not allowed by agent policy" in str(exc.value.detail)


def test_dispatch_command_returns_pending_approval_for_high_risk_action(monkeypatch):
    v2_agents._state_set(  # noqa: SLF001
        v2_agents._POLICY_STATE,  # noqa: SLF001
        agent_id="001",
        tenant_id=5,
        value={
            "command_policy": {
                "enforce_allow_list": True,
                "allow_list": ["kill-process"],
            }
        },
    )
    monkeypatch.setattr(v2_agents, "get_action", lambda action_id: {"id": action_id, "command": action_id, "inputs": []})
    monkeypatch.setattr(v2_agents, "normalize_args", lambda action, args: [])  # noqa: ARG005
    monkeypatch.setattr(
        v2_agents,
        "resolve_action_dispatch",
        lambda action, args: {"command": action["command"], "arguments": args, "custom": False, "attempts": []},
    )
    monkeypatch.setattr(
        v1_approvals,
        "create_approval_request_record",
        lambda **kwargs: {"approval_id": 91, "id": 91, "status": "submitted", "requirements": [{"role": "admin", "count": 1}]},  # noqa: ARG005
    )

    response = v2_agents.dispatch_agent_command(
        agent_id="001",
        request=_make_request(method="POST", path="/api/v2/agents/001/commands"),
        payload=v2_agents.AgentCommandDispatchRequest(action_id="kill-process", reason="Contain malware"),
        user={"sub": "alice", "role": "admin", "org_id": 5},
    )

    data = response.get("data", {})
    assert data.get("mode") == "approval_required"
    assert data.get("approval_id") == 91
    assert data.get("result") is None


def test_report_agent_health_persists_network_path_and_agent_state():
    response = v2_agents.report_agent_health(
        agent_id="001",
        request=_make_request(method="POST", path="/api/v2/agents/001/health"),
        payload=v2_agents.AgentHealthReportRequest(
            status="active",
            metrics={
                "network_path": "vpn-gateway-a",
                "network_status": "ok",
                "free_memory_mb": 768,
            },
        ),
        user={"sub": "sensor", "role": "admin", "org_id": 3},
    )

    data = response.get("data", {})
    assert data.get("status") == "active"

    network_state = get_agent_state(state_kind=STATE_NETWORK_PATH, agent_id="001", tenant_id=3)
    assert network_state is not None
    assert network_state.get("path") == "vpn-gateway-a"
    assert network_state.get("network_ok") is True

    with db_database.engine.connect() as conn:
        row = conn.execute(
            text("SELECT online_status, free_memory_mb FROM agent_state WHERE agent_id=:agent_id"),
            {"agent_id": "001"},
        ).fetchone()
    assert row is not None
    assert row[0] == "active"
    assert int(row[1]) == 768


def test_isolation_auto_creates_group_when_missing(monkeypatch):
    calls = {"assign": 0, "created": 0}

    def fake_assign_group(agent_id: str, group_id: str):  # noqa: ARG001
        calls["assign"] += 1
        if calls["assign"] == 1:
            raise HTTPException(status_code=404, detail="Group not found")
        return {"ok": True}

    def fake_create_group(group_id: str):  # noqa: ARG001
        calls["created"] += 1
        return {"ok": True}

    monkeypatch.setattr(v2_agents.client, "assign_agent_group", fake_assign_group)
    monkeypatch.setattr(v2_agents.client, "create_group", fake_create_group)
    monkeypatch.setattr(
        v2_agents.client,
        "get_agent",
        lambda agent_id: {"data": {"affected_items": [{"id": agent_id, "groups": ["isolated"]}]}},
    )

    response = v2_agents.set_agent_isolation(
        agent_id="1",
        request=_make_request(method="POST", path="/api/v2/agents/1/isolation"),
        payload=v2_agents.AgentIsolationRequest(isolate=True, reason="containment"),
        user={"sub": "alice", "role": "admin", "org_id": 2},
    )

    data = response.get("data", {})
    assert data.get("isolated") is True
    assert "group_created:isolated" in data.get("operations", [])
    assert calls["assign"] == 2
    assert calls["created"] == 1


def test_native_enroll_uses_agent_manager(monkeypatch):
    monkeypatch.setattr(
        v2_agents.manager_client,
        "enroll",
        lambda payload: {  # noqa: ARG005
            "tenant_id": 12,
            "agent_id": "agt_1234567890ab",
            "agent_token": "agent-token-123",
            "enrolled_at_utc": "2026-03-03T00:00:00Z",
        },
    )

    response = v2_agents.enroll_agent(
        payload=v2_agents.AgentEnrollmentRequest(
            provider="native",
            name="c2f-win-01",
            os="windows",
            fingerprint="fingerprint-12345678",
            bootstrap_token="bootstrap-token-12345678",
        ),
        request=_make_request(method="POST", path="/api/v2/agents/enroll"),
        user={"sub": "alice", "role": "admin", "org_id": 12},
    )

    data = response.get("data", {})
    assert data.get("provider") == "native"
    assert data.get("agent_id") == "agt_1234567890ab"
    assert data.get("agent_token") == "agent-token-123"
    assert response.get("meta", {}).get("tenant_id") == 12


def test_native_dispatch_supports_unknown_catalog_action(monkeypatch):
    v2_agents._state_set(  # noqa: SLF001
        v2_agents._ENROLLMENT_STATE,  # noqa: SLF001
        agent_id="agt_test0001",
        tenant_id=6,
        value={"provider": "native", "tenant_id": 6},
    )
    monkeypatch.setattr(v2_agents, "get_action", lambda action_id: (_ for _ in ()).throw(HTTPException(status_code=404, detail="not found")))
    monkeypatch.setattr(
        v2_agents.manager_client,
        "get_policy",
        lambda **kwargs: {"data": {"policy": {"command_allow_list": ["endpoint-full-scan"], "command_block_list": []}}},
    )
    monkeypatch.setattr(
        v2_agents.manager_client,
        "dispatch_command",
        lambda **kwargs: {"data": {"command": {"command_id": "cmd_1", "status": "queued"}}},
    )

    response = v2_agents.dispatch_agent_command(
        agent_id="agt_test0001",
        request=_make_request(method="POST", path="/api/v2/agents/agt_test0001/commands"),
        payload=v2_agents.AgentCommandDispatchRequest(
            action_id="endpoint-full-scan",
            args=["--deep"],
            dry_run=False,
        ),
        user={"sub": "alice", "role": "admin", "org_id": 6},
    )

    data = response.get("data", {})
    assert data.get("provider") == "native"
    assert data.get("channel") == "agent-manager-queue"
    assert data.get("result", {}).get("command_id") == "cmd_1"


def test_native_events_endpoint_returns_manager_data(monkeypatch):
    v2_agents._state_set(  # noqa: SLF001
        v2_agents._ENROLLMENT_STATE,  # noqa: SLF001
        agent_id="agt_test0002",
        tenant_id=4,
        value={"provider": "native", "tenant_id": 4},
    )
    monkeypatch.setattr(
        v2_agents.manager_client,
        "get_events",
        lambda **kwargs: {"data": {"items": [{"event_id": "evt-1", "name": "network_snapshot"}], "total": 1}},
    )

    response = v2_agents.get_agent_events(
        agent_id="agt_test0002",
        tenant_id=4,
        limit=100,
        user={"sub": "alice", "role": "analyst", "org_id": 4},
    )

    data = response.get("data", {})
    assert data.get("provider") == "native"
    assert data.get("total") == 1
    assert data.get("items", [{}])[0].get("event_id") == "evt-1"


def test_native_scope_falls_back_to_manager_lookup_when_backend_state_is_empty(monkeypatch):
    monkeypatch.setattr(
        v2_agents.manager_client,
        "get_agent",
        lambda **kwargs: {  # noqa: ARG005
            "data": {
                "agent": {
                    "tenant_id": 8,
                    "agent_id": "agt_fallback0001",
                    "hostname": "edge-node-01",
                }
            }
        },
    )
    monkeypatch.setattr(
        v2_agents.manager_client,
        "get_events",
        lambda **kwargs: {"data": {"items": [{"event_id": "evt-fallback-1"}], "total": 1}},
    )

    response = v2_agents.get_agent_events(
        agent_id="agt_fallback0001",
        tenant_id=8,
        limit=50,
        user={"sub": "alice", "role": "analyst", "org_id": 8},
    )

    data = response.get("data", {})
    assert data.get("provider") == "native"
    assert data.get("items", [{}])[0].get("event_id") == "evt-fallback-1"
