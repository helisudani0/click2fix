from __future__ import annotations

import json
from typing import Any

from sqlalchemy import text

from db.database import connect


STATE_ENROLLMENT = "enrollment"
STATE_POLICY = "policy"
STATE_HEALTH = "health"
STATE_ISOLATION = "isolation"
STATE_NETWORK_PATH = "network_path"
STATE_SCA_BASELINE = "sca_baseline"


def _tenant_scope(tenant_id: int | None) -> int:
    try:
        parsed = int(tenant_id or 0)
    except Exception:
        return 0
    return parsed if parsed > 0 else 0


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _json_loads(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def get_agent_state(*, state_kind: str, agent_id: str, tenant_id: int | None) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT payload_json
                FROM agent_runtime_state
                WHERE tenant_scope=:tenant_scope
                  AND agent_id=:agent_id
                  AND state_kind=:state_kind
                LIMIT 1
                """
            ),
            {
                "tenant_scope": _tenant_scope(tenant_id),
                "agent_id": str(agent_id or "").strip(),
                "state_kind": str(state_kind or "").strip(),
            },
        ).fetchone()
        return _json_loads(row[0] if row else None)
    finally:
        db.close()


def find_any_agent_state(*, state_kind: str, agent_id: str) -> dict[str, Any] | None:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT payload_json
                FROM agent_runtime_state
                WHERE agent_id=:agent_id
                  AND state_kind=:state_kind
                ORDER BY updated_at DESC, id DESC
                LIMIT 1
                """
            ),
            {
                "agent_id": str(agent_id or "").strip(),
                "state_kind": str(state_kind or "").strip(),
            },
        ).fetchone()
        return _json_loads(row[0] if row else None)
    finally:
        db.close()


def upsert_agent_state(
    *,
    state_kind: str,
    agent_id: str,
    tenant_id: int | None,
    value: dict[str, Any],
    updated_by: str | None = None,
) -> dict[str, Any]:
    payload = dict(value or {})
    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO agent_runtime_state
                (tenant_scope, agent_id, state_kind, payload_json, updated_by)
                VALUES
                (:tenant_scope, :agent_id, :state_kind, :payload_json, :updated_by)
                ON CONFLICT (tenant_scope, agent_id, state_kind)
                DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_by=excluded.updated_by,
                    updated_at=CURRENT_TIMESTAMP
                """
            ),
            {
                "tenant_scope": _tenant_scope(tenant_id),
                "agent_id": str(agent_id or "").strip(),
                "state_kind": str(state_kind or "").strip(),
                "payload_json": _json_dumps(payload),
                "updated_by": str(updated_by or "").strip() or None,
            },
        )
        db.commit()
        return payload
    finally:
        db.close()


def clear_agent_runtime_state(
    *,
    state_kind: str | None = None,
    agent_id: str | None = None,
    tenant_id: int | None = None,
) -> None:
    where: list[str] = []
    params: dict[str, Any] = {}
    if state_kind:
        where.append("state_kind=:state_kind")
        params["state_kind"] = str(state_kind).strip()
    if agent_id:
        where.append("agent_id=:agent_id")
        params["agent_id"] = str(agent_id).strip()
    if tenant_id is not None:
        where.append("tenant_scope=:tenant_scope")
        params["tenant_scope"] = _tenant_scope(tenant_id)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""

    db = connect()
    try:
        db.execute(text(f"DELETE FROM agent_runtime_state {where_sql}"), params)
        db.commit()
    finally:
        db.close()
