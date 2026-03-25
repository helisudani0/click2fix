from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import text

from core.time_utils import utc_now_naive
from db.database import connect


def _json_dumps(value: Any) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def acquire_or_renew_lease(
    *,
    lease_name: str,
    owner_id: str,
    ttl_seconds: int,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = utc_now_naive()
    expires_at = now + timedelta(seconds=max(5, int(ttl_seconds)))
    lease_token = str(uuid.uuid4())

    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO service_runtime_leases
                (lease_name, owner_id, lease_token, lease_expires_at, metadata_json, created_at, updated_at)
                VALUES
                (:lease_name, :owner_id, :lease_token, :lease_expires_at, :metadata_json, :created_at, :updated_at)
                ON CONFLICT (lease_name)
                DO UPDATE SET
                    owner_id=excluded.owner_id,
                    lease_token=excluded.lease_token,
                    lease_expires_at=excluded.lease_expires_at,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                WHERE service_runtime_leases.owner_id=:owner_id
                   OR service_runtime_leases.lease_expires_at < :now
                """
            ),
            {
                "lease_name": str(lease_name or "").strip(),
                "owner_id": str(owner_id or "").strip(),
                "lease_token": lease_token,
                "lease_expires_at": expires_at,
                "metadata_json": _json_dumps(metadata),
                "created_at": now,
                "updated_at": now,
                "now": now,
            },
        )
        db.commit()
        current = db.execute(
            text(
                """
                SELECT owner_id, lease_token, lease_expires_at
                FROM service_runtime_leases
                WHERE lease_name=:lease_name
                LIMIT 1
                """
            ),
            {"lease_name": str(lease_name or "").strip()},
        ).fetchone()
        return {
            "acquired": bool(current and current[0] == str(owner_id or "").strip()),
            "owner_id": current[0] if current else None,
            "lease_token": current[1] if current else None,
            "lease_expires_at": current[2] if current else None,
        }
    finally:
        db.close()


def release_lease(*, lease_name: str, owner_id: str) -> None:
    db = connect()
    try:
        db.execute(
            text(
                """
                DELETE FROM service_runtime_leases
                WHERE lease_name=:lease_name
                  AND owner_id=:owner_id
                """
            ),
            {
                "lease_name": str(lease_name or "").strip(),
                "owner_id": str(owner_id or "").strip(),
            },
        )
        db.commit()
    finally:
        db.close()
