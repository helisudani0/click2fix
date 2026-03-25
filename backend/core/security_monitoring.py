from __future__ import annotations

import json
import threading
from collections import Counter, deque
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from db.database import connect


_LOCK = threading.Lock()
_RECENT_EVENTS: deque[dict[str, Any]] = deque(maxlen=200)
_COUNTS = Counter()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _request_ip(request) -> str | None:
    if request and getattr(request, "headers", None):
        forwarded_for = str(request.headers.get("x-forwarded-for") or "").strip()
        if forwarded_for:
            first = forwarded_for.split(",", 1)[0].strip()
            if first:
                return first
        real_ip = str(request.headers.get("x-real-ip") or "").strip()
        if real_ip:
            return real_ip
    client = getattr(request, "client", None)
    host = getattr(client, "host", None)
    return str(host).strip() or None


def _trim_text(value: Any, *, limit: int = 400) -> str | None:
    if value is None:
        return None
    text_value = str(value).strip()
    if not text_value:
        return None
    return text_value[:limit]


def _serialize_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(metadata, Mapping):
        return {}
    out: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            out[key_text] = value
        else:
            out[key_text] = _trim_text(value, limit=500)
    return out


def record_security_event(
    event_type: str,
    *,
    severity: str = "warning",
    detail: str | None = None,
    request=None,
    user: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    event_name = str(event_type or "").strip().lower() or "security.unknown"
    level = str(severity or "warning").strip().lower() or "warning"
    timestamp = _utc_now()
    event = {
        "event_type": event_name,
        "severity": level,
        "detail": _trim_text(detail, limit=1200),
        "username": _trim_text((user or {}).get("sub") if isinstance(user, Mapping) else None, limit=120),
        "role": _trim_text((user or {}).get("role") if isinstance(user, Mapping) else None, limit=64),
        "org_id": (user or {}).get("org_id") if isinstance(user, Mapping) else None,
        "ip_address": _trim_text(_request_ip(request), limit=128),
        "method": _trim_text(getattr(request, "method", None), limit=16),
        "path": _trim_text(getattr(getattr(request, "url", None), "path", None), limit=256),
        "metadata": _serialize_metadata(metadata),
        "created_at_utc": _utc_iso(timestamp),
    }

    with _LOCK:
        _COUNTS[event_name] += 1
        _COUNTS[f"severity:{level}"] += 1
        _RECENT_EVENTS.appendleft(dict(event))

    if persist:
        try:
            db = connect()
            try:
                db.execute(
                    text(
                        """
                        INSERT INTO security_events
                        (event_type, severity, username, role, org_id, ip_address, method, path, detail, metadata_json, created_at)
                        VALUES
                        (:event_type, :severity, :username, :role, :org_id, :ip_address, :method, :path, :detail, :metadata_json, CURRENT_TIMESTAMP)
                        """
                    ),
                    {
                        "event_type": event["event_type"],
                        "severity": event["severity"],
                        "username": event["username"],
                        "role": event["role"],
                        "org_id": event["org_id"],
                        "ip_address": event["ip_address"],
                        "method": event["method"],
                        "path": event["path"],
                        "detail": event["detail"],
                        "metadata_json": json.dumps(event["metadata"]),
                    },
                )
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

    return event


def runtime_counters() -> dict[str, Any]:
    with _LOCK:
        event_counts = {
            key: value
            for key, value in _COUNTS.items()
            if not str(key).startswith("severity:")
        }
        severity_counts = {
            key.split(":", 1)[1]: value
            for key, value in _COUNTS.items()
            if str(key).startswith("severity:")
        }
        recent = list(_RECENT_EVENTS)
    return {
        "event_counts": dict(sorted(event_counts.items())),
        "severity_counts": dict(sorted(severity_counts.items())),
        "recent_events": recent,
    }


def list_security_events(
    *,
    limit: int = 50,
    offset: int = 0,
    event_type: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 200))
    safe_offset = max(0, int(offset))
    where_parts = ["1=1"]
    params: dict[str, Any] = {
        "limit": safe_limit,
        "offset": safe_offset,
    }
    if event_type:
        params["event_type"] = str(event_type).strip().lower()
        where_parts.append("LOWER(event_type)=:event_type")
    if severity:
        params["severity"] = str(severity).strip().lower()
        where_parts.append("LOWER(severity)=:severity")
    where_sql = " AND ".join(where_parts)

    db = connect()
    try:
        total = int(
            db.execute(
                text(f"SELECT COUNT(*) FROM security_events WHERE {where_sql}"),
                params,
            ).scalar()
            or 0
        )
        rows = db.execute(
            text(
                f"""
                SELECT
                    id,
                    event_type,
                    severity,
                    username,
                    role,
                    org_id,
                    ip_address,
                    method,
                    path,
                    detail,
                    metadata_json,
                    created_at
                FROM security_events
                WHERE {where_sql}
                ORDER BY created_at DESC, id DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        ).fetchall()
    finally:
        db.close()

    items: list[dict[str, Any]] = []
    for row in rows:
        metadata_json = row[10]
        try:
            metadata = json.loads(metadata_json) if metadata_json else {}
        except Exception:
            metadata = {}
        items.append(
            {
                "id": row[0],
                "event_type": row[1],
                "severity": row[2],
                "username": row[3],
                "role": row[4],
                "org_id": row[5],
                "ip_address": row[6],
                "method": row[7],
                "path": row[8],
                "detail": row[9],
                "metadata": metadata,
                "created_at": row[11].isoformat() if hasattr(row[11], "isoformat") else row[11],
            }
        )

    return {"total": total, "items": items}


def security_event_summary(*, recent_limit: int = 20) -> dict[str, Any]:
    safe_limit = max(1, min(int(recent_limit), 100))
    db = connect()
    try:
        severity_rows = db.execute(
            text(
                """
                SELECT LOWER(COALESCE(severity, 'warning')) AS severity, COUNT(*)
                FROM security_events
                GROUP BY LOWER(COALESCE(severity, 'warning'))
                ORDER BY COUNT(*) DESC, severity ASC
                """
            )
        ).fetchall()
        type_rows = db.execute(
            text(
                """
                SELECT LOWER(COALESCE(event_type, 'security.unknown')) AS event_type, COUNT(*)
                FROM security_events
                GROUP BY LOWER(COALESCE(event_type, 'security.unknown'))
                ORDER BY COUNT(*) DESC, event_type ASC
                """
            )
        ).fetchall()
        total = int(db.execute(text("SELECT COUNT(*) FROM security_events")).scalar() or 0)
    finally:
        db.close()

    runtime = runtime_counters()
    recent = list_security_events(limit=safe_limit, offset=0)
    return {
        "runtime": runtime,
        "persisted_total": total,
        "persisted_by_severity": {str(row[0]): int(row[1]) for row in severity_rows},
        "persisted_by_event_type": {str(row[0]): int(row[1]) for row in type_rows},
        "recent_events": recent.get("items", []),
    }


def reset_security_monitor_state() -> None:
    with _LOCK:
        _COUNTS.clear()
        _RECENT_EVENTS.clear()
