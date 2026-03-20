from __future__ import annotations

import copy
import csv
import hashlib
import hmac
import io
import json
import threading
import uuid
from collections import defaultdict
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import text

from core.audit import log_audit
from core.secrets import resolve_secret_env
from core.security import require_role
from core.time_utils import parse_utc_datetime, utc_iso, utc_iso_now
from db.database import connect
from ._scoping import scoped_where_clause
from .common import API_VERSION, ok, pagination_meta
from .tenant_contract import org_id_to_tenant_id, resolve_tenant_scope, tenant_id_to_org_id


router = APIRouter(prefix="/audit")

IMMUTABLE_AUDIT_SCHEMA_VERSION = "2026-03-03.v2"
_LEGACY_IMMUTABLE_AUDIT_SCHEMA_VERSIONS = {"2026-03-02.v1"}
_MAX_PAGE_SIZE = 500
_MAX_EXPORT_LIMIT = 10000
_MAX_VERIFY_LIMIT = 20000
_CHAIN_LOOKBACK_LIMIT = 200
_CHAIN_WRITE_LOCK = threading.Lock()
_AUDIT_SIGNATURE_SECRET = (
    resolve_secret_env("C2F_AUDIT_HMAC_SECRET")
    or resolve_secret_env("JWT_SECRET")
    or "c2f-audit-dev-secret"
)


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _normalized_limit(value: int, *, default: int, max_value: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(1, min(parsed, max_value))


def _chain_scope(tenant_id: int | None) -> str:
    return f"tenant:{tenant_id or 0}"


def _event_without_hash(event: Mapping[str, Any]) -> dict[str, Any]:
    clone = copy.deepcopy(dict(event))
    immutability = clone.get("immutability")
    if isinstance(immutability, dict):
        out = dict(immutability)
        out.pop("event_hash", None)
        out.pop("signature", None)
        out.pop("signature_algorithm", None)
        out.pop("signature_key_id", None)
        clone["immutability"] = out
    return clone


def _event_hash(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_event_without_hash(event)).encode("utf-8")).hexdigest()


def _event_signature(event: Mapping[str, Any]) -> str:
    digest = _event_hash(event)
    return hmac.new(
        _AUDIT_SIGNATURE_SECRET.encode("utf-8"),
        digest.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _parse_immutable_detail(detail: Any) -> tuple[dict[str, Any] | None, str | None]:
    raw = str(detail or "").strip()
    if not raw:
        return None, "empty_detail"
    try:
        payload = json.loads(raw)
    except Exception:
        return None, "detail_not_json"
    if not isinstance(payload, dict):
        return None, "detail_not_object"
    immutability = payload.get("immutability")
    if not isinstance(immutability, dict):
        return None, "missing_immutability"
    return payload, None


def _event_chain_scope(event: Mapping[str, Any], fallback_tenant_id: int | None) -> str:
    immutability = event.get("immutability")
    if isinstance(immutability, dict):
        chain_scope = str(immutability.get("chain_scope") or "").strip()
        if chain_scope:
            return chain_scope
    target = event.get("target")
    if isinstance(target, dict):
        target_tenant = org_id_to_tenant_id(target.get("tenant_id"))
        if target_tenant is not None:
            return _chain_scope(target_tenant)
    actor = event.get("actor")
    if isinstance(actor, dict):
        actor_tenant = org_id_to_tenant_id(actor.get("tenant_id"))
        if actor_tenant is not None:
            return _chain_scope(actor_tenant)
    return _chain_scope(fallback_tenant_id)


def _latest_chain_head(conn, *, tenant_id: int | None, chain_scope: str) -> tuple[str | None, int | None]:
    org_id = tenant_id_to_org_id(tenant_id)
    if org_id is None:
        rows = conn.execute(
            text(
                """
                SELECT id, detail
                FROM audit_logs
                WHERE org_id IS NULL
                  AND detail LIKE :immutable_marker
                ORDER BY id DESC
                LIMIT :limit
                """
            ),
            {"immutable_marker": '%"immutability"%', "limit": _CHAIN_LOOKBACK_LIMIT},
        ).fetchall()
    else:
        rows = conn.execute(
            text(
                """
                SELECT id, detail
                FROM audit_logs
                WHERE org_id=:org_id
                  AND detail LIKE :immutable_marker
                ORDER BY id DESC
                LIMIT :limit
                """
            ),
            {"org_id": org_id, "immutable_marker": '%"immutability"%', "limit": _CHAIN_LOOKBACK_LIMIT},
        ).fetchall()

    for row in rows:
        event, _ = _parse_immutable_detail(row[1])
        if not isinstance(event, dict):
            continue
        if _event_chain_scope(event, tenant_id) != chain_scope:
            continue
        immutability = event.get("immutability")
        if not isinstance(immutability, dict):
            continue
        previous_hash = str(immutability.get("event_hash") or "").strip()
        if previous_hash:
            return previous_hash, int(row[0])
    return None, None


def build_v2_audit_event(
    *,
    action: str,
    entity_type: str,
    entity_id: Any = None,
    user: Mapping[str, Any] | None = None,
    request: Request | None = None,
    tenant_id: Any = None,
    changes: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    prev_event_hash: str | None = None,
    prev_event_id: int | None = None,
    chain_scope: str | None = None,
) -> dict[str, Any]:
    resolved_tenant_id = org_id_to_tenant_id(
        tenant_id if tenant_id is not None else ((user or {}).get("org_id") if isinstance(user, Mapping) else None)
    )
    effective_chain_scope = str(chain_scope or _chain_scope(resolved_tenant_id)).strip() or _chain_scope(resolved_tenant_id)
    base_event = {
        "schema_version": IMMUTABLE_AUDIT_SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "event_time_utc": utc_iso_now(),
        "api_version": API_VERSION,
        "immutability": {
            "append_only": True,
            "hash_algorithm": "sha256",
            "chain_scope": effective_chain_scope,
            "prev_event_hash": str(prev_event_hash or "").strip() or None,
            "prev_event_id": int(prev_event_id) if prev_event_id else None,
            "signature_algorithm": "hmac-sha256",
            "signature_key_id": "local-default",
        },
        "action": action,
        "actor": {
            "username": (user or {}).get("sub") if isinstance(user, Mapping) else None,
            "role": (user or {}).get("role") if isinstance(user, Mapping) else None,
            "tenant_id": resolved_tenant_id,
        },
        "request": {
            "method": request.method if request else None,
            "path": request.url.path if request else None,
            "client_ip": request.client.host if (request and request.client) else None,
            "user_agent": request.headers.get("user-agent") if request else None,
        },
        "target": {
            "entity_type": entity_type,
            "entity_id": str(entity_id) if entity_id is not None else None,
            "tenant_id": resolved_tenant_id,
        },
        "changes": dict(changes or {}),
        "metadata": dict(metadata or {}),
    }
    base_event["immutability"]["event_hash"] = _event_hash(base_event)
    base_event["immutability"]["signature"] = _event_signature(base_event)
    return base_event


def log_v2_write_audit(
    *,
    action: str,
    entity_type: str,
    entity_id: Any = None,
    user: Mapping[str, Any] | None = None,
    request: Request | None = None,
    tenant_id: Any = None,
    changes: Mapping[str, Any] | None = None,
    metadata: Mapping[str, Any] | None = None,
    conn=None,
) -> dict[str, Any]:
    resolved_tenant_id = org_id_to_tenant_id(
        tenant_id if tenant_id is not None else ((user or {}).get("org_id") if isinstance(user, Mapping) else None)
    )
    chain_scope = _chain_scope(resolved_tenant_id)

    owns_conn = conn is None
    db = conn or connect()
    try:
        with _CHAIN_WRITE_LOCK:
            prev_event_hash, prev_event_id = _latest_chain_head(
                db,
                tenant_id=resolved_tenant_id,
                chain_scope=chain_scope,
            )
            event = build_v2_audit_event(
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                user=user,
                request=request,
                tenant_id=resolved_tenant_id,
                changes=changes,
                metadata=metadata,
                prev_event_hash=prev_event_hash,
                prev_event_id=prev_event_id,
                chain_scope=chain_scope,
            )
            log_audit(
                action=action,
                actor=event["actor"]["username"],
                entity_type=entity_type,
                entity_id=event["target"]["entity_id"],
                detail=_canonical_json(event),
                org_id=tenant_id_to_org_id(event["target"]["tenant_id"]),
                ip_address=event["request"]["client_ip"],
                conn=db,
            )
        if owns_conn:
            db.commit()
        return event
    except Exception:
        if owns_conn:
            try:
                db.rollback()
            except Exception:
                pass
        raise
    finally:
        if owns_conn:
            db.close()


def _build_audit_where(
    *,
    user: Mapping[str, Any] | None,
    tenant_id: int | None,
    actor: str | None,
    action: str | None,
    entity_type: str | None,
    entity_id: str | None,
    start: str | None,
    end: str | None,
    immutable_only: bool,
) -> tuple[str, dict[str, Any], int | None]:
    scope_clause, scope_params, scoped_tenant = scoped_where_clause(
        alias="a",
        user=user,
        tenant_id=tenant_id,
    )
    where_parts = [scope_clause]
    params: dict[str, Any] = dict(scope_params)

    if actor:
        where_parts.append("a.actor=:actor")
        params["actor"] = str(actor).strip()
    if action:
        where_parts.append("a.action=:action")
        params["action"] = str(action).strip()
    if entity_type:
        where_parts.append("a.entity_type=:entity_type")
        params["entity_type"] = str(entity_type).strip()
    if entity_id:
        where_parts.append("a.entity_id=:entity_id")
        params["entity_id"] = str(entity_id).strip()

    start_dt = parse_utc_datetime(start) if start else None
    if start and start_dt is None:
        raise HTTPException(status_code=400, detail="Invalid start timestamp")
    end_dt = parse_utc_datetime(end) if end else None
    if end and end_dt is None:
        raise HTTPException(status_code=400, detail="Invalid end timestamp")
    if start_dt and end_dt and end_dt < start_dt:
        raise HTTPException(status_code=400, detail="end must be >= start")
    if start_dt:
        where_parts.append("a.created_at >= :start")
        params["start"] = start_dt.replace(tzinfo=None)
    if end_dt:
        where_parts.append("a.created_at <= :end")
        params["end"] = end_dt.replace(tzinfo=None)
    if immutable_only:
        where_parts.append("a.detail LIKE :immutable_marker")
        params["immutable_marker"] = '%"immutability"%'

    return " AND ".join(where_parts), params, scoped_tenant


def _load_audit_rows(
    *,
    where_sql: str,
    params: Mapping[str, Any],
    limit: int,
    offset: int,
) -> tuple[int, list[dict[str, Any]]]:
    db = connect()
    try:
        total = (
            db.execute(
                text(f"SELECT COUNT(*) FROM audit_logs a WHERE {where_sql}"),
                dict(params),
            ).scalar()
            or 0
        )
        rows = db.execute(
            text(
                f"""
                SELECT
                    a.id,
                    a.actor,
                    a.action,
                    a.entity_type,
                    a.entity_id,
                    a.detail,
                    a.org_id,
                    a.ip_address,
                    a.created_at
                FROM audit_logs a
                WHERE {where_sql}
                ORDER BY a.created_at DESC, a.id DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**dict(params), "limit": limit, "offset": offset},
        ).fetchall()
    finally:
        db.close()

    out: list[dict[str, Any]] = []
    for row in rows:
        mapping = row._mapping
        out.append(
            {
                "id": int(mapping.get("id") or 0),
                "actor": mapping.get("actor"),
                "action": mapping.get("action"),
                "entity_type": mapping.get("entity_type"),
                "entity_id": mapping.get("entity_id"),
                "detail": mapping.get("detail"),
                "org_id": mapping.get("org_id"),
                "tenant_id": org_id_to_tenant_id(mapping.get("org_id")),
                "ip_address": mapping.get("ip_address"),
                "created_at_utc": utc_iso(mapping.get("created_at")),
            }
        )
    return int(total), out


def _normalize_audit_entries(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        event, parse_error = _parse_immutable_detail(row.get("detail"))
        immutability = event.get("immutability") if isinstance(event, dict) else {}
        if not isinstance(immutability, dict):
            immutability = {}
        chain_scope = (
            _event_chain_scope(event, row.get("tenant_id"))
            if isinstance(event, dict)
            else _chain_scope(row.get("tenant_id"))
        )
        out.append(
            {
                **row,
                "immutable": isinstance(event, dict),
                "parse_error": parse_error,
                "event": event if isinstance(event, dict) else None,
                "schema_version": (event or {}).get("schema_version") if isinstance(event, dict) else None,
                "event_id": (event or {}).get("event_id") if isinstance(event, dict) else None,
                "event_time_utc": (event or {}).get("event_time_utc") if isinstance(event, dict) else None,
                "chain_scope": chain_scope,
                "event_hash": str(immutability.get("event_hash") or "").strip() or None,
                "prev_event_hash": str(immutability.get("prev_event_hash") or "").strip() or None,
                "prev_event_id": immutability.get("prev_event_id"),
                "signature": str(immutability.get("signature") or "").strip() or None,
            }
        )
    return out


def _validate_immutable_chain(entries: list[dict[str, Any]]) -> dict[str, Any]:
    anomalies: list[dict[str, Any]] = []
    row_results: list[dict[str, Any]] = []
    by_scope: dict[str, list[dict[str, Any]]] = defaultdict(list)

    immutable_entries = [entry for entry in entries if bool(entry.get("immutable")) and isinstance(entry.get("event"), dict)]
    for entry in immutable_entries:
        by_scope[str(entry.get("chain_scope") or _chain_scope(entry.get("tenant_id")))].append(entry)

    hash_mismatches = 0
    continuity_breaks = 0
    scopes_with_issues: set[str] = set()

    for scope_entries in by_scope.values():
        scope_entries.sort(key=lambda item: int(item.get("id") or 0))
        for index, entry in enumerate(scope_entries):
            row_id = int(entry.get("id") or 0)
            event = entry.get("event") or {}
            immutability = event.get("immutability") if isinstance(event, dict) else {}
            if not isinstance(immutability, dict):
                immutability = {}
            stored_hash = str(immutability.get("event_hash") or "").strip()
            computed_hash = _event_hash(event) if isinstance(event, dict) else ""
            stored_signature = str(immutability.get("signature") or "").strip()
            computed_signature = _event_signature(event) if isinstance(event, dict) else ""
            expected_prev_hash = None
            prev_hash = str(immutability.get("prev_event_hash") or "").strip() or None
            issues: list[str] = []

            if not stored_hash:
                issues.append("missing_event_hash")
                anomalies.append(
                    {
                        "row_id": row_id,
                        "scope": entry.get("chain_scope"),
                        "type": "missing_event_hash",
                        "message": "Immutable audit event is missing immutability.event_hash",
                    }
                )
            elif stored_hash != computed_hash:
                hash_mismatches += 1
                scopes_with_issues.add(str(entry.get("chain_scope")))
                issues.append("hash_mismatch")
                anomalies.append(
                    {
                        "row_id": row_id,
                        "scope": entry.get("chain_scope"),
                        "type": "hash_mismatch",
                        "expected": computed_hash,
                        "actual": stored_hash,
                        "message": "Immutable event hash does not match canonical payload hash",
                    }
                )

            if not stored_signature:
                issues.append("missing_signature")
                anomalies.append(
                    {
                        "row_id": row_id,
                        "scope": entry.get("chain_scope"),
                        "type": "missing_signature",
                        "message": "Immutable audit event is missing immutability.signature",
                    }
                )
            elif stored_signature != computed_signature:
                hash_mismatches += 1
                scopes_with_issues.add(str(entry.get("chain_scope")))
                issues.append("signature_mismatch")
                anomalies.append(
                    {
                        "row_id": row_id,
                        "scope": entry.get("chain_scope"),
                        "type": "signature_mismatch",
                        "expected": computed_signature,
                        "actual": stored_signature,
                        "message": "Immutable event signature does not match expected HMAC signature",
                    }
                )

            if index > 0:
                previous = scope_entries[index - 1]
                expected_prev_hash = previous.get("event_hash")
                if not expected_prev_hash and isinstance(previous.get("event"), dict):
                    expected_prev_hash = _event_hash(previous["event"])
                expected_prev_hash = str(expected_prev_hash or "").strip() or None
                if expected_prev_hash and prev_hash != expected_prev_hash:
                    continuity_breaks += 1
                    scopes_with_issues.add(str(entry.get("chain_scope")))
                    issues.append("continuity_break")
                    anomalies.append(
                        {
                            "row_id": row_id,
                            "scope": entry.get("chain_scope"),
                            "type": "continuity_break",
                            "expected": expected_prev_hash,
                            "actual": prev_hash,
                            "message": "prev_event_hash does not link to the previous immutable event",
                        }
                    )

            status = "tampered" if issues else "ok"
            row_results.append(
                {
                    "row_id": row_id,
                    "scope": entry.get("chain_scope"),
                    "status": status,
                    "issues": issues,
                    "event_hash": stored_hash or None,
                    "computed_hash": computed_hash or None,
                    "signature": stored_signature or None,
                    "computed_signature": computed_signature or None,
                    "prev_event_hash": prev_hash,
                    "expected_prev_event_hash": expected_prev_hash,
                }
            )

    return {
        "verified_at_utc": utc_iso_now(),
        "summary": {
            "total_rows": len(entries),
            "immutable_rows": len(immutable_entries),
            "scopes_checked": len(by_scope),
            "hash_mismatches": hash_mismatches,
            "continuity_breaks": continuity_breaks,
            "anomaly_count": len(anomalies),
            "tampered": bool(anomalies),
        },
        "scope_status": [
            {
                "scope": scope,
                "events": len(scope_entries),
                "status": "tampered" if scope in scopes_with_issues else "ok",
            }
            for scope, scope_entries in sorted(by_scope.items(), key=lambda item: item[0])
        ],
        "rows": row_results,
        "anomalies": anomalies,
    }


def _supported_schema_version(value: Any) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False
    return candidate == IMMUTABLE_AUDIT_SCHEMA_VERSION or candidate in _LEGACY_IMMUTABLE_AUDIT_SCHEMA_VERSIONS


@router.get("/query")
def query_audit_events(
    actor: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=_MAX_PAGE_SIZE),
    tenant_id: int | None = Query(default=None, ge=1),
    immutable_only: bool = True,
    verify_chain: bool = False,
    user=Depends(require_role("admin")),
):
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    where_sql, params, _ = _build_audit_where(
        user=user,
        tenant_id=scoped_tenant,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        start=start,
        end=end,
        immutable_only=immutable_only,
    )
    safe_size = _normalized_limit(page_size, default=100, max_value=_MAX_PAGE_SIZE)
    offset = (int(page) - 1) * safe_size
    total, rows = _load_audit_rows(
        where_sql=where_sql,
        params=params,
        limit=safe_size,
        offset=offset,
    )
    entries = _normalize_audit_entries(rows)
    if immutable_only:
        entries = [
            entry
            for entry in entries
            if entry.get("immutable") and _supported_schema_version(entry.get("schema_version"))
        ]

    payload: dict[str, Any] = {
        "items": entries,
        "pagination": pagination_meta(page=page, page_size=safe_size, total=total),
    }
    if verify_chain:
        payload["verification"] = _validate_immutable_chain(entries)
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/verify")
def verify_audit_chain(
    actor: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = Query(default=5000, ge=1, le=_MAX_VERIFY_LIMIT),
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(require_role("admin")),
):
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    where_sql, params, _ = _build_audit_where(
        user=user,
        tenant_id=scoped_tenant,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        start=start,
        end=end,
        immutable_only=True,
    )
    safe_limit = _normalized_limit(limit, default=5000, max_value=_MAX_VERIFY_LIMIT)
    _, rows = _load_audit_rows(
        where_sql=where_sql,
        params=params,
        limit=safe_limit,
        offset=0,
    )
    entries = [
        entry
        for entry in _normalize_audit_entries(rows)
        if entry.get("immutable") and _supported_schema_version(entry.get("schema_version"))
    ]
    report = _validate_immutable_chain(entries)
    return ok(
        {
            "verification": report,
            "events_checked": len(entries),
            "limit_applied": safe_limit,
        },
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.get("/export")
def export_audit_events(
    format: str = Query(default="json"),
    actor: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = Query(default=1000, ge=1, le=_MAX_EXPORT_LIMIT),
    tenant_id: int | None = Query(default=None, ge=1),
    verify_chain: bool = True,
    user=Depends(require_role("admin")),
):
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    where_sql, params, _ = _build_audit_where(
        user=user,
        tenant_id=scoped_tenant,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        start=start,
        end=end,
        immutable_only=True,
    )
    safe_limit = _normalized_limit(limit, default=1000, max_value=_MAX_EXPORT_LIMIT)
    _, rows = _load_audit_rows(
        where_sql=where_sql,
        params=params,
        limit=safe_limit,
        offset=0,
    )
    entries = [
        entry
        for entry in _normalize_audit_entries(rows)
        if entry.get("immutable") and _supported_schema_version(entry.get("schema_version"))
    ]
    verification = _validate_immutable_chain(entries) if verify_chain else None

    normalized_format = str(format or "json").strip().lower()
    if normalized_format not in {"json", "csv"}:
        raise HTTPException(status_code=400, detail="format must be one of: json, csv")

    if normalized_format == "csv":
        tamper_by_row: dict[int, list[str]] = defaultdict(list)
        if verification:
            for anomaly in verification.get("anomalies", []):
                rid = int(anomaly.get("row_id") or 0)
                if rid > 0:
                    tamper_by_row[rid].append(str(anomaly.get("type") or "unknown"))

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "id",
                "created_at_utc",
                "tenant_id",
                "actor",
                "action",
                "entity_type",
                "entity_id",
                "chain_scope",
                "event_hash",
                "prev_event_hash",
                "tamper_flags",
                "event_id",
                "event_time_utc",
                "event_json",
            ]
        )
        for entry in entries:
            row_id = int(entry.get("id") or 0)
            writer.writerow(
                [
                    row_id,
                    entry.get("created_at_utc"),
                    entry.get("tenant_id"),
                    entry.get("actor"),
                    entry.get("action"),
                    entry.get("entity_type"),
                    entry.get("entity_id"),
                    entry.get("chain_scope"),
                    entry.get("event_hash"),
                    entry.get("prev_event_hash"),
                    ",".join(sorted(set(tamper_by_row.get(row_id, [])))),
                    entry.get("event_id"),
                    entry.get("event_time_utc"),
                    _canonical_json(entry.get("event") or {}),
                ]
            )
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=v2_audit_export.csv"},
        )

    payload = {
        "generated_at_utc": utc_iso_now(),
        "filters": {
            "actor": actor,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "start": start,
            "end": end,
            "tenant_id": scoped_tenant,
            "limit": safe_limit,
        },
        "events": entries,
        "verification": verification,
    }
    return Response(
        content=json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True, default=str) + "\n",
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=v2_audit_export.json"},
    )
