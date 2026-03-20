from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import text

from api import incidents as v1_incidents
from core.security import current_user
from core.time_utils import utc_iso
from db.database import connect
from .audit import log_v2_write_audit
from .common import ok, pagination_meta
from .policy import enforce_abac
from .tenant_contract import normalize_contract_response, org_id_to_tenant_id, resolve_tenant_scope


router = APIRouter(prefix="/incidents")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _with_tenant_scope(
    *,
    user: Mapping[str, Any] | None,
    tenant_id: int | None,
):
    if not isinstance(user, Mapping):
        return user
    effective_user = dict(user)
    effective_user["org_id"] = tenant_id
    return effective_user


def _resolve_incident_delegate_tenant(
    *,
    incident_id: int,
    scoped_tenant: int | None,
) -> int | None:
    db = connect()
    try:
        row = v1_incidents._get_incident_row(db, incident_id, scoped_tenant)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident = v1_incidents._serialize_incident_row(row)
    finally:
        db.close()
    row_tenant = org_id_to_tenant_id((incident or {}).get("org_id"))
    return row_tenant if row_tenant is not None else scoped_tenant


@router.post("/correlate")
def correlate_incidents(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    normalized_payload = dict(payload or {})
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=normalized_payload.get("tenant_id"),
        org_id=normalized_payload.get("org_id"),
        allow_superadmin_override=True,
    )
    if scoped_tenant is not None:
        normalized_payload["tenant_id"] = scoped_tenant
        normalized_payload["org_id"] = scoped_tenant

    decision = enforce_abac(
        action="v2.incidents.correlate",
        user=user,
        request=request,
        resource={"type": "incident_collection", "tenant_id": scoped_tenant},
    )

    effective_user = _with_tenant_scope(user=user, tenant_id=scoped_tenant)
    result = v1_incidents.correlate_incidents(
        request=request,
        payload=normalized_payload,
        user=effective_user,
    )
    log_v2_write_audit(
        action="v2.incidents.correlate",
        entity_type="incident_batch",
        entity_id=None,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "persisted": bool((result or {}).get("persisted")),
            "persisted_groups": _safe_int((result or {}).get("persisted_groups"), 0),
            "created_incidents": _safe_int((result or {}).get("created_incidents"), 0),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(result, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("")
def list_incidents(
    status: str | None = None,
    owner: str | None = None,
    priority: str | None = None,
    due_state: str | None = None,
    include_alerts: bool = False,
    include_history: bool = False,
    history_limit: int = Query(default=20, ge=1, le=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    offset = (page - 1) * page_size
    effective_user = _with_tenant_scope(user=user, tenant_id=scoped_tenant)

    result = v1_incidents.list_incidents(
        status=status,
        owner=owner,
        priority=priority,
        due_state=due_state,
        include_alerts=include_alerts,
        include_history=include_history,
        history_limit=history_limit,
        limit=page_size,
        offset=offset,
        user=effective_user,
    )
    total = _safe_int(result.get("total"), 0) if isinstance(result, dict) else 0
    items = result.get("items") if isinstance(result, dict) else []
    normalized_items = [normalize_contract_response(item) for item in (items or [])]
    return ok(
        {
            "items": normalized_items,
            "pagination": pagination_meta(page=page, page_size=page_size, total=total),
        },
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    include_alerts: bool = False,
    include_history: bool = False,
    history_limit: int = Query(default=20, ge=1, le=200),
    user=Depends(current_user),
):
    user_role = str((user or {}).get("role") or "").strip().lower() if isinstance(user, dict) else ""
    org_id = None if user_role == "superadmin" else resolve_tenant_scope(
        user=user,
        allow_superadmin_override=False,
    )
    db = connect()
    try:
        row = v1_incidents._get_incident_row(db, incident_id, org_id)
        if not row:
            raise HTTPException(status_code=404, detail="Incident not found")
        incident = normalize_contract_response(v1_incidents._serialize_incident_row(row))

        if include_alerts:
            alert_rows = db.execute(
                text(
                    """
                    SELECT alert_id, agent_id, tactic, identity, matched_signals, created_at
                    FROM incident_alerts
                    WHERE incident_id=:incident_id
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    """
                ),
                {"incident_id": incident_id},
            ).fetchall()
            alerts = []
            for alert_row in alert_rows:
                matched_signals = []
                try:
                    matched_signals = json.loads(str(alert_row[4] or "[]"))
                except Exception:
                    matched_signals = []
                alerts.append(
                    {
                        "alert_id": alert_row[0],
                        "agent_id": alert_row[1],
                        "tactic": alert_row[2],
                        "identity": alert_row[3],
                        "matched_signals": matched_signals if isinstance(matched_signals, list) else [],
                        "attached_at": utc_iso(alert_row[5]),
                    }
                )
            incident["alerts"] = alerts

        if include_history:
            assignment_rows = db.execute(
                text(
                    """
                    SELECT previous_owner, new_owner, changed_by, note, created_at
                    FROM incident_assignments
                    WHERE incident_id=:incident_id
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id": incident_id, "limit": history_limit},
            ).fetchall()
            incident["assignment_history"] = [
                {
                    "previous_owner": row[0],
                    "new_owner": row[1],
                    "changed_by": row[2],
                    "note": row[3],
                    "created_at": utc_iso(row[4]),
                }
                for row in assignment_rows
            ]

            sla_rows = db.execute(
                text(
                    """
                    SELECT event_type, detail, actor, created_at
                    FROM incident_sla_events
                    WHERE incident_id=:incident_id
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    LIMIT :limit
                    """
                ),
                {"incident_id": incident_id, "limit": history_limit},
            ).fetchall()
            incident["sla_events"] = [
                {
                    "event_type": row[0],
                    "detail": row[1],
                    "actor": row[2],
                    "created_at": utc_iso(row[3]),
                }
                for row in sla_rows
            ]

        incident = v1_incidents._apply_incident_intelligence(
            db,
            incident,
            alerts=incident.get("alerts") if isinstance(incident.get("alerts"), list) else None,
        )
        return ok(incident, tenant_id=incident.get("tenant_id"), contract="tenant_id_primary")
    finally:
        db.close()


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    normalized_payload = dict(payload or {})
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=normalized_payload.get("tenant_id"),
        org_id=normalized_payload.get("org_id"),
        allow_superadmin_override=True,
    )
    effective_tenant = _resolve_incident_delegate_tenant(
        incident_id=incident_id,
        scoped_tenant=scoped_tenant,
    )
    normalized_payload.pop("tenant_id", None)
    normalized_payload.pop("org_id", None)
    decision = enforce_abac(
        action="v2.incidents.update",
        user=user,
        request=request,
        resource={
            "type": "incident",
            "id": incident_id,
            "tenant_id": effective_tenant,
        },
    )
    effective_user = _with_tenant_scope(user=user, tenant_id=effective_tenant)
    result = v1_incidents.update_incident(
        incident_id=incident_id,
        request=request,
        payload=normalized_payload,
        user=effective_user,
    )
    if isinstance(result, dict) and isinstance(result.get("incident"), dict):
        result["incident"] = normalize_contract_response(result["incident"])
    log_v2_write_audit(
        action="v2.incidents.update",
        entity_type="incident",
        entity_id=incident_id,
        user=user,
        request=request,
        tenant_id=effective_tenant,
        changes={"fields": sorted(list(normalized_payload.keys()))},
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
            "updated": bool((result or {}).get("updated")),
        },
    )
    message = "Incident updated" if bool((result or {}).get("updated")) else "No incident changes applied"
    return ok(result, message=message, tenant_id=effective_tenant, contract="tenant_id_primary")


@router.post("/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    normalized_payload = dict(payload or {})
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=normalized_payload.get("tenant_id"),
        org_id=normalized_payload.get("org_id"),
        allow_superadmin_override=True,
    )
    effective_tenant = _resolve_incident_delegate_tenant(
        incident_id=incident_id,
        scoped_tenant=scoped_tenant,
    )
    normalized_payload.pop("tenant_id", None)
    normalized_payload.pop("org_id", None)
    decision = enforce_abac(
        action="v2.incidents.assign",
        user=user,
        request=request,
        resource={
            "type": "incident",
            "id": incident_id,
            "tenant_id": effective_tenant,
        },
    )
    effective_user = _with_tenant_scope(user=user, tenant_id=effective_tenant)
    result = v1_incidents.assign_incident(
        incident_id=incident_id,
        request=request,
        payload=normalized_payload,
        user=effective_user,
    )
    if isinstance(result, dict) and isinstance(result.get("incident"), dict):
        result["incident"] = normalize_contract_response(result["incident"])
    log_v2_write_audit(
        action="v2.incidents.assign",
        entity_type="incident",
        entity_id=incident_id,
        user=user,
        request=request,
        tenant_id=effective_tenant,
        changes={
            "owner": normalized_payload.get("owner"),
            "due_at": normalized_payload.get("due_at"),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(result, message="Incident assigned", tenant_id=effective_tenant, contract="tenant_id_primary")
