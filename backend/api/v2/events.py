from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from core.active_defense import interpret_semantic_search
from core.event_bus import get_event_bus, get_schema_registry
from core.cross_domain_detection import correlate_cross_domain_events
from core.ingest_gateway_client import IngestGatewayClient
from core.event_indexer_client import EventIndexerClient
from core.retention import (
    event_indexer_stream_for_policy,
    normalize_data_class,
    normalize_retention_status,
    retention_policy_by_class,
    serialize_retention_policy,
)
from core.security import require_role
from db.database import connect
from .audit import log_v2_write_audit
from .common import ok
from .policy import enforce_abac
from .tenant_contract import resolve_tenant_scope


router = APIRouter(prefix="/events")
event_indexer_client = EventIndexerClient()
ingest_gateway_client = IngestGatewayClient()

_ALLOWED_SOURCE_TYPES = {
    "endpoint",
    "network",
    "cloud",
    "identity",
    "email",
    "devsecops",
    "generic",
}


def _bool_flag(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


class EventIngestRequest(BaseModel):
    source_type: str = Field(default="generic")
    tenant_id: int | None = Field(default=None, ge=1)
    raw_event: dict[str, Any] = Field(default_factory=dict)
    event_id: str | None = None
    event_time: str | int | float | None = None
    severity_raw: str | int | None = None
    asset_id: str | None = None
    identity_id: str | None = None
    trace_id: str | None = None
    normalized_fields: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    risk_context: dict[str, Any] = Field(default_factory=dict)
    confidence: int | None = Field(default=None, ge=1, le=100)
    publish: bool = True

    @field_validator("source_type")
    @classmethod
    def validate_source_type(cls, value: str):
        source = str(value or "").strip().lower() or "generic"
        if source not in _ALLOWED_SOURCE_TYPES:
            raise ValueError(f"source_type must be one of: {', '.join(sorted(_ALLOWED_SOURCE_TYPES))}")
        return source


class EventReplayRequest(BaseModel):
    queue_event_ids: list[str] = Field(default_factory=list, min_length=1, max_length=200)

    @field_validator("queue_event_ids")
    @classmethod
    def validate_queue_event_ids(cls, value: list[str]):
        cleaned = [str(item or "").strip() for item in value if str(item or "").strip()]
        if not cleaned:
            raise ValueError("queue_event_ids cannot be empty")
        return cleaned


class EventQueueRunRequest(BaseModel):
    batch_size: int | None = Field(default=None, ge=1, le=200)


class EventLifecycleRunRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    data_class: str = Field(default="events", min_length=1, max_length=120)
    dry_run: bool = False

    @field_validator("data_class")
    @classmethod
    def validate_data_class(cls, value: str):
        try:
            return normalize_data_class(value)
        except HTTPException as exc:
            raise ValueError(str(exc.detail)) from exc


class EventLifecycleBatchRunRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    data_classes: list[str] = Field(default_factory=list, max_length=20)
    dry_run: bool = False

    @field_validator("data_classes")
    @classmethod
    def validate_data_classes(cls, value: list[str]):
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in value or []:
            cleaned = normalize_data_class(raw)
            if cleaned in seen:
                continue
            normalized.append(cleaned)
            seen.add(cleaned)
        return normalized


def _list_event_indexer_retention_policies(
    *,
    tenant_id: int,
    data_classes: list[str] | None = None,
) -> list[dict[str, Any]]:
    where_parts = [
        "org_id=:tenant_id",
        "storage_backend=:storage_backend",
        "status=:status",
    ]
    params: dict[str, Any] = {
        "tenant_id": int(tenant_id),
        "storage_backend": "event_indexer",
        "status": "active",
    }
    normalized_classes = [
        normalize_data_class(value)
        for value in (data_classes or [])
        if str(value or "").strip()
    ]
    if normalized_classes:
        placeholders: list[str] = []
        for idx, value in enumerate(normalized_classes):
            key = f"data_class_{idx}"
            placeholders.append(f":{key}")
            params[key] = value
        where_parts.append(f"data_class IN ({', '.join(placeholders)})")

    db = connect()
    try:
        rows = db.execute(
            text(
                f"""
                SELECT
                    id,
                    org_id,
                    data_class,
                    storage_backend,
                    stream,
                    warm_after_days,
                    cold_after_days,
                    archive_after_days,
                    delete_after_days,
                    archive_backend,
                    legal_hold,
                    status,
                    notes,
                    created_by,
                    updated_by,
                    last_applied_at,
                    created_at,
                    updated_at
                FROM retention_policies
                WHERE {' AND '.join(where_parts)}
                ORDER BY data_class ASC
                """
            ),
            params,
        ).fetchall()
        return [serialize_retention_policy(row) for row in rows]
    finally:
        db.close()


def _get_retention_policy_or_404(*, tenant_id: int, data_class: str) -> dict[str, Any]:
    db = connect()
    try:
        row = retention_policy_by_class(db, tenant_id=tenant_id, data_class=data_class)
        if not row:
            raise HTTPException(status_code=404, detail="Retention policy not found")
        policy = serialize_retention_policy(row)
    finally:
        db.close()

    policy_status = normalize_retention_status(policy.get("status") or "active")
    if policy_status != "active":
        raise HTTPException(status_code=409, detail="Retention policy is paused")
    return policy


def _mark_retention_policy_applied(*, tenant_id: int, data_class: str) -> None:
    db = connect()
    try:
        db.execute(
            text(
                """
                UPDATE retention_policies
                SET last_applied_at=CURRENT_TIMESTAMP
                WHERE org_id=:tenant_id AND data_class=:data_class
                """
            ),
            {
                "tenant_id": int(tenant_id),
                "data_class": normalize_data_class(data_class),
            },
        )
        db.commit()
    finally:
        db.close()


@router.get("/topics")
def list_event_topics(user=Depends(require_role("analyst"))):
    bus = get_event_bus()
    return ok(bus.describe_topics())


@router.get("/schemas")
def list_event_schemas(user=Depends(require_role("analyst"))):
    schemas = get_schema_registry().list()
    return ok({"items": schemas, "count": len(schemas)})


@router.get("/published")
def list_recent_published_events(
    topic: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    user=Depends(require_role("analyst")),
):
    bus = get_event_bus()
    rows = bus.recent(topic=topic, limit=limit)
    return ok({"items": rows, "count": len(rows), "topic": topic, "backend": bus.backend})


@router.get("/search")
def search_events(
    tenant_id: int | None = Query(default=None, ge=1),
    agent_id: str | None = Query(default=None),
    stream: str | None = Query(default=None),
    storage_tier: str | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    q: str | None = Query(default=None, min_length=1, max_length=200),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for indexed event queries")
    semantic = interpret_semantic_search(q or "")
    effective_agent_id = agent_id or (semantic.get("agent_id") if semantic.get("enabled") else None)
    effective_query = semantic.get("query") if semantic.get("enabled") else q
    effective_start = start or (semantic.get("start") if semantic.get("enabled") else None)
    result = event_indexer_client.search_events(
        tenant_id=resolved_tenant_id,
        agent_id=effective_agent_id,
        stream=stream,
        storage_tier=storage_tier,
        category=category,
        severity=severity,
        q=effective_query,
        start=effective_start,
        end=end,
        limit=limit,
        offset=offset,
    )
    payload = {
        "tenant_id": resolved_tenant_id,
        "items": result.get("data", {}).get("items", []),
        "total": result.get("data", {}).get("total", 0),
        "limit": result.get("data", {}).get("limit", limit),
        "offset": result.get("data", {}).get("offset", offset),
        "semantic_search": semantic if semantic.get("enabled") else {"enabled": False, "query": q or ""},
    }
    return ok(payload, tenant_id=resolved_tenant_id, contract="tenant_id_primary")


@router.get("/timeseries")
def time_series_events(
    tenant_id: int | None = Query(default=None, ge=1),
    agent_id: str | None = Query(default=None),
    stream: str | None = Query(default=None),
    storage_tier: str | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    bucket: str = Query(default="1h"),
    group_by: str | None = Query(default=None),
    limit: int = Query(default=2000, ge=10, le=5000),
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for time-series queries")
    result = event_indexer_client.time_series(
        tenant_id=resolved_tenant_id,
        agent_id=agent_id,
        stream=stream,
        storage_tier=storage_tier,
        category=category,
        severity=severity,
        start=start,
        end=end,
        bucket=bucket,
        group_by=group_by,
        limit=limit,
    )
    payload = {
        "tenant_id": resolved_tenant_id,
        "series": result.get("data", {}).get("series", []),
        "totals": result.get("data", {}).get("totals", []),
        "bucket": result.get("data", {}).get("bucket", bucket),
        "group_by": result.get("data", {}).get("group_by"),
        "total_points": result.get("data", {}).get("total_points", 0),
        "total_count": result.get("data", {}).get("total_count", 0),
    }
    return ok(payload, tenant_id=resolved_tenant_id, contract="tenant_id_primary")


@router.get("/correlate")
def correlate_events(
    tenant_id: int | None = Query(default=None, ge=1),
    agent_id: str | None = Query(default=None),
    stream: str | None = Query(default=None),
    storage_tier: str | None = Query(default=None),
    category: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    window: str = Query(default="15m"),
    min_group_size: int = Query(default=3, ge=2, le=100),
    cross_domain: bool = Query(default=False),
    min_domains: int = Query(default=2, ge=2, le=4),
    include_detections: bool = Query(default=True),
    max_groups: int = Query(default=50, ge=1, le=500),
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for correlation queries")
    cross_domain_enabled = _bool_flag(cross_domain, default=False)
    include_detections_enabled = _bool_flag(include_detections, default=True)
    if cross_domain_enabled:
        search_limit = max(200, min(2000, int(max_groups) * max(4, int(min_group_size)) * 2))
        indexed = event_indexer_client.search_events(
            tenant_id=resolved_tenant_id,
            agent_id=agent_id,
            stream=stream,
            storage_tier=storage_tier,
            category=category,
            severity=severity,
            q=None,
            start=start,
            end=end,
            limit=search_limit,
            offset=0,
        )
        indexed_data = indexed.get("data", {}) if isinstance(indexed, dict) else {}
        items = indexed_data.get("items") if isinstance(indexed_data.get("items"), list) else []
        correlation = correlate_cross_domain_events(
            items=items,
            window=window,
            min_group_size=min_group_size,
            min_domains=min_domains,
            max_groups=max_groups,
        )
        payload = {
            "tenant_id": resolved_tenant_id,
            "window": correlation.get("window", window),
            "window_seconds": correlation.get("window_seconds"),
            "groups": correlation.get("groups", []),
            "total_groups": correlation.get("total_groups", 0),
            "correlated_events": correlation.get("correlated_events", 0),
            "cross_domain": True,
            "min_domains": correlation.get("min_domains", min_domains),
            "analyzed_events": correlation.get("analyzed_events", len(items)),
            "scan_limit": search_limit,
            "total_candidates": indexed_data.get("total", len(items)),
            "truncated": int(indexed_data.get("total", len(items)) or 0) > len(items),
        }
        if include_detections_enabled:
            payload["detections"] = correlation.get("detections", [])
    else:
        result = event_indexer_client.correlate_events(
            tenant_id=resolved_tenant_id,
            agent_id=agent_id,
            stream=stream,
            storage_tier=storage_tier,
            category=category,
            severity=severity,
            start=start,
            end=end,
            window=window,
            min_group_size=min_group_size,
            max_groups=max_groups,
        )
        payload = {
            "tenant_id": resolved_tenant_id,
            "window": result.get("data", {}).get("window", window),
            "groups": result.get("data", {}).get("groups", []),
            "total_groups": result.get("data", {}).get("total_groups", 0),
            "correlated_events": result.get("data", {}).get("correlated_events", 0),
            "cross_domain": False,
        }
    return ok(payload, tenant_id=resolved_tenant_id, contract="tenant_id_primary")


@router.get("/raw/{event_id}")
def get_raw_event(
    event_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    agent_id: str | None = Query(default=None),
    stream: str | None = Query(default=None),
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for indexed event queries")
    result = event_indexer_client.get_event(
        tenant_id=resolved_tenant_id,
        event_id=event_id,
        agent_id=agent_id,
        stream=stream,
    )
    payload = {
        "tenant_id": resolved_tenant_id,
        "item": result.get("data", {}),
    }
    return ok(payload, tenant_id=resolved_tenant_id, contract="tenant_id_primary")


@router.get("/lifecycle/summary")
def get_event_lifecycle_summary(
    tenant_id: int | None = Query(default=None, ge=1),
    data_class: str = Query(default="events", min_length=1, max_length=120),
    user=Depends(require_role("analyst")),
):
    normalized_data_class = normalize_data_class(data_class)
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for lifecycle summary")
    policy = _get_retention_policy_or_404(
        tenant_id=resolved_tenant_id,
        data_class=normalized_data_class,
    )
    result = event_indexer_client.lifecycle_summary(
        tenant_id=resolved_tenant_id,
        stream=event_indexer_stream_for_policy(policy),
        warm_after_days=int(policy.get("warm_after_days") or 0),
        cold_after_days=int(policy.get("cold_after_days") or 0),
        archive_after_days=int(policy.get("archive_after_days") or 0),
        delete_after_days=(
            int(policy["delete_after_days"])
            if policy.get("delete_after_days") is not None
            else None
        ),
        legal_hold=bool(policy.get("legal_hold")),
        archive_backend=str(policy.get("archive_backend") or "").strip().lower() or None,
    )
    return ok(
        {
            "tenant_id": resolved_tenant_id,
            "data_class": normalized_data_class,
            "policy": policy,
            "summary": result.get("data", {}),
        },
        tenant_id=resolved_tenant_id,
        contract="tenant_id_primary",
    )


@router.post("/lifecycle/apply")
def apply_event_lifecycle(
    payload: EventLifecycleRunRequest,
    request: Request,
    user=Depends(require_role("admin")),
):
    normalized_data_class = normalize_data_class(payload.data_class)
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=payload.tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for lifecycle apply")
    decision = enforce_abac(
        action="v2.events.lifecycle.apply",
        user=user,
        request=request,
        resource={"type": "event_lifecycle", "tenant_id": resolved_tenant_id, "data_class": normalized_data_class},
    )
    policy = _get_retention_policy_or_404(
        tenant_id=resolved_tenant_id,
        data_class=normalized_data_class,
    )
    result = event_indexer_client.apply_lifecycle(
        tenant_id=resolved_tenant_id,
        stream=event_indexer_stream_for_policy(policy),
        warm_after_days=int(policy.get("warm_after_days") or 0),
        cold_after_days=int(policy.get("cold_after_days") or 0),
        archive_after_days=int(policy.get("archive_after_days") or 0),
        delete_after_days=(
            int(policy["delete_after_days"])
            if policy.get("delete_after_days") is not None
            else None
        ),
        legal_hold=bool(policy.get("legal_hold")),
        archive_backend=str(policy.get("archive_backend") or "").strip().lower() or None,
        dry_run=bool(payload.dry_run),
    )
    if not payload.dry_run:
        _mark_retention_policy_applied(tenant_id=resolved_tenant_id, data_class=normalized_data_class)
    log_v2_write_audit(
        action="v2.events.lifecycle.apply",
        entity_type="retention_policy",
        entity_id=normalized_data_class,
        user=user,
        request=request,
        tenant_id=resolved_tenant_id,
        changes={
            "data_class": normalized_data_class,
            "dry_run": bool(payload.dry_run),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
            "stream": event_indexer_stream_for_policy(policy),
            "deleted": result.get("data", {}).get("deleted"),
        },
    )
    return ok(
        {
            "tenant_id": resolved_tenant_id,
            "data_class": normalized_data_class,
            "policy": policy,
            "result": result.get("data", {}),
        },
        message="Lifecycle policy applied",
        tenant_id=resolved_tenant_id,
        contract="tenant_id_primary",
    )


@router.post("/lifecycle/apply-all")
def apply_all_event_lifecycle(
    payload: EventLifecycleBatchRunRequest,
    request: Request,
    user=Depends(require_role("admin")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=payload.tenant_id,
        allow_superadmin_override=True,
    )
    if resolved_tenant_id is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for lifecycle batch apply")
    decision = enforce_abac(
        action="v2.events.lifecycle.apply_batch",
        user=user,
        request=request,
        resource={"type": "event_lifecycle_batch", "tenant_id": resolved_tenant_id},
    )
    policies = _list_event_indexer_retention_policies(
        tenant_id=resolved_tenant_id,
        data_classes=payload.data_classes or None,
    )
    policy_by_class = {
        normalize_data_class(item.get("data_class")): item
        for item in policies
    }

    ordered_data_classes = payload.data_classes or sorted(policy_by_class.keys())
    if not ordered_data_classes:
        return ok(
            {
                "tenant_id": resolved_tenant_id,
                "requested": 0,
                "applied": 0,
                "failed": 0,
                "results": [],
            },
            message="No active event-indexer retention policies found",
            tenant_id=resolved_tenant_id,
            contract="tenant_id_primary",
        )

    results: list[dict[str, Any]] = []
    applied = 0
    failed = 0
    for data_class in ordered_data_classes:
        policy = policy_by_class.get(normalize_data_class(data_class))
        if not policy:
            failed += 1
            results.append(
                {
                    "data_class": normalize_data_class(data_class),
                    "status": "not_found",
                    "error": "Active event-indexer retention policy not found",
                }
            )
            continue
        stream = event_indexer_stream_for_policy(policy)
        try:
            apply_result = event_indexer_client.apply_lifecycle(
                tenant_id=resolved_tenant_id,
                stream=stream,
                warm_after_days=int(policy.get("warm_after_days") or 0),
                cold_after_days=int(policy.get("cold_after_days") or 0),
                archive_after_days=int(policy.get("archive_after_days") or 0),
                delete_after_days=(
                    int(policy["delete_after_days"])
                    if policy.get("delete_after_days") is not None
                    else None
                ),
                legal_hold=bool(policy.get("legal_hold")),
                archive_backend=str(policy.get("archive_backend") or "").strip().lower() or None,
                dry_run=bool(payload.dry_run),
            )
            if not payload.dry_run:
                _mark_retention_policy_applied(
                    tenant_id=resolved_tenant_id,
                    data_class=normalize_data_class(policy.get("data_class")),
                )
            applied += 1
            results.append(
                {
                    "data_class": normalize_data_class(policy.get("data_class")),
                    "stream": stream,
                    "status": "dry_run" if payload.dry_run else "applied",
                    "result": apply_result.get("data", {}),
                }
            )
        except HTTPException as exc:
            failed += 1
            results.append(
                {
                    "data_class": normalize_data_class(policy.get("data_class")),
                    "stream": stream,
                    "status": "failed",
                    "error": exc.detail,
                }
            )
        except Exception as exc:
            failed += 1
            results.append(
                {
                    "data_class": normalize_data_class(policy.get("data_class")),
                    "stream": stream,
                    "status": "failed",
                    "error": str(exc),
                }
            )

    log_v2_write_audit(
        action="v2.events.lifecycle.apply_batch",
        entity_type="retention_policy_batch",
        entity_id=",".join(ordered_data_classes[:5]),
        user=user,
        request=request,
        tenant_id=resolved_tenant_id,
        changes={
            "requested": len(ordered_data_classes),
            "applied": applied,
            "failed": failed,
            "dry_run": bool(payload.dry_run),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        {
            "tenant_id": resolved_tenant_id,
            "requested": len(ordered_data_classes),
            "applied": applied,
            "failed": failed,
            "dry_run": bool(payload.dry_run),
            "results": results,
        },
        message="Lifecycle policies executed",
        tenant_id=resolved_tenant_id,
        contract="tenant_id_primary",
    )


@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    payload: EventIngestRequest,
    request: Request,
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=payload.tenant_id,
        allow_superadmin_override=True,
    )
    decision = enforce_abac(
        action="v2.events.ingest",
        user=user,
        request=request,
        resource={"type": "event_ingest", "tenant_id": resolved_tenant_id},
    )
    actor = user.get("sub") if isinstance(user, dict) else "system"
    request_payload = payload.model_dump(exclude_none=True)
    request_payload["tenant_id"] = resolved_tenant_id
    result = ingest_gateway_client.ingest_event(request_payload)
    response_data = result.get("data", result)
    event_id = payload.event_id
    log_v2_write_audit(
        action="v2.events.ingest",
        entity_type="event",
        entity_id=event_id or payload.event_id,
        user=user,
        request=request,
        tenant_id=resolved_tenant_id,
        changes={
            "source_type": payload.source_type,
            "publish": bool(payload.publish),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        {
            **response_data,
        },
        message="Event accepted for asynchronous ingestion",
        tenant_id=resolved_tenant_id,
        contract="tenant_id_primary",
    )


@router.get("/ingestion/queue")
def list_ingestion_queue_events(
    tenant_id: int | None = Query(default=None, ge=1),
    stream: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    include_payload: bool = Query(default=False),
    user=Depends(require_role("analyst")),
):
    resolved_tenant_id = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    params = {
        "tenant_id": resolved_tenant_id,
        "stream": stream,
        "status": status,
        "limit": limit,
        "offset": offset,
        "include_payload": bool(include_payload),
    }
    queue_result = ingest_gateway_client.list_ingestion_queue(params=params)
    queue_data = queue_result.get("data", queue_result)
    return ok(
        queue_data,
        tenant_id=resolved_tenant_id,
        contract="tenant_id_primary",
    )


@router.post("/ingestion/replay", status_code=status.HTTP_202_ACCEPTED)
def replay_queue_events(
    payload: EventReplayRequest,
    request: Request,
    user=Depends(require_role("admin")),
):
    decision = enforce_abac(
        action="v2.events.ingestion.replay",
        user=user,
        request=request,
        resource={"type": "event_ingestion_queue"},
    )
    actor = user.get("sub") if isinstance(user, dict) else "system"
    result = ingest_gateway_client.replay_ingestion_events(
        {"queue_event_ids": payload.queue_event_ids}
    )
    response_data = result.get("data", result)
    log_v2_write_audit(
        action="v2.events.ingestion.replay",
        entity_type="event_ingestion_queue",
        entity_id=",".join(payload.queue_event_ids[:5]),
        user=user,
        request=request,
        tenant_id=(user.get("org_id") if isinstance(user, dict) else None),
        changes={
            "requested": len(payload.queue_event_ids),
            "accepted": int(result.get("accepted") or 0),
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        {
            **response_data,
        },
        message="Replay events accepted for asynchronous ingestion",
    )


@router.post("/ingestion/run")
def run_ingestion_now(
    request: Request,
    payload: EventQueueRunRequest | None = None,
    user=Depends(require_role("admin")),
):
    body = payload or EventQueueRunRequest()
    decision = enforce_abac(
        action="v2.events.ingestion.run",
        user=user,
        request=request,
        resource={"type": "event_ingestion_queue"},
    )
    actor = user.get("sub") if isinstance(user, dict) else "system"
    result = ingest_gateway_client.run_ingestion_cycle({"batch_size": body.batch_size or 25})
    response_data = result.get("data", result)
    log_v2_write_audit(
        action="v2.events.ingestion.run",
        entity_type="event_ingestion_queue",
        entity_id=None,
        user=user,
        request=request,
        tenant_id=(user.get("org_id") if isinstance(user, dict) else None),
        changes={
            "batch_size": body.batch_size or 25,
            "processed": int(result.get("processed") or 0),
            "failed": int(result.get("failed") or 0),
        },
        metadata={
            "triggered_by": str(actor),
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        {
            **response_data,
        },
        message="Ingestion queue processed",
    )
