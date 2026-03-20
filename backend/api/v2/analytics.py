from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from core.active_defense import predict_alert_storm
from core.analytics import alert_summary, hourly_volume, kill_chain, overview
from core.security import current_user
from .common import ok


router = APIRouter(prefix="/analytics")
_ALLOWED_SORT_ORDERS = {"asc", "desc"}


def _normalize_sort_order(sort_order: str, default: str = "desc") -> str:
    order = str(sort_order or default).strip().lower() or default
    if order not in _ALLOWED_SORT_ORDERS:
        raise HTTPException(status_code=400, detail=f"Unsupported sort_order '{sort_order}'")
    return order


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


@router.get("/overview")
def analytics_overview(user=Depends(current_user)):
    return ok(overview())


@router.get("/kill-chain")
def analytics_kill_chain(
    case_id: int | None = None,
    hours: int = Query(default=24, ge=1, le=720),
    sort_by: str = "count",
    sort_order: str = "desc",
    user=Depends(current_user),
):
    field = str(sort_by or "count").strip().lower()
    if field not in {"count", "stage"}:
        raise HTTPException(status_code=400, detail=f"Unsupported sort_by '{sort_by}'")
    order = _normalize_sort_order(sort_order, default="desc")

    result = kill_chain(case_id, hours=hours) or {}
    stages_dict = result.get("stages") if isinstance(result, dict) else {}
    stage_items = [
        {"stage": str(stage), "count": _safe_int(count, 0)}
        for stage, count in (stages_dict or {}).items()
    ]

    stage_items.sort(key=lambda item: item.get("stage", ""))
    if field == "count":
        stage_items.sort(key=lambda item: _safe_int(item.get("count"), 0), reverse=order == "desc")
    elif order == "desc":
        stage_items.reverse()

    payload = dict(result) if isinstance(result, dict) else {}
    payload["stages"] = stage_items
    return ok(payload, sort_by=field, sort_order=order)


@router.get("/alert/{alert_id}")
def analytics_alert_summary(alert_id: str, user=Depends(current_user)):
    return ok(alert_summary(alert_id))


@router.get("/hourly")
def analytics_hourly(
    hours: int = Query(default=72, ge=1, le=720),
    sort_order: str = "asc",
    user=Depends(current_user),
):
    order = _normalize_sort_order(sort_order, default="asc")
    series = hourly_volume(hours)
    items = list(series or [])
    items.sort(key=lambda item: str((item or {}).get("hour") or ""))
    if order == "desc":
        items.reverse()
    return ok(
        {
            "hours": hours,
            "series": items,
            "storm_prediction": predict_alert_storm(items),
        },
        sort_order=order,
    )
