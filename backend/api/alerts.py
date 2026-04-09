from typing import Iterable

from fastapi import APIRouter, Depends, HTTPException, Query

from core.ingest_gateway_client import IngestGatewayClient
from core.indexer_client import IndexerClient
from core.security import current_user
from core.wazuh_client import WazuhClient


router = APIRouter()
client = WazuhClient()
indexer = IndexerClient()
ingest_gateway_client = IngestGatewayClient()


def _extract_items(data):
    if isinstance(data, dict):
        return (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
    if isinstance(data, list):
        return data
    return []


def _extract_total_hits(data) -> int | None:
    if not isinstance(data, dict):
        return None
    hits = data.get("hits")
    if not isinstance(hits, dict):
        return None
    total = hits.get("total")
    if isinstance(total, dict):
        try:
            return int(total.get("value"))
        except Exception:
            return None
    try:
        return int(total)
    except Exception:
        return None


def _extract_total_affected_items(data) -> int | None:
    if not isinstance(data, dict):
        return None
    candidates = [
        data.get("data", {}).get("total_affected_items"),
        data.get("total_affected_items"),
        data.get("total"),
        data.get("data", {}).get("total"),
    ]
    for value in candidates:
        try:
            if value is None:
                continue
            parsed = int(value)
            if parsed >= 0:
                return parsed
        except Exception:
            continue
    return None


def _severity_bucket(level_value) -> str:
    try:
        level = int(level_value)
    except Exception:
        return "unknown"
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _severity_summary_from_items(items, total_hint: int | None = None):
    bucket = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for alert in items if isinstance(items, list) else []:
        if not isinstance(alert, dict):
            continue
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        level = rule.get("level") if isinstance(rule, dict) else alert.get("level")
        bucket[_severity_bucket(level)] += 1
    total = int(total_hint) if isinstance(total_hint, int) and total_hint >= 0 else sum(bucket.values())
    known = bucket["critical"] + bucket["high"] + bucket["medium"] + bucket["low"] + bucket["unknown"]
    if total > known:
        bucket["unknown"] += (total - known)
    return {"total": total, **bucket}


def _extract_indexer_summary(data):
    if not isinstance(data, dict):
        return None
    total = _extract_total_hits(data)
    if total is None:
        return None
    severity = data.get("aggregations", {}).get("severity", {}).get("buckets", {})
    bucket = {
        "critical": int((severity.get("critical") or {}).get("doc_count") or 0),
        "high": int((severity.get("high") or {}).get("doc_count") or 0),
        "medium": int((severity.get("medium") or {}).get("doc_count") or 0),
        "low": int((severity.get("low") or {}).get("doc_count") or 0),
        "unknown": int((severity.get("unknown") or {}).get("doc_count") or 0),
    }
    known = bucket["critical"] + bucket["high"] + bucket["medium"] + bucket["low"] + bucket["unknown"]
    if total > known:
        bucket["unknown"] += (total - known)
    return {"total": int(total), **bucket}


def _alert_agent_id(alert):
    if not isinstance(alert, dict):
        return None
    agent = alert.get("agent") or {}
    if isinstance(agent, dict):
        return str(agent.get("id") or agent.get("agent_id") or agent.get("name") or "").strip() or None
    if isinstance(agent, str):
        return agent.strip() or None
    return str(alert.get("agent_id") or alert.get("agent") or "").strip() or None


def _normalized_agent_id(value):
    raw = str(value or "").strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _agent_id_variants(value):
    raw = str(value or "").strip()
    if not raw:
        return set()
    out = {raw, _normalized_agent_id(raw)}
    if raw.isdigit():
        out.add(str(int(raw)))
        out.add(str(int(raw)).zfill(3))
    return {entry for entry in out if entry}


def _store_alerts_background(items: Iterable[dict], *, tenant_id: int | None) -> None:
    rows = [row for row in (items or []) if isinstance(row, dict)]
    if not rows:
        return
    if not ingest_gateway_client.enabled:
        return
    try:
        ingest_gateway_client.ingest_wazuh_alerts(
            {
                "tenant_id": tenant_id,
                "actor": "api.alerts",
                "source_type": "endpoint",
                "alerts": rows[:500],
            }
        )
    except Exception:
        return


@router.get("")
def list_alerts(
    limit: int = Query(default=1000, ge=1, le=20000),
    q: str | None = None,
    agent_id: str | None = None,
    agent_only: bool = False,
    start: str | None = None,
    end: str | None = None,
    include_total: bool = False,
    include_summary: bool = False,
    user=Depends(current_user),
):
    """
    Get alerts from Wazuh and enrich them with IOC data
    """
    alerts = []
    total_alerts: int | None = None
    summary_payload: dict | None = None
    indexer_query_succeeded = False
    if indexer.enabled:
        try:
            data = indexer.search_alerts(
                limit=limit,
                query=q,
                agent_id=agent_id,
                agent_only=agent_only,
                start=start,
                end=end,
            )
            alerts = indexer.extract_alerts(data)
            total_alerts = _extract_total_hits(data)
            indexer_query_succeeded = True
        except HTTPException:
            alerts = []
            total_alerts = None
        if include_total or include_summary:
            try:
                summary_data = indexer.search_alerts_summary(
                    query=q,
                    agent_id=agent_id,
                    agent_only=agent_only,
                    start=start,
                    end=end,
                )
                summary_payload = _extract_indexer_summary(summary_data)
                if summary_payload and isinstance(summary_payload.get("total"), int):
                    total_alerts = int(summary_payload["total"])
            except HTTPException:
                pass

    if not indexer_query_succeeded:
        try:
            raw_alerts = client.get_alerts(limit)
        except HTTPException:
            if include_total or include_summary:
                return {
                    "items": [],
                    "total": 0,
                    "returned": 0,
                    "limited": False,
                    "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                }
            return []

        alerts = _extract_items(raw_alerts)
        total_alerts = _extract_total_affected_items(raw_alerts)
        if total_alerts is None:
            total_alerts = len(alerts)

    items = alerts if isinstance(alerts, list) else []
    if agent_only:
        items = [a for a in items if _normalized_agent_id(_alert_agent_id(a)) not in ("", "000")]
    if agent_id:
        variants = _agent_id_variants(agent_id)
        items = [a for a in items if _alert_agent_id(a) in variants or _normalized_agent_id(_alert_agent_id(a)) in variants]

    _store_alerts_background(
        items,
        tenant_id=(user.get("org_id") if isinstance(user, dict) else None),
    )
    if include_total or include_summary:
        total_value = total_alerts if isinstance(total_alerts, int) and total_alerts >= 0 else len(items)
        if summary_payload is None:
            summary_payload = _severity_summary_from_items(items, total_hint=total_value)
        return {
            "items": items,
            "total": total_value,
            "returned": len(items),
            "limited": total_value > len(items),
            "summary": summary_payload,
        }
    return items


@router.get("/{alert_id}")
def get_alert(alert_id: str, user=Depends(current_user)):
    """
    Get a specific alert by ID
    """
    if indexer.enabled:
        try:
            data = indexer.search_alerts(
                limit=1,
                query=f'id:"{alert_id}" OR _id:"{alert_id}"',
            )
            items = indexer.extract_alerts(data)
            if items:
                return items[0]
        except HTTPException:
            pass

    try:
        alerts = _extract_items(client.get_alerts(500))
    except HTTPException:
        alerts = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        raw_id = alert.get("id") or alert.get("_id") or alert.get("alert_id")
        if raw_id is not None and str(raw_id) == str(alert_id):
            return alert

    raise HTTPException(status_code=404, detail="Alert not found")
