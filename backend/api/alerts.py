import threading
from typing import Iterable

from fastapi import APIRouter, Depends, HTTPException, Query

from core.alert_store import store_alerts
from core.indexer_client import IndexerClient
from core.security import current_user
from core.wazuh_client import WazuhClient


router = APIRouter()
client = WazuhClient()
indexer = IndexerClient()
_store_lock = threading.Lock()
_store_inflight = False


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


def _store_alerts_background(items: Iterable[dict]) -> None:
    rows = [row for row in (items or []) if isinstance(row, dict)]
    if not rows:
        return

    snapshot = rows[:500]

    def _task(batch):
        global _store_inflight
        try:
            store_alerts(batch)
        finally:
            with _store_lock:
                _store_inflight = False

    with _store_lock:
        global _store_inflight
        if _store_inflight:
            return
        _store_inflight = True
    threading.Thread(target=_task, args=(snapshot,), daemon=True).start()


@router.get("")
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    q: str | None = None,
    agent_id: str | None = None,
    agent_only: bool = False,
    start: str | None = None,
    end: str | None = None,
    user=Depends(current_user),
):
    """
    Get alerts from Wazuh and enrich them with IOC data
    """
    alerts = []
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
        except HTTPException:
            alerts = []

    if not alerts:
        try:
            raw_alerts = client.get_alerts(limit)
        except HTTPException:
            return []

        alerts = _extract_items(raw_alerts)

    items = alerts if isinstance(alerts, list) else []
    if agent_only:
        items = [a for a in items if _normalized_agent_id(_alert_agent_id(a)) not in ("", "000")]
    if agent_id:
        variants = _agent_id_variants(agent_id)
        items = [a for a in items if _alert_agent_id(a) in variants or _normalized_agent_id(_alert_agent_id(a)) in variants]

    _store_alerts_background(items)
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
