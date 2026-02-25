import asyncio
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, WebSocket

from core.indexer_client import IndexerClient
from core.security import COOKIE_NAME, decode_token
from core.settings import SETTINGS
from core.wazuh_client import WazuhClient

router = APIRouter()

clients = []
indexer = IndexerClient()
wazuh = WazuhClient()


def _ws_candidates(ws: WebSocket) -> list[str]:
    candidates: list[str] = []

    auth_header = ws.headers.get("authorization") or ""
    if auth_header.lower().startswith("bearer "):
        header_token = auth_header.split(" ", 1)[1].strip()
        if header_token and header_token not in {"null", "undefined"} and header_token not in candidates:
            candidates.append(header_token)

    cookie_token = ws.cookies.get(COOKIE_NAME)
    if cookie_token and cookie_token not in {"null", "undefined"} and cookie_token not in candidates:
        candidates.append(cookie_token)

    return candidates


def _allowed_origins() -> set[str]:
    cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    raw = cfg.get("cors_origins")
    if isinstance(raw, list):
        return {str(item).strip() for item in raw if str(item).strip()}
    return {"http://localhost:5173", "http://localhost:3000"}


def _validate_ws_origin(ws: WebSocket) -> None:
    origin = (ws.headers.get("origin") or "").strip()
    if not origin:
        return
    allowed = _allowed_origins()
    if "*" in allowed:
        raise HTTPException(status_code=403, detail="Wildcard WS origin is not allowed")
    if origin not in allowed:
        raise HTTPException(status_code=403, detail="WebSocket origin not allowed")


def _authorize_ws(ws: WebSocket) -> None:
    _validate_ws_origin(ws)
    for token in _ws_candidates(ws):
        try:
            decode_token(token)
            return
        except HTTPException:
            continue
    raise HTTPException(status_code=401, detail="Not authenticated")


def _extract_items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        items = (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
        if isinstance(items, list):
            return [item for item in items if isinstance(item, dict)]
    return []


def _alert_id(alert: Dict[str, Any]) -> str | None:
    for key in ("id", "_id", "alert_id"):
        value = alert.get(key)
        if value is not None and not isinstance(value, (dict, list)):
            return str(value)
    return None


def _latest_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    # Prefer indexer-backed results for near real-time alert stream.
    if indexer.enabled:
        try:
            data = indexer.search_alerts(limit=limit, agent_only=True)
            return indexer.extract_alerts(data)
        except HTTPException:
            pass
    try:
        data = wazuh.get_alerts(limit)
        return _extract_items(data)
    except HTTPException:
        return []


@router.websocket("/ws/alerts")
async def alerts_socket(ws: WebSocket):
    try:
        _authorize_ws(ws)
    except HTTPException:
        await ws.close(code=4401)
        return
    await ws.accept()
    clients.append(ws)
    seen_ids: set[str] = set()
    seen_order: List[str] = []
    heartbeat_counter = 0

    try:
        while True:
            alerts = await asyncio.to_thread(_latest_alerts, 25)
            new_batch: List[Dict[str, Any]] = []
            for alert in alerts:
                aid = _alert_id(alert)
                if not aid or aid in seen_ids:
                    continue
                seen_ids.add(aid)
                seen_order.append(aid)
                new_batch.append(alert)

            # Keep memory bounded for long-lived sockets.
            if len(seen_ids) > 2000:
                while len(seen_order) > 1000:
                    stale = seen_order.pop(0)
                    seen_ids.discard(stale)

            # Emit oldest first so UI receives ordered stream.
            for alert in reversed(new_batch):
                await ws.send_json({"event": "alert", "data": alert})

            heartbeat_counter += 1
            if heartbeat_counter >= 6:
                heartbeat_counter = 0
                await ws.send_json({"event": "heartbeat"})

            await asyncio.sleep(5)
    except Exception:
        pass
    finally:
        if ws in clients:
            clients.remove(ws)
