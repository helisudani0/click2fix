import asyncio
import os
from typing import Any, Dict, List
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from core.alert_stream import start_alert_stream, stop_alert_stream, subscribe_alerts, unsubscribe_alerts
from core.indexer_client import IndexerClient
from core.origin_policy import configured_cors_origins, normalize_origin
from core.security import COOKIE_NAME, decode_token
from core.wazuh_client import WazuhClient

router = APIRouter()

indexer = IndexerClient()
wazuh = WazuhClient()


def _safe_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


_STREAM_POLL_SECONDS = max(
    0.2,
    _safe_float(os.getenv("C2F_ALERT_STREAM_POLL_SECONDS"), 1.0),
)
_STREAM_FETCH_LIMIT = max(25, _safe_int(os.getenv("C2F_ALERT_STREAM_FETCH_LIMIT"), 200))
_STREAM_SNAPSHOT_LIMIT = max(1, min(_safe_int(os.getenv("C2F_ALERT_STREAM_SNAPSHOT_LIMIT"), 40), 200))


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
    return set(configured_cors_origins())


def _validate_ws_origin(ws: WebSocket) -> None:
    origin = normalize_origin(ws.headers.get("origin"))
    if not origin:
        return
    allowed = _allowed_origins()
    if "*" in allowed:
        raise HTTPException(status_code=403, detail="Wildcard WS origin is not allowed")
    try:
        parsed_origin = urlsplit(origin)
        origin_host = str(parsed_origin.hostname or "").strip().lower()
    except Exception:
        origin_host = ""
    request_host = str((ws.headers.get("host") or "").split(":", 1)[0]).strip().lower()
    if origin_host and request_host and origin_host == request_host:
        return
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


def _latest_alerts(limit: int = 20) -> List[Dict[str, Any]]:
    # Source fetch for the shared real-time alert stream processor.
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


def _stream_fetch(limit: int) -> list[dict[str, Any]]:
    return _latest_alerts(limit=limit)


async def start_alert_stream_processor(loop: asyncio.AbstractEventLoop) -> None:
    await start_alert_stream(
        loop=loop,
        fetcher=_stream_fetch,
        poll_seconds=_STREAM_POLL_SECONDS,
        fetch_limit=_STREAM_FETCH_LIMIT,
    )


async def stop_alert_stream_processor() -> None:
    await stop_alert_stream()


@router.websocket("/ws/alerts")
@router.websocket("/api/ws/alerts")
async def alerts_socket(ws: WebSocket):
    try:
        _authorize_ws(ws)
    except HTTPException:
        await ws.close(code=4401)
        return
    await ws.accept()
    await start_alert_stream_processor(asyncio.get_running_loop())
    queue, snapshot = await subscribe_alerts(snapshot_limit=_STREAM_SNAPSHOT_LIMIT)
    receiver_task = None

    async def _receive_client_messages() -> None:
        while True:
            payload = await ws.receive_text()
            if str(payload or "").strip().lower() != "ping":
                continue
            await ws.send_json({"event": "heartbeat", "kind": "pong"})

    try:
        receiver_task = asyncio.create_task(_receive_client_messages())
        for alert in snapshot:
            await ws.send_json({"event": "alert", "data": alert})
        while True:
            try:
                alert = await asyncio.wait_for(queue.get(), timeout=15)
                await ws.send_json({"event": "alert", "data": alert})
            except asyncio.TimeoutError:
                await ws.send_json({"event": "heartbeat"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if receiver_task:
            receiver_task.cancel()
        await unsubscribe_alerts(queue)
