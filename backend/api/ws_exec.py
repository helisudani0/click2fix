from fastapi import APIRouter, HTTPException, WebSocket
from core.ws_bus import subscribe, unsubscribe
from core.security import COOKIE_NAME, decode_token
from core.settings import SETTINGS

router = APIRouter()


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


@router.websocket("/ws/executions/{execution_id}")
async def execution_ws(ws: WebSocket, execution_id: int):
    try:
        _authorize_ws(ws)
    except HTTPException:
        await ws.close(code=4401)
        return
    await ws.accept()
    await subscribe(execution_id, ws)

    try:
        while True:
            await ws.receive_text()
    except Exception:
        await unsubscribe(execution_id, ws)
