from pathlib import Path
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from core.security import ROLE_LEVELS, decode_token, extract_request_token, oauth

router = APIRouter()
OPS_PATH = Path(__file__).resolve().parents[1] / "ui" / "ops.html"


def _resolve_admin_user(request: Request, bearer_token: str | None, query_token: str | None):
    candidates: list[str] = []
    request_token = extract_request_token(request, bearer_token)
    if request_token:
        candidates.append(request_token)
    token_q = str(query_token or "").strip()
    if token_q and token_q not in candidates:
        candidates.append(token_q)
    if not candidates:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for candidate in candidates:
        try:
            user = decode_token(candidate, check_revocation=True)
        except HTTPException:
            continue
        if ROLE_LEVELS.get(str(user.get("role") or "").lower(), 0) < ROLE_LEVELS["admin"]:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/ops", include_in_schema=False)
def ops_console(request: Request, token: str | None = None, bearer_token: str | None = Depends(oauth)):
    _resolve_admin_user(request, bearer_token, token)
    if OPS_PATH.exists():
        nonce = secrets.token_urlsafe(16)
        html = OPS_PATH.read_text(encoding="utf-8").replace("__CSP_NONCE__", nonce)
        response = HTMLResponse(html)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-src 'none';"
        )
        return response
    return HTMLResponse("<h1>Ops console not found.</h1>", status_code=404)
