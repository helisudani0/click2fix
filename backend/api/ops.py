from pathlib import Path
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from core.security import ROLE_LEVELS, decode_token, extract_request_token, oauth
from core.security_monitoring import record_security_event

router = APIRouter()
OPS_PATH = Path(__file__).resolve().parents[1] / "ui" / "ops.html"
OPS_LOGO_PATH = Path(__file__).resolve().parents[1] / "ui" / "c2f-logo.svg"


def _resolve_admin_user(request: Request, bearer_token: str | None):
    candidates: list[str] = []
    request_token = extract_request_token(request, bearer_token)
    if request_token:
        candidates.append(request_token)
    if not candidates:
        record_security_event(
            "ops.auth_missing",
            severity="warning",
            request=request,
            detail="Ops console request did not include a valid auth cookie or bearer token",
        )
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
            record_security_event(
                "ops.auth_forbidden",
                severity="warning",
                request=request,
                user=user,
                detail="Non-admin user attempted to open ops console",
            )
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    record_security_event(
        "ops.auth_rejected",
        severity="warning",
        request=request,
        detail="Ops console request used invalid or revoked credentials",
    )
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.get("/ops", include_in_schema=False)
def ops_console(request: Request, bearer_token: str | None = Depends(oauth)):
    _resolve_admin_user(request, bearer_token)
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


@router.get("/ops/c2f-logo.svg", include_in_schema=False)
def ops_logo():
    if OPS_LOGO_PATH.exists():
        return FileResponse(
            OPS_LOGO_PATH,
            media_type="image/svg+xml",
            headers={"Cache-Control": "public, max-age=86400"},
        )
    raise HTTPException(status_code=404, detail="Ops logo not found")
