from pathlib import Path
import secrets

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from core.security import require_role

router = APIRouter()
OPS_PATH = Path(__file__).resolve().parents[1] / "ui" / "ops.html"


@router.get("/ops", include_in_schema=False)
def ops_console(user=Depends(require_role("admin"))):
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
