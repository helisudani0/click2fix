import asyncio
import logging
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

# Import all routers including websocket streams
from api import actions, agents, alerts, analytics, approvals, audit, auth, cases, changes, dashboard, executions, forensics, governance, incidents, integration, ioc, ops, orgs, playbooks, remediation, scheduler, system, vulnerabilities, ws, ws_exec
from core.http_security import (
    CSRFMiddleware,
    InMemoryRateLimitMiddleware,
    RateLimitRule,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
## try:
##     from core.http_security import TenantScopeMiddleware
## except Exception:
##     TenantScopeMiddleware = None
TenantScopeMiddleware = None
from core.execution_reconciler import reconcile_orphan_executions
from core.scheduler import start_scheduler, stop_scheduler
from core.security import COOKIE_NAME, CSRF_COOKIE_NAME
from core.security_posture import assess_security_posture, record_posture_findings
from core.settings import SETTINGS
from core.time_utils import utc_iso_now
from core.ws_bus import close_redis, init_redis, set_main_loop
from db.database import init as init_db

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Click2Fix SOAR API",
    description="Wazuh Vulnerability & Incident Response Orchestration",
    version="1.1.0"
)


def _security_cfg() -> dict:
    return SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}


def _cfg_list(value, fallback):
    if isinstance(value, list):
        out = [str(item).strip() for item in value if str(item).strip()]
        return out or fallback
    return fallback


def _env_list(name: str) -> list[str] | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    parts = [item.strip() for item in str(raw).split(",")]
    values = [item for item in parts if item]
    return values or None


def _parse_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if value is None:
        return default
    return bool(value)


_SECURITY = _security_cfg()
_DEFAULT_ORIGINS = ["http://localhost:5173", "http://localhost:3000"]
_CORS_ORIGINS = _env_list("C2F_CORS_ORIGINS") or _cfg_list(_SECURITY.get("cors_origins"), _DEFAULT_ORIGINS)
_CORS_ORIGINS = [origin for origin in _CORS_ORIGINS if origin != "*"]
if not _CORS_ORIGINS:
    _CORS_ORIGINS = _DEFAULT_ORIGINS
_CORS_METHODS = _cfg_list(_SECURITY.get("cors_methods"), ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
_CORS_HEADERS = _cfg_list(
    _SECURITY.get("cors_headers"),
    ["Authorization", "Content-Type", "Accept", "Origin", "X-CSRF-Token"],
)
if "X-CSRF-Token" not in _CORS_HEADERS:
    _CORS_HEADERS.append("X-CSRF-Token")
_TRUSTED_HOSTS = _env_list("C2F_TRUSTED_HOSTS") or _cfg_list(
    _SECURITY.get("trusted_hosts"),
    ["localhost", "127.0.0.1", "*.localhost"],
)
_INCLUDE_HSTS = _parse_bool(_SECURITY.get("enable_hsts"), True)
_MAX_REQUEST_BYTES = int(_SECURITY.get("max_request_body_bytes", 10 * 1024 * 1024))
_UPLOAD_LIMIT_BYTES = int(_SECURITY.get("max_upload_body_bytes", 25 * 1024 * 1024))
_ENABLE_V1_SOAR = _parse_bool(os.getenv("C2F_ENABLE_V1_SOAR"), True)
## _CUTOVER_TEST_MODE = _parse_bool(os.getenv("C2F_CUTOVER_TEST_MODE"), False)
## _ENABLE_V2_SOAR = _parse_bool(os.getenv("C2F_ENABLE_V2_SOAR"), False)
_ENABLE_V2_SOAR = False
_ENABLE_V1_SOAR_DEPRECATION_HEADERS = _parse_bool(os.getenv("C2F_ENABLE_V1_SOAR_DEPRECATION_HEADERS"), True)
_V1_SOAR_SUNSET = str(
    os.getenv("C2F_V1_SOAR_SUNSET", "Wed, 30 Sep 2026 00:00:00 GMT")
).strip()

## if _CUTOVER_TEST_MODE:
##     # Cutover test mode intentionally disables v1 SOAR APIs and fallback signaling.
##     _ENABLE_V1_SOAR = False
##     _ENABLE_V1_SOAR_DEPRECATION_HEADERS = False
##     # In cutover simulations, force v2 route surface on.
##     _ENABLE_V2_SOAR = True

v2_router = None
## if _ENABLE_V2_SOAR:
##     try:
##         from api.v2 import router as v2_router  # type: ignore
##     except Exception as exc:
##         logger.warning("V2 router unavailable; disabling /api/v2 routes (%s)", exc)
##         _ENABLE_V2_SOAR = False

_RATE_RULES = [
    # Login has stricter per-user/IP lockout in api/auth.py.
    # Keep this global limiter permissive to avoid premature client lockouts.
    RateLimitRule(path_prefix="/api/auth/login", requests=120, window_seconds=60),
    RateLimitRule(path_prefix="/api/auth/oidc/callback", requests=20, window_seconds=300),
    RateLimitRule(path_prefix="/api/actions/global-shell", requests=20, window_seconds=60),
    RateLimitRule(path_prefix="/api/actions/run", requests=40, window_seconds=60),
    RateLimitRule(path_prefix="/api/remediate", requests=40, window_seconds=60),
    RateLimitRule(path_prefix="/api/approvals", requests=90, window_seconds=60),
]


@app.on_event("startup")
async def _register_ws_loop():
    # WS publish from threadpool workers must be scheduled on the app loop.
    running_loop = asyncio.get_running_loop()
    set_main_loop(running_loop)
    try:
        await init_redis(running_loop)
    except Exception as exc:
        logger.warning("Redis WS bus init failed: %s", exc)
    try:
        # Shared alert stream processor backs /ws/alerts with one poller.
        await ws.start_alert_stream_processor(running_loop)
    except Exception as exc:
        logger.exception("Alert stream startup failed: %s", exc)
    try:
        # Ensure schema/tables exist on fresh appliance installs.
        init_db()
    except Exception as exc:
        logger.exception("Database initialization failed: %s", exc)
        raise
    try:
        posture = assess_security_posture()
        record_posture_findings(posture)
    except Exception as exc:
        logger.exception("Security posture assessment failed: %s", exc)
    try:
        # Startup orphan-recovery is opt-in because long-running executions are user-controlled.
        enable_recovery = str(os.getenv("C2F_ENABLE_STARTUP_ORPHAN_RECOVERY", "false")).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        if enable_recovery:
            timeout_raw = os.getenv("C2F_STARTUP_ORPHAN_RECOVERY_TIMEOUT_SECONDS", "300")
            try:
                timeout_seconds = max(60, min(int(str(timeout_raw).strip()), 3600))
            except Exception:
                timeout_seconds = 300
            rec = reconcile_orphan_executions(timeout_seconds=timeout_seconds)
            issues = int(rec.get("total_issues_found") or 0)
            if issues > 0:
                logger.warning("Startup execution reconciliation: %s", rec)
            else:
                logger.info("Startup execution reconciliation: no stale executions")
        else:
            logger.info("Startup execution reconciliation: disabled (user-controlled execution lifetime)")
    except Exception as exc:
        logger.exception("Startup execution reconciliation failed: %s", exc)
    start_scheduler()


@app.on_event("shutdown")
async def _shutdown_background_services():
    try:
        await ws.stop_alert_stream_processor()
    except Exception as exc:
        logger.exception("Alert stream shutdown failed: %s", exc)
    try:
        await close_redis()
    except Exception as exc:
        logger.exception("Redis WS bus shutdown failed: %s", exc)
    stop_scheduler()


@app.middleware("http")
async def add_server_time_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Server-Time"] = utc_iso_now()
    response.headers["X-Timezone"] = "UTC"
    if _ENABLE_V1_SOAR and _ENABLE_V1_SOAR_DEPRECATION_HEADERS:
        path = str(getattr(request.url, "path", "") or "")
        if path.startswith("/api/approvals") or path.startswith("/api/executions") or path.startswith("/api/playbooks"):
            response.headers["Deprecation"] = "true"
            response.headers["Sunset"] = _V1_SOAR_SUNSET
            if _ENABLE_V2_SOAR:
                response.headers["Link"] = '</api/v2>; rel="successor-version"'
    return response


_REQUEST_SIZE_OVERRIDES = {
    "/api/cases/": _UPLOAD_LIMIT_BYTES,
    "/api/forensics/reports": _UPLOAD_LIMIT_BYTES,
}
## if _ENABLE_V2_SOAR:
##     _REQUEST_SIZE_OVERRIDES["/api/v2/cases/"] = _UPLOAD_LIMIT_BYTES

# Host header hardening.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=_TRUSTED_HOSTS)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=_CORS_METHODS,
    allow_headers=_CORS_HEADERS,
    expose_headers=["Content-Disposition", "X-Server-Time", "X-Timezone"],
)
app.add_middleware(
    RequestSizeLimitMiddleware,
    max_bytes=_MAX_REQUEST_BYTES,
    path_overrides=_REQUEST_SIZE_OVERRIDES,
)
app.add_middleware(InMemoryRateLimitMiddleware, rules=_RATE_RULES)
app.add_middleware(
    CSRFMiddleware,
    auth_cookie_name=COOKIE_NAME,
    csrf_cookie_name=CSRF_COOKIE_NAME,
    exempt_paths=[
        "/api/auth/login",
        "/api/auth/oidc",
    ],
)
## if _ENABLE_V2_SOAR and TenantScopeMiddleware is not None:
##     app.add_middleware(
##         TenantScopeMiddleware,
##         api_prefix="/api/v2",
##         exempt_prefixes=[
##             "/api/v2/auth",
##             "/api/v2/system",
##         ],
##     )
## elif _ENABLE_V2_SOAR:
##     logger.warning("TenantScopeMiddleware unavailable; skipping v2 tenant scope middleware registration")
app.add_middleware(SecurityHeadersMiddleware, include_hsts=_INCLUDE_HSTS)

# Register routers
app.include_router(actions.router, prefix="/api", tags=["Actions"])
app.include_router(auth.router, prefix="/api", tags=["Auth"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(audit.router, prefix="/api", tags=["Audit"])
app.include_router(cases.router, prefix="/api", tags=["Cases"])
app.include_router(changes.router, prefix="/api", tags=["Changes"])
app.include_router(dashboard.router, prefix="/api", tags=["Dashboard"])
app.include_router(remediation.router, prefix="/api/remediate", tags=["Remediation"])
app.include_router(scheduler.router, prefix="/api", tags=["Scheduler"])
app.include_router(system.router, prefix="/api", tags=["System"])
app.include_router(vulnerabilities.router, prefix="/api", tags=["Vulnerabilities"])
app.include_router(ioc.router, prefix="/api", tags=["IOC"])
app.include_router(analytics.router, prefix="/api", tags=["Analytics"])
app.include_router(incidents.router, prefix="/api", tags=["Incidents"])
app.include_router(governance.router, prefix="/api", tags=["Governance"])
app.include_router(integration.router, prefix="/api", tags=["Integration"])
app.include_router(forensics.router, prefix="/api", tags=["Forensics"])
app.include_router(orgs.router, prefix="/api", tags=["Orgs"])
if _ENABLE_V1_SOAR:
    app.include_router(approvals.router, prefix="/api", tags=["Approvals"])
    app.include_router(executions.router, prefix="/api", tags=["Executions"])
    app.include_router(playbooks.router, prefix="/api/playbooks", tags=["Playbooks"])
## if _ENABLE_V2_SOAR and v2_router is not None:
##     app.include_router(v2_router, prefix="/api/v2")
app.include_router(ops.router)
app.include_router(ws.router)
app.include_router(ws_exec.router)
