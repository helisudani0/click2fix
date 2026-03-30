import secrets
import time
import os

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from db.database import connect
from sqlalchemy import text
from core.audit import log_audit
from core.ldap_auth import authenticate as ldap_auth
from core.oidc import build_auth_url, enabled as oidc_enabled, exchange_code, fetch_userinfo
from core.security import (
    COOKIE_NAME,
    CSRF_COOKIE_NAME,
    TOKEN_EXP_HOURS,
    current_user,
    extract_request_token,
    issue_token,
    revoke_token,
)
from core.settings import SETTINGS

router = APIRouter(prefix="/auth")

pwd = CryptContext(schemes=["bcrypt"])
OIDC_STATE_CACHE = {}
FAILED_AUTH_ATTEMPTS = {}


def _auth_config():
    return SETTINGS.get("auth", {}) if isinstance(SETTINGS, dict) else {}


def _oidc_config():
    return _auth_config().get("oidc", {}) if isinstance(_auth_config(), dict) else {}


def _rate_limit_config():
    cfg = _auth_config().get("login_rate_limit", {})
    if not isinstance(cfg, dict):
        cfg = {}
    security_cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    security_limit = security_cfg.get("login_rate_limit", {}) if isinstance(security_cfg, dict) else {}
    return {
        "max_attempts": int(cfg.get("max_attempts", security_limit.get("max_attempts", 8))),
        "window_seconds": int(cfg.get("window_seconds", security_limit.get("window_seconds", 300))),
        "block_seconds": int(cfg.get("block_seconds", security_limit.get("block_seconds", 900))),
    }


def _include_access_token_in_body() -> bool:
    security_cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    raw = security_cfg.get("return_access_token_in_body", False)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return bool(raw)


def _cookie_config(request: Request):
    security_cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    secure_from_cfg = security_cfg.get("cookie_secure")
    host = (request.url.hostname or "").strip().lower() if request and request.url else ""
    is_local = host in {"localhost", "127.0.0.1", "::1"}
    if secure_from_cfg is None:
        secure = not is_local
    else:
        secure = bool(secure_from_cfg)
    return {
        "name": security_cfg.get("cookie_name", COOKIE_NAME),
        "csrf_name": security_cfg.get("csrf_cookie_name", CSRF_COOKIE_NAME),
        "max_age": int(TOKEN_EXP_HOURS * 3600),
        "secure": secure,
        "httponly": bool(security_cfg.get("cookie_httponly", True)),
        "samesite": security_cfg.get("cookie_samesite", "strict"),
        "path": security_cfg.get("cookie_path", "/"),
    }


def _set_auth_cookie(response: Response, request: Request, token: str, csrf_token: str | None = None):
    cfg = _cookie_config(request)
    response.set_cookie(
        key=cfg["name"],
        value=token,
        max_age=cfg["max_age"],
        secure=cfg["secure"],
        httponly=cfg["httponly"],
        samesite=cfg["samesite"],
        path=cfg["path"],
    )
    if csrf_token:
        response.set_cookie(
            key=cfg["csrf_name"],
            value=csrf_token,
            max_age=cfg["max_age"],
            secure=cfg["secure"],
            httponly=False,
            samesite=cfg["samesite"],
            path=cfg["path"],
        )


def _normalize_cookie_path(path_value: str | None) -> str:
    path = str(path_value or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _clear_cookie_for_common_paths(response: Response, key: str, paths: list[str]) -> None:
    for path in paths:
        response.delete_cookie(key=key, path=path)
        response.delete_cookie(key=key, path=path, samesite="lax")
        response.delete_cookie(key=key, path=path, samesite="strict")
        response.delete_cookie(key=key, path=path, samesite="none")


def _clear_auth_cookie(response: Response, request: Request):
    cfg = _cookie_config(request)
    candidate_paths = [
        _normalize_cookie_path(cfg.get("path")),
        "/",
        "/api",
        "/auth",
    ]
    cookie_paths: list[str] = []
    for path in candidate_paths:
        if path not in cookie_paths:
            cookie_paths.append(path)
    _clear_cookie_for_common_paths(response, str(cfg["name"]), cookie_paths)
    _clear_cookie_for_common_paths(response, str(cfg["csrf_name"]), cookie_paths)


def _client_ip(request: Request) -> str:
    if request and request.client and request.client.host:
        return request.client.host
    return "unknown"


def _rate_limit_key(username: str, ip: str) -> str:
    return f"{ip}:{(username or '').strip().lower()}"


def _check_rate_limit(key: str):
    now = time.time()
    cfg = _rate_limit_config()
    record = FAILED_AUTH_ATTEMPTS.get(key)
    if not record:
        return
    blocked_until = record.get("blocked_until", 0)
    if blocked_until > now:
        wait_seconds = int(blocked_until - now)
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Retry in {wait_seconds}s.",
        )
    attempts = [ts for ts in record.get("attempts", []) if (now - ts) <= cfg["window_seconds"]]
    if attempts:
        record["attempts"] = attempts
        FAILED_AUTH_ATTEMPTS[key] = record
    else:
        FAILED_AUTH_ATTEMPTS.pop(key, None)


def _register_failed_attempt(key: str):
    now = time.time()
    cfg = _rate_limit_config()
    record = FAILED_AUTH_ATTEMPTS.get(key, {"attempts": [], "blocked_until": 0})
    attempts = [ts for ts in record.get("attempts", []) if (now - ts) <= cfg["window_seconds"]]
    attempts.append(now)
    blocked_until = record.get("blocked_until", 0)
    if len(attempts) >= cfg["max_attempts"]:
        blocked_until = now + cfg["block_seconds"]
    FAILED_AUTH_ATTEMPTS[key] = {"attempts": attempts, "blocked_until": blocked_until}


def _clear_failed_attempts(key: str):
    FAILED_AUTH_ATTEMPTS.pop(key, None)


def ensure_user(username: str, role: str, org_id: int | None):
    db = connect()
    try:
        exists = db.execute(
            text("SELECT 1 FROM users WHERE username=:username"),
            {"username": username},
        ).scalar()
        if not exists:
            db.execute(
                text(
                    """
                    INSERT INTO users (username, password, role, org_id)
                    VALUES (:username, :password, :role, :org_id)
                    """
                ),
                {
                    "username": username,
                    "password": pwd.hash(secrets.token_urlsafe(16)),
                    "role": role,
                    "org_id": org_id,
                },
            )
            db.commit()
    finally:
        db.close()


def _bootstrap_admin_on_first_login(username: str, password: str) -> bool:
    configured_username = str(os.getenv("C2F_BOOTSTRAP_ADMIN_USERNAME") or "").strip()
    configured_password = str(os.getenv("C2F_BOOTSTRAP_ADMIN_PASSWORD") or "")
    configured_role = str(os.getenv("C2F_BOOTSTRAP_ADMIN_ROLE") or "admin").strip().lower() or "admin"
    if configured_role not in {"analyst", "admin", "superadmin"}:
        configured_role = "admin"

    if not configured_username or len(configured_password) < 8:
        return False
    if username != configured_username or password != configured_password:
        return False

    db = connect()
    try:
        existing = db.execute(
            text("SELECT 1 FROM users WHERE username=:username"),
            {"username": configured_username},
        ).scalar()
        if existing:
            return True

        user_count = int(
            db.execute(text("SELECT COUNT(1) FROM users")).scalar() or 0
        )
        if user_count > 0:
            # Do not create surprise users on non-empty deployments.
            return False

        org_id = db.execute(text("SELECT id FROM orgs ORDER BY id LIMIT 1")).scalar()
        if not org_id:
            db.execute(text("INSERT INTO orgs (name) VALUES (:name)"), {"name": "Default Org"})
            org_id = db.execute(text("SELECT id FROM orgs ORDER BY id LIMIT 1")).scalar()

        db.execute(
            text(
                """
                INSERT INTO users (username, password, role, org_id)
                VALUES (:username, :password, :role, :org_id)
                """
            ),
            {
                "username": configured_username,
                "password": pwd.hash(configured_password),
                "role": configured_role,
                "org_id": org_id,
            },
        )
        db.commit()
        return True
    finally:
        db.close()

@router.post("/login")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    key = _rate_limit_key(username, _client_ip(request))
    _check_rate_limit(key)
    db = connect()
    try:
        user = db.execute(
            text("SELECT username,password,role,org_id FROM users WHERE username=:username"),
            {"username": username},
        ).fetchone()
    finally:
        db.close()

    if not user and _bootstrap_admin_on_first_login(username, password):
        db = connect()
        try:
            user = db.execute(
                text("SELECT username,password,role,org_id FROM users WHERE username=:username"),
                {"username": username},
            ).fetchone()
        finally:
            db.close()

    if not user or not pwd.verify(password, user[1]):
        ldap_user = ldap_auth(username, password)
        if not ldap_user:
            _register_failed_attempt(key)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        default_role = _auth_config().get("ldap", {}).get("default_role", "analyst")
        ensure_user(username, default_role, None)
        user = (username, None, default_role, None)

    csrf_token = secrets.token_urlsafe(24)
    token = issue_token(
        username=user[0],
        role=user[2],
        org_id=user[3],
        csrf_token=csrf_token,
    )
    _clear_failed_attempts(key)
    log_audit(
        "login_success",
        actor=user[0],
        entity_type="auth",
        entity_id=user[0],
        detail="password_login",
        org_id=user[3],
        ip_address=request.client.host if request and request.client else None,
    )
    payload = {
        "user": {"username": user[0], "role": user[2], "org_id": user[3]},
        "session": {"mode": "cookie", "expires_in_seconds": int(TOKEN_EXP_HOURS * 3600)},
    }
    if _include_access_token_in_body():
        payload["access_token"] = token
        payload["token_type"] = "bearer"
    response = JSONResponse(payload)
    # Always clear stale auth/csrf cookie variants before setting a fresh session.
    _clear_auth_cookie(response, request)
    _set_auth_cookie(response, request, token, csrf_token=csrf_token)
    return response


@router.post("/logout")
def logout(request: Request):
    token = extract_request_token(request)
    if token:
        revoke_token(token)
    response = JSONResponse({"status": "ok"})
    _clear_auth_cookie(response, request)
    return response


@router.get("/session/reset")
def reset_session(request: Request):
    response = JSONResponse({"status": "ok", "cleared": True})
    _clear_auth_cookie(response, request)
    return response


@router.get("/me")
def me(user=Depends(current_user)):
    return {
        "username": user.get("sub"),
        "role": user.get("role"),
        "org_id": user.get("org_id"),
    }


@router.get("/oidc/login")
def oidc_login():
    if not oidc_enabled():
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    OIDC_STATE_CACHE[state] = time.time() + 300
    auth_url = build_auth_url(state, nonce)
    return {"auth_url": auth_url, "state": state}


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str, state: str):
    if not oidc_enabled():
        raise HTTPException(status_code=404, detail="OIDC not enabled")

    now = time.time()
    stale_states = [k for k, expiry in OIDC_STATE_CACHE.items() if expiry <= now]
    for key in stale_states:
        OIDC_STATE_CACHE.pop(key, None)

    expires = OIDC_STATE_CACHE.get(state)
    if not expires or time.time() > expires:
        raise HTTPException(status_code=400, detail="Invalid state")
    OIDC_STATE_CACHE.pop(state, None)

    token_data = exchange_code(code)
    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="OIDC token exchange failed")

    userinfo = fetch_userinfo(access_token)
    cfg = _oidc_config()
    username_claim = cfg.get("username_claim", "preferred_username")
    username = userinfo.get(username_claim) or userinfo.get("email") or userinfo.get("sub")
    if not username:
        raise HTTPException(status_code=400, detail="OIDC user identity not found")

    default_role = cfg.get("default_role", "analyst")
    ensure_user(username, default_role, None)

    csrf_token = secrets.token_urlsafe(24)
    token = issue_token(
        username=username,
        role=default_role,
        org_id=None,
        csrf_token=csrf_token,
    )
    frontend_redirect = cfg.get("frontend_redirect")
    log_audit(
        "login_success",
        actor=username,
        entity_type="auth",
        entity_id=username,
        detail="oidc_login",
        org_id=None,
        ip_address=None,
    )
    if frontend_redirect:
        response = RedirectResponse(frontend_redirect)
        _clear_auth_cookie(response, request)
        _set_auth_cookie(response, request, token, csrf_token=csrf_token)
        return response
    payload = {
        "status": "ok",
        "session": {"mode": "cookie", "expires_in_seconds": int(TOKEN_EXP_HOURS * 3600)},
    }
    if _include_access_token_in_body():
        payload["access_token"] = token
        payload["token_type"] = "bearer"
    response = JSONResponse(payload)
    _clear_auth_cookie(response, request)
    _set_auth_cookie(response, request, token, csrf_token=csrf_token)
    return response
