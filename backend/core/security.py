import hashlib
import json
import os
import secrets
import threading
import time
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from core.secrets import resolve_secret_env
from core.security_monitoring import record_security_event
from core.settings import SETTINGS


oauth = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_SECURITY_CFG = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
_DEFAULT_SECRET = _SECURITY_CFG.get("jwt_secret", "CHANGE_ME")
_RAW_SECRET = resolve_secret_env("JWT_SECRET", _DEFAULT_SECRET)
_ENFORCE_STRONG_JWT = str(
    os.getenv(
        "SECURITY_ENFORCE_STRONG_JWT",
        _SECURITY_CFG.get("enforce_strong_jwt", "true"),
    )
).strip().lower() in {"1", "true", "yes", "on"}

if not _RAW_SECRET or _RAW_SECRET in {"CHANGE_ME", "CHANGE_ME_TO_A_LONG_RANDOM_VALUE"}:
    if _ENFORCE_STRONG_JWT:
        raise RuntimeError(
            "JWT secret is insecure. Set JWT_SECRET to a long random value (>=32 chars)."
        )
    warnings.warn(
        "Insecure JWT secret detected. Using an ephemeral per-process secret; set JWT_SECRET for production.",
        RuntimeWarning,
        stacklevel=1,
    )
    SECRET = secrets.token_urlsafe(64)
elif len(_RAW_SECRET) < 32:
    if _ENFORCE_STRONG_JWT:
        raise RuntimeError("JWT_SECRET is too short. Use at least 32 random characters.")
    warnings.warn(
        "Short JWT_SECRET detected; token integrity is weaker than recommended.",
        RuntimeWarning,
        stacklevel=1,
    )
    SECRET = _RAW_SECRET
else:
    SECRET = _RAW_SECRET

ALGO = os.getenv("JWT_ALGO", _SECURITY_CFG.get("jwt_algorithm", "HS256"))
TOKEN_EXP_HOURS = max(1, min(24, int(os.getenv("TOKEN_EXP_HOURS", _SECURITY_CFG.get("token_exp_hours", 8)))))
TOKEN_ISSUER = str(os.getenv("JWT_ISSUER", _SECURITY_CFG.get("jwt_issuer", "click2fix-api")) or "").strip()
TOKEN_AUDIENCE = str(os.getenv("JWT_AUDIENCE", _SECURITY_CFG.get("jwt_audience", "click2fix-ui")) or "").strip()
COOKIE_NAME = str(_SECURITY_CFG.get("cookie_name", "c2f_token") or "c2f_token")
CSRF_COOKIE_NAME = str(_SECURITY_CFG.get("csrf_cookie_name", "c2f_csrf") or "c2f_csrf")

_revoked_lock = threading.Lock()
_revoked_token_fingerprints: dict[str, int] = {}
_last_revoked_store_cleanup_ts = 0
_REVOKED_STORE_PATH = Path(
    str(
        os.getenv(
            "C2F_REVOKED_TOKEN_STORE",
            (_SECURITY_CFG.get("revoked_token_store") if isinstance(_SECURITY_CFG, dict) else "") or "./data/revoked_tokens.json",
        )
    ).strip()
).expanduser()


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _token_decode_kwargs() -> dict:
    options = {
        "verify_aud": bool(TOKEN_AUDIENCE),
        "verify_iss": bool(TOKEN_ISSUER),
    }
    kwargs = {"options": options}
    if TOKEN_AUDIENCE:
        kwargs["audience"] = TOKEN_AUDIENCE
    if TOKEN_ISSUER:
        kwargs["issuer"] = TOKEN_ISSUER
    return kwargs


def _cleanup_revoked(now_ts: int | None = None) -> None:
    ts = int(now_ts or time.time())
    stale = [fp for fp, exp_ts in _revoked_token_fingerprints.items() if exp_ts <= ts]
    for fp in stale:
        _revoked_token_fingerprints.pop(fp, None)


def _revoked_store_read() -> dict[str, dict]:
    path = _REVOKED_STORE_PATH
    try:
        if not path.exists():
            return {}
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _revoked_store_write(payload: dict[str, dict]) -> None:
    path = _REVOKED_STORE_PATH
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True), encoding="utf-8")
        tmp_path.replace(path)
    except Exception:
        pass


def _cleanup_revoked_store(now_ts: int | None = None) -> None:
    global _last_revoked_store_cleanup_ts
    ts = int(now_ts or time.time())
    if ts - int(_last_revoked_store_cleanup_ts or 0) < 600:
        return
    _last_revoked_store_cleanup_ts = ts
    with _revoked_lock:
        payload = _revoked_store_read()
        if not payload:
            return
        trimmed = {
            fp: row
            for fp, row in payload.items()
            if int(((row or {}).get("exp") or 0)) > ts
        }
        if trimmed != payload:
            _revoked_store_write(trimmed)


def _persist_revoked_token(token: str, *, payload: dict | None = None) -> None:
    raw_token = str(token or "").strip()
    if not raw_token:
        return
    claims = payload or {}
    try:
        exp = int(claims.get("exp") or 0)
    except Exception:
        exp = 0
    if exp <= 0:
        return
    fingerprint = _token_fingerprint(raw_token)
    with _revoked_lock:
        payload_data = _revoked_store_read()
        payload_data[fingerprint] = {
            "exp": exp,
            "username": str(claims.get("sub") or "").strip() or "",
            "token_jti": str(claims.get("jti") or "").strip() or "",
            "revoked_at": int(time.time()),
        }
        _revoked_store_write(payload_data)


def _is_token_revoked_in_store(token: str) -> bool:
    raw_token = str(token or "").strip()
    if not raw_token:
        return False
    fingerprint = _token_fingerprint(raw_token)
    payload = _revoked_store_read()
    row = payload.get(fingerprint) if isinstance(payload, dict) else None
    if not isinstance(row, dict):
        return False
    try:
        exp_ts = int(row.get("exp") or 0)
    except Exception:
        exp_ts = 0
    now_ts = int(time.time())
    if exp_ts > now_ts:
        with _revoked_lock:
            _revoked_token_fingerprints[fingerprint] = exp_ts
        return True
    return False


def is_token_revoked(token: str) -> bool:
    with _revoked_lock:
        _cleanup_revoked()
        fp = _token_fingerprint(token)
        if fp in _revoked_token_fingerprints:
            return True
    _cleanup_revoked_store()
    return _is_token_revoked_in_store(token)


def revoke_token(token: str) -> None:
    if not token or token in {"null", "undefined"}:
        return
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO], **_token_decode_kwargs())
        exp = int(payload.get("exp") or 0)
        if exp <= 0:
            return
        fp = _token_fingerprint(token)
        with _revoked_lock:
            _cleanup_revoked()
            _revoked_token_fingerprints[fp] = exp
        _persist_revoked_token(token, payload=payload)
        _cleanup_revoked_store()
    except JWTError:
        return


def issue_token(
    *,
    username: str,
    role: str,
    org_id: int | None,
    csrf_token: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "org_id": org_id,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(hours=TOKEN_EXP_HOURS),
        "jti": str(uuid.uuid4()),
    }
    if TOKEN_ISSUER:
        payload["iss"] = TOKEN_ISSUER
    if TOKEN_AUDIENCE:
        payload["aud"] = TOKEN_AUDIENCE
    if csrf_token:
        payload["csrf"] = csrf_token
    return jwt.encode(payload, SECRET, algorithm=ALGO)


def decode_token(token: str, *, check_revocation: bool = True):
    if not token or token in {"null", "undefined"}:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(token, SECRET, algorithms=[ALGO], **_token_decode_kwargs())
        if check_revocation and is_token_revoked(token):
            raise JWTError("Token has been revoked")
        return payload
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def _extract_auth_candidates(request: Request, bearer_token: str | None) -> list[str]:
    candidates: list[str] = []
    if bearer_token and bearer_token not in {"null", "undefined"}:
        candidates.append(bearer_token)
    if request:
        cookie_token = request.cookies.get(COOKIE_NAME)
        if cookie_token and cookie_token not in {"null", "undefined"} and cookie_token not in candidates:
            candidates.append(cookie_token)
    return candidates


def extract_request_token(request: Request, bearer_token: str | None = None) -> str:
    candidates = _extract_auth_candidates(request, bearer_token)
    if not candidates:
        return ""
    return candidates[0]


def current_user(request: Request, token: str | None = Depends(oauth)):
    candidates = _extract_auth_candidates(request, token)
    if not candidates:
        record_security_event(
            "auth.missing_token",
            severity="warning",
            request=request,
            detail="Request did not include bearer token or auth cookie",
        )
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    for candidate in candidates:
        try:
            return decode_token(candidate, check_revocation=True)
        except HTTPException:
            continue
    record_security_event(
        "auth.invalid_token",
        severity="warning",
        request=request,
        detail="All presented authentication tokens were rejected",
    )
    raise HTTPException(
        status_code=401,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def org_scope(user):
    return user["org_id"]


ROLE_LEVELS = {
    "analyst": 1,
    "admin": 2,
    "superadmin": 3,
}


def require_role(role):
    def checker(request: Request, user=Depends(current_user)):
        required_level = ROLE_LEVELS.get(role, 0)
        user_level = ROLE_LEVELS.get(user.get("role"), 0)
        if user_level < required_level:
            record_security_event(
                "auth.role_denied",
                severity="warning",
                request=request,
                user=user,
                detail=f"Role '{user.get('role') or 'unknown'}' cannot satisfy required role '{role}'",
                metadata={"required_role": role, "actual_role": user.get("role")},
            )
            raise HTTPException(403)
        return user

    return checker
