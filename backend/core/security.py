import hashlib
import os
import secrets
import threading
import time
import uuid
import warnings
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from core.settings import SETTINGS


oauth = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

_SECURITY_CFG = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
_DEFAULT_SECRET = _SECURITY_CFG.get("jwt_secret", "CHANGE_ME")
_RAW_SECRET = os.getenv("JWT_SECRET", _DEFAULT_SECRET)
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


def is_token_revoked(token: str) -> bool:
    with _revoked_lock:
        _cleanup_revoked()
        fp = _token_fingerprint(token)
        return fp in _revoked_token_fingerprints


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
    def checker(user=Depends(current_user)):
        required_level = ROLE_LEVELS.get(role, 0)
        user_level = ROLE_LEVELS.get(user.get("role"), 0)
        if user_level < required_level:
            raise HTTPException(403)
        return user

    return checker
