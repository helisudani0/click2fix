import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def client_ip(request: Request) -> str:
    forwarded_for = (request.headers.get("x-forwarded-for") or "").strip()
    if forwarded_for:
        first = forwarded_for.split(",")[0].strip()
        if first:
            return first
    real_ip = (request.headers.get("x-real-ip") or "").strip()
    if real_ip:
        return real_ip
    if request.client and request.client.host:
        return str(request.client.host)
    return "unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, include_hsts: bool = True):
        super().__init__(app)
        self.include_hsts = include_hsts

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=()",
        )
        response.headers.setdefault("X-XSS-Protection", "0")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if self.include_hsts:
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains; preload",
            )

        if request.url.path.startswith("/api/auth"):
            response.headers.setdefault("Cache-Control", "no-store")
            response.headers.setdefault("Pragma", "no-cache")

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        max_bytes: int = 10 * 1024 * 1024,
        path_overrides: dict[str, int] | None = None,
    ):
        super().__init__(app)
        self.max_bytes = max(1, int(max_bytes))
        self.path_overrides = path_overrides or {}

    def _path_limit(self, path: str) -> int:
        for prefix, limit in self.path_overrides.items():
            if path.startswith(prefix):
                return max(1, int(limit))
        return self.max_bytes

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
            limit = self._path_limit(request.url.path)
            if size > limit:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Request body too large (limit {limit} bytes)"},
                )
        return await call_next(request)


@dataclass(frozen=True)
class RateLimitRule:
    path_prefix: str
    requests: int
    window_seconds: int


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, rules: list[RateLimitRule] | None = None):
        super().__init__(app)
        self.rules = [rule for rule in (rules or []) if rule.requests > 0 and rule.window_seconds > 0]
        self._bucket = defaultdict(deque)
        self._lock = threading.Lock()

    def _match_rule(self, path: str) -> RateLimitRule | None:
        for rule in self.rules:
            if path.startswith(rule.path_prefix):
                return rule
        return None

    async def dispatch(self, request: Request, call_next):
        rule = self._match_rule(request.url.path)
        if not rule:
            return await call_next(request)

        key = f"{rule.path_prefix}:{client_ip(request)}"
        now = time.time()
        with self._lock:
            attempts = self._bucket[key]
            cutoff = now - rule.window_seconds
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if len(attempts) >= rule.requests:
                retry_after = max(1, int(rule.window_seconds - (now - attempts[0])))
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded"},
                    headers={"Retry-After": str(retry_after)},
                )
            attempts.append(now)
        return await call_next(request)


class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        *,
        auth_cookie_name: str,
        csrf_cookie_name: str,
        exempt_paths: list[str] | None = None,
    ):
        super().__init__(app)
        self.auth_cookie_name = auth_cookie_name
        self.csrf_cookie_name = csrf_cookie_name
        self.exempt_paths = exempt_paths or []
        self.unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}

    def _is_exempt(self, path: str) -> bool:
        return any(path.startswith(prefix) for prefix in self.exempt_paths)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path or ""
        if request.method.upper() not in self.unsafe_methods:
            return await call_next(request)
        if not path.startswith("/api"):
            return await call_next(request)
        if self._is_exempt(path):
            return await call_next(request)

        auth_cookie = request.cookies.get(self.auth_cookie_name) or ""
        if not auth_cookie:
            return await call_next(request)

        csrf_cookie = request.cookies.get(self.csrf_cookie_name) or ""
        csrf_header = request.headers.get("x-csrf-token") or ""
        if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
            return JSONResponse(status_code=403, content={"detail": "CSRF validation failed"})
        return await call_next(request)
