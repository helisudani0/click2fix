from __future__ import annotations

import sys
from pathlib import Path

from starlette.requests import Request


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import auth  # noqa: E402


def _make_request(*, method: str, path: str, scheme: str = "http", headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": headers or [],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
        "root_path": "",
    }
    return Request(scope, receive)


def test_session_reset_clears_auth_cookie_variants():
    response = auth.reset_session(
        _make_request(method="GET", path="/api/auth/session/reset")
    )
    cookies = response.headers.getlist("set-cookie")
    assert cookies

    def has_delete_header(name: str, path: str) -> bool:
        name_prefix = f"{name}="
        path_marker = f"Path={path}"
        expires_marker = "Max-Age=0"
        return any(
            header.startswith(name_prefix)
            and path_marker in header
            and expires_marker in header
            for header in cookies
        )

    assert has_delete_header("c2f_token", "/")
    assert has_delete_header("c2f_token", "/api")
    assert has_delete_header("c2f_csrf", "/")
    assert has_delete_header("c2f_csrf", "/api")


def test_cookie_secure_defaults_false_for_http():
    cfg = auth._cookie_config(_make_request(method="POST", path="/api/auth/token", scheme="http"))
    assert cfg["secure"] is False


def test_cookie_secure_defaults_true_for_https_via_proxy_header():
    request = _make_request(
        method="POST",
        path="/api/auth/token",
        scheme="http",
        headers=[(b"x-forwarded-proto", b"https")],
    )
    cfg = auth._cookie_config(request)
    assert cfg["secure"] is True


def test_cookie_secure_override_string_true():
    security_cfg = auth.SETTINGS.setdefault("security", {})
    original = security_cfg.get("cookie_secure")
    try:
        security_cfg["cookie_secure"] = "true"
        cfg = auth._cookie_config(_make_request(method="POST", path="/api/auth/token", scheme="http"))
        assert cfg["secure"] is True
    finally:
        security_cfg["cookie_secure"] = original


def test_cookie_secure_override_string_false():
    security_cfg = auth.SETTINGS.setdefault("security", {})
    original = security_cfg.get("cookie_secure")
    try:
        security_cfg["cookie_secure"] = "false"
        cfg = auth._cookie_config(_make_request(method="POST", path="/api/auth/token", scheme="https"))
        assert cfg["secure"] is False
    finally:
        security_cfg["cookie_secure"] = original
