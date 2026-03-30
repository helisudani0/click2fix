from __future__ import annotations

import sys
from pathlib import Path

from starlette.requests import Request


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import auth  # noqa: E402


def _make_request(*, method: str, path: str) -> Request:
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
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
