from __future__ import annotations

import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "origin-policy-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from api import ws, ws_exec  # noqa: E402
from core import origin_policy  # noqa: E402


def test_configured_cors_origins_prefers_env_and_normalizes(monkeypatch):
    monkeypatch.setenv(
        "C2F_CORS_ORIGINS",
        "http://192.168.1.237:5173/, http://localhost:5173/login",
    )
    monkeypatch.setattr(
        origin_policy,
        "SETTINGS",
        {"security": {"cors_origins": ["http://localhost:3000"]}},
    )

    assert origin_policy.configured_cors_origins() == [
        "http://192.168.1.237:5173",
        "http://localhost:5173",
    ]


def test_websocket_allowed_origins_follow_env(monkeypatch):
    monkeypatch.setenv(
        "C2F_CORS_ORIGINS",
        "http://192.168.1.237:5173, http://localhost:5173",
    )

    assert ws._allowed_origins() == {
        "http://192.168.1.237:5173",
        "http://localhost:5173",
    }
    assert ws_exec._allowed_origins() == {
        "http://192.168.1.237:5173",
        "http://localhost:5173",
    }


def test_origin_matches_request_hosts_supports_forwarded_proxy_chain():
    headers = {
        "origin": "http://10.22.33.44:5173",
        "host": "backend:8000",
        "x-forwarded-host": "10.22.33.44:5173, c2f-lb:8000",
    }

    assert origin_policy.origin_matches_request_hosts("http://10.22.33.44:5173", headers) is True


def test_websocket_origin_validation_allows_forwarded_host_match(monkeypatch):
    monkeypatch.setenv("C2F_CORS_ORIGINS", "http://localhost:5173")
    headers = {
        "origin": "http://10.22.33.44:5173",
        "host": "backend:8000",
        "x-forwarded-host": "10.22.33.44:5173",
    }
    fake_ws = type("FakeWs", (), {"headers": headers})()

    ws._validate_ws_origin(fake_ws)
    ws_exec._validate_ws_origin(fake_ws)
