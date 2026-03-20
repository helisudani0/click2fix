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
