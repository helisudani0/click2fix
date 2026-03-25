from __future__ import annotations

import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "security-store-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from core import security as security_core  # noqa: E402


def test_revoked_token_store_survives_memory_reset(tmp_path, monkeypatch):
    store_path = tmp_path / "revoked_tokens.json"
    monkeypatch.setattr(security_core, "_REVOKED_STORE_PATH", store_path)
    security_core._revoked_token_fingerprints.clear()  # noqa: SLF001
    monkeypatch.setattr(security_core, "_last_revoked_store_cleanup_ts", 0)

    token = security_core.issue_token(username="alice", role="admin", org_id=1)
    security_core.revoke_token(token)

    assert security_core.is_token_revoked(token) is True

    security_core._revoked_token_fingerprints.clear()  # noqa: SLF001
    assert security_core.is_token_revoked(token) is True


def test_require_recent_auth_allows_fresh_login():
    user = {"sub": "alice", "role": "admin", "iat": security_core.time.time()}

    age = security_core.require_recent_auth(
        user,
        None,
        max_age_seconds=3600,
        action_label="test action",
    )

    assert isinstance(age, int)
    assert age >= 0


def test_require_recent_auth_rejects_stale_login():
    user = {
        "sub": "alice",
        "role": "admin",
        "iat": security_core.time.time() - 7200,
    }

    try:
        security_core.require_recent_auth(
            user,
            None,
            max_age_seconds=900,
            action_label="test action",
        )
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
        assert "Recent login required" in str(getattr(exc, "detail", exc))
    else:
        raise AssertionError("Expected require_recent_auth to reject stale login")
