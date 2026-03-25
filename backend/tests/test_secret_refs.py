from __future__ import annotations

import json
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.secrets import resolve_secret_env, resolve_secret_value, resolve_settings_tree, vault_provider_status  # noqa: E402


def test_secret_ref_reads_env_value(monkeypatch):
    monkeypatch.setenv("UNIT_SECRET_ENV", "expected-secret")
    assert resolve_secret_value("env://UNIT_SECRET_ENV") == "expected-secret"
    assert resolve_secret_env("UNIT_SECRET_ENV") == "expected-secret"


def test_secret_ref_reads_file_value(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-secret\n", encoding="utf-8")
    assert resolve_secret_value(f"file://{secret_file}") == "file-secret"


def test_secret_ref_reads_vault_value(monkeypatch):
    monkeypatch.setenv("C2F_VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("C2F_VAULT_TOKEN", "vault-token")

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            payload = {"data": {"data": {"password": "vault-secret"}}}
            return json.dumps(payload).encode("utf-8")

    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: _FakeResponse())
    assert resolve_secret_value("vault://secret/data/click2fix/backend#password") == "vault-secret"


def test_resolve_settings_tree_converts_secret_specs(monkeypatch, tmp_path):
    secret_file = tmp_path / "nested-secret.txt"
    secret_file.write_text("nested-secret", encoding="utf-8")
    monkeypatch.setenv("JWT_SECRET", "env-jwt-secret")
    config = {
        "security": {
            "jwt_secret": {"from_env": "JWT_SECRET", "default": "fallback"},
            "client_secret": f"file://{secret_file}",
        }
    }
    resolved = resolve_settings_tree(config)
    assert resolved["security"]["jwt_secret"] == "env-jwt-secret"
    assert resolved["security"]["client_secret"] == "nested-secret"


def test_vault_provider_status_reports_configuration(monkeypatch):
    monkeypatch.setenv("C2F_VAULT_ADDR", "https://vault.example")
    monkeypatch.setenv("C2F_VAULT_TOKEN", "vault-token")
    status = vault_provider_status()
    assert status["configured"] is True
    assert status["token_configured"] is True
