from __future__ import annotations

from core import tenant_ai_config


class _Row:
    def __init__(self, config_json):
        self._mapping = {"config_json": config_json}


class _Result:
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class _Db:
    def __init__(self, *, row=None, raise_on_execute: bool = False):
        self._row = row
        self._raise_on_execute = raise_on_execute
        self.closed = False

    def execute(self, *_args, **_kwargs):
        if self._raise_on_execute:
            raise RuntimeError("relation does not exist")
        return _Result(row=self._row)

    def close(self):
        self.closed = True


def test_load_active_tenant_ai_config_falls_back_when_store_unavailable(monkeypatch):
    ensure_calls = {"count": 0}

    def _fake_connect():
        return _Db(raise_on_execute=True)

    def _fake_ensure():
        ensure_calls["count"] += 1

    monkeypatch.setattr(tenant_ai_config, "connect", _fake_connect)
    monkeypatch.setattr(tenant_ai_config, "_ensure_tenant_config_store_best_effort", _fake_ensure)

    assert tenant_ai_config.load_active_tenant_ai_config(1) == {}
    assert ensure_calls["count"] == 1


def test_load_active_tenant_ai_config_parses_active_row(monkeypatch):
    row = _Row(
        '{"ai_remediation":{"provider":"openai","model":"gpt-5-mini","api_key":"sk-test","enabled":true,"timeout_seconds":30}}'
    )

    monkeypatch.setattr(tenant_ai_config, "connect", lambda: _Db(row=row))

    parsed = tenant_ai_config.load_active_tenant_ai_config(1)
    assert parsed.get("provider") == "openai"
    assert parsed.get("model") == "gpt-5-mini"
    assert parsed.get("enabled") is True
    assert parsed.get("timeout_seconds") == 30


def test_load_active_tenant_ai_config_ignores_invalid_json(monkeypatch):
    monkeypatch.setattr(tenant_ai_config, "connect", lambda: _Db(row=_Row("{invalid-json}")))
    assert tenant_ai_config.load_active_tenant_ai_config(1) == {}
