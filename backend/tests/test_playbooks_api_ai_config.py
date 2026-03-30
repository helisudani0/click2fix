from __future__ import annotations

import asyncio
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api import playbooks as playbooks_api  # noqa: E402


class _RequestStub:
    def __init__(self, payload):
        self._payload = payload

    async def json(self):
        return self._payload


def test_generate_route_uses_tenant_ai_config_when_request_has_no_ai_config(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        playbooks_api,
        "load_active_tenant_ai_config",
        lambda org_id: {"provider": "openai", "api_key": "tenant-key", "enabled": True, "model": "gpt-4.1-mini"},
    )

    def _fake_generate_playbook(**kwargs):
        captured.update(kwargs)
        return {
            "name": "Generated",
            "description": "ok",
            "source": {"generation_mode": "ai_prompt"},
            "steps": [],
        }

    monkeypatch.setattr(playbooks_api, "generate_playbook", _fake_generate_playbook)

    response = asyncio.run(
        playbooks_api.generate(
            _RequestStub({"use_ai": True, "ai_prompt": "test prompt"}),
            user={"org_id": 7, "sub": "admin"},
        )
    )

    assert response["name"] == "Generated"
    assert captured["use_ai"] is True
    assert captured["ai_prompt"] == "test prompt"
    assert captured["ai_config"]["api_key"] == "tenant-key"


def test_generate_route_prefers_explicit_request_ai_config_over_tenant(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        playbooks_api,
        "load_active_tenant_ai_config",
        lambda org_id: {"provider": "openai", "api_key": "tenant-key", "enabled": True, "model": "gpt-4.1-mini"},
    )

    def _fake_generate_playbook(**kwargs):
        captured.update(kwargs)
        return {
            "name": "Generated",
            "description": "ok",
            "source": {"generation_mode": "ai_prompt"},
            "steps": [],
        }

    monkeypatch.setattr(playbooks_api, "generate_playbook", _fake_generate_playbook)

    response = asyncio.run(
        playbooks_api.generate(
            _RequestStub(
                {
                    "use_ai": True,
                    "ai_prompt": "test prompt",
                    "ai_config": {
                        "provider": "gemini",
                        "api_key": "request-key",
                        "enabled": True,
                        "model": "gemini-2.5-flash",
                    },
                }
            ),
            user={"org_id": 7, "sub": "admin"},
        )
    )

    assert response["name"] == "Generated"
    assert captured["ai_config"]["provider"] == "gemini"
    assert captured["ai_config"]["api_key"] == "request-key"
