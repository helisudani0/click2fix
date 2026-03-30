from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.actions import _coerce_ai_provider_config  # noqa: E402
import core.ai_providers as ai_providers  # noqa: E402
from core.ai_providers import AIAdapter, AIProviderError, GeminiProvider, ProviderFactory  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, *, text: str = "", headers: dict | None = None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


def test_ai_adapter_uses_provider_defaults_when_base_url_and_model_are_blank():
    gemini = AIAdapter(config={"provider": "gemini", "api_key": "test-key", "base_url": "", "model": ""})

    assert gemini.config["provider"] == "gemini"
    assert gemini.config["base_url"] == "https://generativelanguage.googleapis.com/v1beta"
    assert gemini.config["model"] == "gemini-2.5-flash"
    assert gemini.provider is None

    openai = AIAdapter(config={"provider": "openai", "api_key": "test-key", "base_url": "", "model": ""})

    assert openai.config["base_url"] == "https://api.openai.com/v1"
    assert openai.config["model"] == "gpt-4.1-mini"


def test_provider_factory_supports_gemini():
    provider = ProviderFactory.create({"provider": "gemini", "api_key": "test-key"})

    assert isinstance(provider, GeminiProvider)
    assert provider.base_url == "https://generativelanguage.googleapis.com/v1beta"
    assert provider.model == "gemini-2.5-flash"
    assert provider.api_key == "test-key"


def test_ai_adapter_normalizes_gemini_model_case_and_prefix():
    adapter = AIAdapter(
        config={
            "provider": "gemini",
            "api_key": "test-key",
            "model": "Models/Gemini-2.5-Flash",
            "enabled": True,
        },
        settings_config={},
    )

    assert adapter.config["model"] == "gemini-2.5-flash"


def test_ai_adapter_replaces_openai_base_url_for_gemini_provider():
    adapter = AIAdapter(
        config={
            "provider": "gemini",
            "api_key": "test-key",
            "base_url": "https://api.openai.com/v1",
            "model": "gemini-2.5-flash",
            "enabled": True,
        },
        settings_config={},
    )

    assert adapter.config["base_url"] == "https://generativelanguage.googleapis.com/v1beta"


def test_actions_accepts_gemini_provider_config():
    parsed = _coerce_ai_provider_config({"provider": "gemini", "api_key": "test-key"}, source="request")

    assert parsed["provider"] == "gemini"
    assert parsed["api_key"] == "test-key"


def test_openai_provider_falls_back_when_response_format_is_unsupported():
    provider = ProviderFactory.create(
        {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "custom-model",
            "api_key": "test-key",
        }
    )
    calls = []

    def _fake_post(_url, headers=None, json=None, timeout=None):  # noqa: ANN001
        calls.append(json or {})
        if len(calls) == 1:
            return _FakeResponse(
                400,
                {
                    "error": {
                        "message": "response_format is not supported for this model",
                    }
                },
            )
        return _FakeResponse(
            200,
            {
                "choices": [
                    {
                        "message": {
                            "content": "{\"commands\":[{\"command\":\"Get-Process\"}]}",
                        }
                    }
                ]
            },
        )

    provider.session.post = _fake_post

    out = provider.ask_json("planner", {"prompt": "safe command"})

    assert out["commands"][0]["command"] == "Get-Process"
    assert "response_format" in calls[0]
    assert "response_format" not in calls[1]


def test_openai_provider_retries_on_rate_limit(monkeypatch):
    provider = ProviderFactory.create(
        {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "custom-model",
            "api_key": "test-key",
        }
    )
    sleep_calls = []

    def _fake_sleep(seconds):  # noqa: ANN001
        sleep_calls.append(float(seconds))

    monkeypatch.setattr(ai_providers.time, "sleep", _fake_sleep)

    responses = [
        _FakeResponse(
            429,
            {"error": {"message": "quota exceeded"}},
            headers={"Retry-After": "0.1"},
        ),
        _FakeResponse(
            200,
            {
                "choices": [
                    {
                        "message": {
                            "content": "{\"commands\":[{\"command\":\"Get-Service\"}]}",
                        }
                    }
                ]
            },
        ),
    ]

    def _fake_post(_url, headers=None, json=None, timeout=None):  # noqa: ANN001
        return responses.pop(0)

    provider.session.post = _fake_post

    out = provider.ask_json("planner", {"prompt": "safe command"})

    assert out["commands"][0]["command"] == "Get-Service"
    assert sleep_calls and sleep_calls[0] == 0.1


def test_openai_provider_surfaces_auth_hint_for_bad_keys():
    provider = ProviderFactory.create(
        {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "custom-model",
            "api_key": "bad-key",
        }
    )

    def _fake_post(_url, headers=None, json=None, timeout=None):  # noqa: ANN001
        return _FakeResponse(401, {"error": {"message": "Invalid API key"}})

    provider.session.post = _fake_post

    with pytest.raises(AIProviderError) as exc_info:
        provider.ask_json("planner", {"prompt": "safe command"})

    assert "authentication failed" in str(exc_info.value).lower()


def test_ai_adapter_accepts_openai_api_key_alias(monkeypatch):
    monkeypatch.delenv("C2F_LLM_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "alias-key")

    adapter = AIAdapter(config=None, settings_config={})

    assert adapter.config["provider"] == "openai"
    assert adapter.config["api_key"] == "alias-key"


def test_ai_adapter_normalizes_openai_style_model_for_gemini_provider():
    adapter = AIAdapter(
        config={
            "provider": "gemini",
            "api_key": "test-key",
            "model": "gpt-4.1-mini",
            "enabled": True,
        },
        settings_config={},
    )

    assert adapter.config["provider"] == "gemini"
    assert adapter.config["model"] == "gemini-2.5-flash"


def test_gemini_provider_falls_back_to_supported_model_when_configured_model_is_missing():
    provider = ProviderFactory.create(
        {
            "provider": "gemini",
            "base_url": "https://generativelanguage.googleapis.com/v1beta",
            "model": "gpt-4.1-mini",
            "api_key": "test-key",
        }
    )

    calls = {"post": 0, "get": 0}

    def _fake_post(url, params=None, headers=None, json=None, timeout=None):  # noqa: ANN001
        calls["post"] += 1
        if "gpt-4.1-mini" in url:
            return _FakeResponse(
                404,
                {
                    "error": {
                        "code": 404,
                        "message": (
                            "models/gpt-4.1-mini is not found for API version v1beta, "
                            "or is not supported for generateContent."
                        ),
                    }
                },
            )
        return _FakeResponse(
            200,
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "{\"commands\":[{\"command\":\"Get-Process\"}]}"}
                            ]
                        }
                    }
                ]
            },
        )

    def _fake_get(url, params=None, timeout=None):  # noqa: ANN001
        calls["get"] += 1
        return _FakeResponse(
            200,
            {
                "models": [
                    {
                        "name": "models/gemini-2.5-flash",
                        "supportedGenerationMethods": ["generateContent"],
                    }
                ]
            },
        )

    provider.session.post = _fake_post
    provider.session.get = _fake_get

    out = provider.ask_json("planner", {"prompt": "safe command"})

    assert out["commands"][0]["command"] == "Get-Process"
    assert provider.model == "gemini-2.5-flash"
    assert calls["post"] == 2
    assert calls["get"] >= 1
