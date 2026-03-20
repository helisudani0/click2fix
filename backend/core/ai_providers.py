from __future__ import annotations

import json
import os
from typing import Any, Dict

import requests


_DEFAULT_PROVIDER = "openai"
_DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _json_from_text(raw: str) -> Dict[str, Any]:
    text = _text(raw)
    if not text:
        return {}
    try:
        node = json.loads(text)
        return node if isinstance(node, dict) else {}
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            node = json.loads(text[start : end + 1])
            return node if isinstance(node, dict) else {}
        except Exception:
            return {}
    return {}


def _extract_message_text(node: Dict[str, Any]) -> str:
    choices = node.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AIProviderError("Provider returned no choices")
    message = _dict(choices[0].get("message"))
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if not isinstance(item, dict):
                continue
            text = _text(item.get("text") or item.get("content"))
            if text:
                parts.append(text)
        return "\n".join(parts)
    return ""


def _clean_base_url(base_url: str) -> str:
    return _text(base_url).rstrip("/")


class AIProviderError(RuntimeError):
    pass


class BaseAIProvider:
    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        raise NotImplementedError


class _OpenAICompatibleProvider(BaseAIProvider):
    provider_name = "provider"

    def __init__(self, config: Dict[str, Any]):
        self.base_url = _clean_base_url(config.get("base_url"))
        self.model = _text(config.get("model"))
        self.api_key = _text(config.get("api_key"))
        self.timeout_seconds = max(5, _to_int(config.get("timeout_seconds"), 45))
        self.temperature = _to_float(config.get("temperature"), 0.1)
        self.max_tokens = max(300, _to_int(config.get("max_tokens"), 1800))
        self.session = requests.Session()
        if not self.base_url:
            raise AIProviderError(f"{self.provider_name} base_url is required")
        if not self.model:
            raise AIProviderError(f"{self.provider_name} model is required")

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request_json(self, *, system_prompt: str, user_payload: Dict[str, Any], force_retry_warning: bool) -> Dict[str, Any]:
        prompt = system_prompt
        if force_retry_warning:
            prompt = f"{prompt}\nPrevious answer was invalid JSON. Respond with exactly one JSON object."
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(user_payload, default=str)},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"},
        }
        url = f"{self.base_url}/chat/completions"
        try:
            resp = self.session.post(url, headers=self._headers(), json=body, timeout=self.timeout_seconds)
        except requests.exceptions.ConnectionError as exc:
            raise AIProviderError(f"{self.provider_name} is unreachable at {self.base_url}; verify service and network access") from exc
        except requests.exceptions.Timeout as exc:
            raise AIProviderError(f"{self.provider_name} request timed out after {self.timeout_seconds}s") from exc
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} request failed: {exc}") from exc
        if resp.status_code >= 400:
            raise AIProviderError(f"{self.provider_name} error {resp.status_code}: {_text(resp.text)[:400]}")
        try:
            return _dict(resp.json())
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} returned non-JSON response") from exc

    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        payload = _dict(user_payload)
        if not isinstance(user_payload, dict):
            raise AIProviderError("user_payload must be a JSON object")
        last_error = ""
        for attempt in range(2):
            node = self._request_json(system_prompt=system_prompt, user_payload=payload, force_retry_warning=attempt == 1)
            text = _extract_message_text(node)
            parsed = _json_from_text(text)
            if parsed:
                return parsed
            last_error = _text(text)[:200]
        raise AIProviderError(f"{self.provider_name} returned invalid JSON after retry: {last_error}")


class OpenAIProvider(_OpenAICompatibleProvider):
    provider_name = "openai"

    def __init__(self, config: Dict[str, Any]):
        merged = dict(config or {})
        merged["base_url"] = _clean_base_url(merged.get("base_url") or _DEFAULT_OPENAI_BASE_URL)
        merged["model"] = _text(merged.get("model") or _DEFAULT_OPENAI_MODEL)
        super().__init__(merged)
        if not self.api_key:
            raise AIProviderError("OpenAI provider requires api_key")


class ProviderFactory:
    @staticmethod
    def create(config: dict) -> BaseAIProvider:
        node = _dict(config)
        provider = _text(node.get("provider") or _DEFAULT_PROVIDER).lower()
        if provider == "openai":
            return OpenAIProvider(node)
        if provider == "ollama":
            # Local Ollama support is intentionally disabled for now and can be restored later.
            raise AIProviderError("Unsupported AI provider: ollama (temporarily disabled)")
        raise AIProviderError(f"Unsupported AI provider: {provider}")


class AIAdapter:
    """
    Provider-neutral adapter that keeps the agent independent from provider APIs.

    To add a new provider:
    1) implement BaseAIProvider.ask_json in a new provider class
    2) register it in ProviderFactory.create
    """

    def __init__(self, config: Dict[str, Any] | None = None, settings_config: Dict[str, Any] | None = None):
        self.config = self._resolve_config(config=config, settings_config=settings_config)
        self.enabled = _to_bool(self.config.get("enabled"), True)
        # Provider initialization is lazy so disabled AI does not require provider credentials at startup.
        self.provider: BaseAIProvider | None = None

    @staticmethod
    def _resolve_config(config: Dict[str, Any] | None, settings_config: Dict[str, Any] | None) -> Dict[str, Any]:
        has_user_config = config is not None
        user_cfg = _dict(config)
        settings_cfg = _dict(settings_config)

        def pick(key: str, env_name: str, default: Any) -> Any:
            if key in user_cfg:
                return user_cfg.get(key)
            if not has_user_config:
                env_value = os.getenv(env_name)
                if env_value is not None:
                    return env_value
            if key in settings_cfg:
                return settings_cfg.get(key)
            return default

        provider = _text(pick("provider", "C2F_LLM_PROVIDER", _DEFAULT_PROVIDER)).lower()
        default_base = _DEFAULT_OPENAI_BASE_URL
        default_model = _DEFAULT_OPENAI_MODEL
        if "api_key" in user_cfg:
            api_key = user_cfg.get("api_key")
        elif has_user_config:
            # Tenant-level injected config should not silently inherit global env keys.
            api_key = ""
        else:
            api_key = os.getenv("C2F_LLM_API_KEY")
            if api_key is None and "api_key" in settings_cfg:
                api_key = settings_cfg.get("api_key")
        return {
            "enabled": _to_bool(pick("enabled", "C2F_AI_REMEDIATION_ENABLED", True), True),
            "provider": provider,
            "base_url": _text(pick("base_url", "C2F_LLM_BASE_URL", default_base)),
            "model": _text(pick("model", "C2F_LLM_MODEL", default_model)),
            "api_key": _text(api_key),
            "timeout_seconds": max(5, _to_int(pick("timeout_seconds", "C2F_LLM_TIMEOUT_SECONDS", 45), 45)),
            "temperature": _to_float(pick("temperature", "C2F_LLM_TEMPERATURE", 0.1), 0.1),
            "max_tokens": max(300, _to_int(pick("max_tokens", "C2F_LLM_MAX_TOKENS", 1800), 1800)),
        }

    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        if not self.enabled:
            raise AIProviderError("AI remediation is disabled")
        if self.provider is None:
            self.provider = ProviderFactory.create(self.config)
        return self.provider.ask_json(system_prompt=system_prompt, user_payload=user_payload)
