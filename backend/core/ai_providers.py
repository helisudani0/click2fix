from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

import requests


_DEFAULT_PROVIDER = "openai"
_DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
_DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"
_DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
_DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
_GLOBAL_AI_ENABLED_ENV = "C2F_AI_FEATURES_ENABLED"
_LEGACY_AI_ENABLED_ENV = "C2F_AI_REMEDIATION_ENABLED"


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


def _extract_gemini_text(node: Dict[str, Any]) -> str:
    candidates = node.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise AIProviderError("Provider returned no candidates")
    content = _dict(candidates[0].get("content"))
    parts = content.get("parts")
    if not isinstance(parts, list):
        return ""
    out = []
    for item in parts:
        if not isinstance(item, dict):
            continue
        text = _text(item.get("text"))
        if text:
            out.append(text)
    return "\n".join(out)


def _gemini_response_json_schema(system_prompt: str) -> Dict[str, Any] | None:
    prompt = _text(system_prompt).lower()
    if "keys: analysis, decision, commands" in prompt:
        return {
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string"},
                        },
                        "required": ["command"],
                        "additionalProperties": True,
                    },
                },
            },
            "required": ["commands"],
            "additionalProperties": True,
        }
    if "keys: analysis, next" in prompt:
        return {
            "type": "object",
            "properties": {
                "next": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"},
                    },
                    "required": ["command"],
                    "additionalProperties": True,
                },
            },
            "required": ["next"],
            "additionalProperties": True,
        }
    return None


def _clean_base_url(base_url: str) -> str:
    return _text(base_url).rstrip("/")


def _normalize_gemini_model_name(model: str) -> str:
    value = _text(model)
    if value.lower().startswith("models/"):
        value = value.split("/", 1)[1]
    return _text(value)


class AIProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retryable: bool = False,
        retry_after_seconds: float | None = None,
        response_format_unsupported: bool = False,
        model_not_found: bool = False,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = bool(retryable)
        self.retry_after_seconds = retry_after_seconds
        self.response_format_unsupported = bool(response_format_unsupported)
        self.model_not_found = bool(model_not_found)


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

    def _build_body(
        self,
        *,
        system_prompt: str,
        user_payload: Dict[str, Any],
        use_json_response_format: bool,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, default=str)},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if use_json_response_format:
            body["response_format"] = {"type": "json_object"}
        return body

    @staticmethod
    def _parse_retry_after_seconds(resp: requests.Response) -> float | None:
        retry_after = _text(resp.headers.get("Retry-After"))
        if not retry_after:
            return None
        try:
            parsed = float(retry_after)
            if parsed < 0:
                return None
            return parsed
        except Exception:
            return None

    def _raise_http_error(self, resp: requests.Response) -> None:
        status = int(resp.status_code or 0)
        msg = _text(resp.text)[:500]
        lower = msg.lower()
        try:
            node = _dict(resp.json())
            err = _dict(node.get("error"))
            detail = _text(err.get("message")) or _text(err.get("detail")) or msg
            msg = detail[:500]
            lower = msg.lower()
        except Exception:
            pass

        response_format_unsupported = bool(
            status == 400
            and "response_format" in lower
            and any(token in lower for token in ("unsupported", "not support", "not allowed", "invalid"))
        )
        retryable = bool(status in {408, 429} or status >= 500)
        retry_after_seconds = self._parse_retry_after_seconds(resp) if retryable else None

        if status == 401:
            extra = "authentication failed; verify API key"
        elif status == 403:
            extra = "request forbidden for this key/account"
        elif status == 404 and "model" in lower:
            extra = f"model '{self.model}' is unavailable for this key; set C2F_LLM_MODEL to an allowed model"
        elif status == 429:
            extra = "rate limit or quota exceeded for the supplied key"
        else:
            extra = ""
        suffix = f"; {extra}" if extra else ""
        raise AIProviderError(
            f"{self.provider_name} error {status}: {msg}{suffix}",
            status_code=status,
            retryable=retryable,
            retry_after_seconds=retry_after_seconds,
            response_format_unsupported=response_format_unsupported,
        )

    def _request_json(
        self,
        *,
        system_prompt: str,
        user_payload: Dict[str, Any],
        force_retry_warning: bool,
        use_json_response_format: bool,
    ) -> Dict[str, Any]:
        prompt = system_prompt
        if force_retry_warning:
            prompt = f"{prompt}\nPrevious answer was invalid JSON. Respond with exactly one JSON object."
        body = self._build_body(
            system_prompt=prompt,
            user_payload=user_payload,
            use_json_response_format=use_json_response_format,
        )
        url = f"{self.base_url}/chat/completions"
        try:
            resp = self.session.post(url, headers=self._headers(), json=body, timeout=self.timeout_seconds)
        except requests.exceptions.ConnectionError as exc:
            raise AIProviderError(
                f"{self.provider_name} is unreachable at {self.base_url}; verify service and network access",
                retryable=True,
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise AIProviderError(
                f"{self.provider_name} request timed out after {self.timeout_seconds}s",
                retryable=True,
            ) from exc
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} request failed: {exc}") from exc
        if resp.status_code >= 400:
            self._raise_http_error(resp)
        try:
            return _dict(resp.json())
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} returned non-JSON response") from exc

    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        payload = _dict(user_payload)
        if not isinstance(user_payload, dict):
            raise AIProviderError("user_payload must be a JSON object")
        use_json_response_format = True
        invalid_json_attempts = 0
        transport_attempts = 0
        max_transport_attempts = 4
        last_error = ""
        while transport_attempts < max_transport_attempts:
            force_retry_warning = invalid_json_attempts > 0
            try:
                node = self._request_json(
                    system_prompt=system_prompt,
                    user_payload=payload,
                    force_retry_warning=force_retry_warning,
                    use_json_response_format=use_json_response_format,
                )
            except AIProviderError as exc:
                if exc.response_format_unsupported and use_json_response_format:
                    # Some OpenAI-compatible models/providers reject response_format.
                    # Retry once without it and rely on strict prompt + parser validation.
                    use_json_response_format = False
                    continue
                if exc.retryable and transport_attempts < max_transport_attempts - 1:
                    delay = exc.retry_after_seconds
                    if delay is None:
                        delay = min(8.0, float(2**transport_attempts))
                    if delay > 0:
                        time.sleep(delay)
                    transport_attempts += 1
                    continue
                raise
            transport_attempts += 1
            text = _extract_message_text(node)
            parsed = _json_from_text(text)
            if parsed:
                return parsed
            invalid_json_attempts += 1
            last_error = _text(text)[:200]
            if invalid_json_attempts >= 2:
                break
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


class GeminiProvider(_OpenAICompatibleProvider):
    provider_name = "gemini"

    def __init__(self, config: Dict[str, Any]):
        merged = dict(config or {})
        self.base_url = _clean_base_url(merged.get("base_url") or _DEFAULT_GEMINI_BASE_URL)
        self.model = _normalize_gemini_model_name(merged.get("model") or _DEFAULT_GEMINI_MODEL)
        self.api_key = _text(merged.get("api_key"))
        self.timeout_seconds = max(5, _to_int(merged.get("timeout_seconds"), 45))
        self.temperature = _to_float(merged.get("temperature"), 0.1)
        self.max_tokens = max(300, _to_int(merged.get("max_tokens"), 1800))
        self.session = requests.Session()
        if not self.base_url:
            raise AIProviderError("gemini base_url is required")
        if not self.model:
            raise AIProviderError("gemini model is required")
        if not self.api_key:
            raise AIProviderError("Gemini provider requires api_key")

    @staticmethod
    def _is_model_not_found(status: int, message: str) -> bool:
        detail = _text(message).lower()
        if status != 404:
            return False
        if "model" not in detail:
            return False
        return "not found" in detail or "not supported" in detail

    @staticmethod
    def _extract_error_message(resp: requests.Response) -> str:
        fallback = _text(resp.text)[:500]
        try:
            node = _dict(resp.json())
            err = _dict(node.get("error"))
            detail = _text(err.get("message")) or _text(err.get("detail")) or fallback
            return detail[:500] if detail else fallback
        except Exception:
            return fallback

    def _list_generate_content_models(self) -> list[str]:
        url = f"{self.base_url}/models"
        try:
            resp = self.session.get(
                url,
                params={"key": self.api_key},
                timeout=self.timeout_seconds,
            )
        except Exception:
            return []
        if int(resp.status_code or 0) >= 400:
            return []
        try:
            payload = _dict(resp.json())
        except Exception:
            return []
        models = payload.get("models")
        if not isinstance(models, list):
            return []
        out: list[str] = []
        for item in models:
            if not isinstance(item, dict):
                continue
            name = _normalize_gemini_model_name(item.get("name"))
            if not name:
                continue
            methods = item.get("supportedGenerationMethods")
            if isinstance(methods, list) and methods:
                methods_l = {_text(method).lower() for method in methods}
                if "generatecontent" not in methods_l:
                    continue
            if name not in out:
                out.append(name)
        return out

    def _pick_fallback_model(self, blocked_models: set[str]) -> str | None:
        available = self._list_generate_content_models()
        if not available:
            return None
        blocked = {_normalize_gemini_model_name(name).lower() for name in blocked_models}
        by_key = {_normalize_gemini_model_name(name).lower(): name for name in available}
        preferred = [
            _DEFAULT_GEMINI_MODEL,
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-flash",
            "gemini-1.5-pro",
        ]
        for candidate in preferred:
            key = _normalize_gemini_model_name(candidate).lower()
            if key in by_key and key not in blocked:
                return by_key[key]
        for name in available:
            key = _normalize_gemini_model_name(name).lower()
            if key not in blocked:
                return name
        return None

    def _request_json(
        self,
        *,
        system_prompt: str,
        user_payload: Dict[str, Any],
        force_retry_warning: bool,
        use_json_response_format: bool = True,
    ) -> Dict[str, Any]:
        prompt = system_prompt
        if force_retry_warning:
            prompt = f"{prompt}\nPrevious answer was invalid JSON. Respond with exactly one JSON object."
        body = {
            "systemInstruction": {
                "parts": [{"text": prompt}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": json.dumps(user_payload, default=str)}],
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
                "responseMimeType": "application/json",
            },
        }
        schema = _gemini_response_json_schema(prompt)
        if schema:
            body["generationConfig"]["responseJsonSchema"] = schema
        model = _normalize_gemini_model_name(self.model)
        if not model:
            model = _DEFAULT_GEMINI_MODEL
        self.model = model
        url = f"{self.base_url}/models/{model}:generateContent"
        try:
            resp = self.session.post(
                url,
                params={"key": self.api_key},
                headers={"Content-Type": "application/json"},
                json=body,
                timeout=self.timeout_seconds,
            )
        except requests.exceptions.ConnectionError as exc:
            raise AIProviderError(f"{self.provider_name} is unreachable at {self.base_url}; verify service and network access") from exc
        except requests.exceptions.Timeout as exc:
            raise AIProviderError(f"{self.provider_name} request timed out after {self.timeout_seconds}s") from exc
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} request failed: {exc}") from exc
        if resp.status_code >= 400:
            status = int(resp.status_code or 0)
            detail = self._extract_error_message(resp)
            raise AIProviderError(
                f"{self.provider_name} error {status}: {detail}",
                status_code=status,
                model_not_found=self._is_model_not_found(status, detail),
            )
        try:
            return _dict(resp.json())
        except Exception as exc:
            raise AIProviderError(f"{self.provider_name} returned non-JSON response") from exc

    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        payload = _dict(user_payload)
        if not isinstance(user_payload, dict):
            raise AIProviderError("user_payload must be a JSON object")
        last_error = ""
        invalid_json_attempts = 0
        attempted_models: set[str] = set()
        max_total_attempts = 6
        total_attempts = 0
        while total_attempts < max_total_attempts:
            total_attempts += 1
            force_retry_warning = invalid_json_attempts > 0
            attempted_models.add(_normalize_gemini_model_name(self.model))
            try:
                node = self._request_json(
                    system_prompt=system_prompt,
                    user_payload=payload,
                    force_retry_warning=force_retry_warning,
                )
            except AIProviderError as exc:
                if exc.model_not_found:
                    fallback_model = self._pick_fallback_model(attempted_models)
                    if fallback_model:
                        self.model = _normalize_gemini_model_name(fallback_model)
                        invalid_json_attempts = 0
                        continue
                raise
            text = _extract_gemini_text(node)
            parsed = _json_from_text(text)
            if parsed:
                return parsed
            invalid_json_attempts += 1
            last_error = _text(text)[:200]
            if invalid_json_attempts >= 2:
                break
        raise AIProviderError(f"{self.provider_name} returned invalid JSON after retry: {last_error}")


class ProviderFactory:
    @staticmethod
    def create(config: dict) -> BaseAIProvider:
        node = _dict(config)
        provider = _text(node.get("provider") or _DEFAULT_PROVIDER).lower()
        if provider == "openai":
            return OpenAIProvider(node)
        if provider == "gemini":
            return GeminiProvider(node)
        # Fallback: treat any named provider as OpenAI-compatible.
        # This supports providers such as OpenRouter, Groq, xAI, local gateways, etc.
        generic = dict(node or {})
        if provider != "openai" and not _text(generic.get("base_url")):
            raise AIProviderError(
                f"Unsupported AI provider '{provider}' without base_url; "
                "set a provider-specific OpenAI-compatible base_url"
            )
        generic["base_url"] = _clean_base_url(generic.get("base_url") or _DEFAULT_OPENAI_BASE_URL)
        generic["model"] = _text(generic.get("model") or _DEFAULT_OPENAI_MODEL)
        adapter = _OpenAICompatibleProvider(generic)
        adapter.provider_name = provider or "openai-compatible"
        return adapter


class AIAdapter:
    """
    Provider-neutral adapter that keeps the agent independent from provider APIs.

    To add a new provider:
    1) implement BaseAIProvider.ask_json in a new provider class
    2) register it in ProviderFactory.create
    """

    def __init__(self, config: Dict[str, Any] | None = None, settings_config: Dict[str, Any] | None = None):
        self.config = self._resolve_config(config=config, settings_config=settings_config)
        self.enabled = _to_bool(self.config.get("enabled"), False)
        # Provider initialization is lazy so disabled AI does not require provider credentials at startup.
        self.provider: BaseAIProvider | None = None

    @staticmethod
    def _platform_ai_enabled() -> bool:
        raw = os.getenv(_GLOBAL_AI_ENABLED_ENV)
        if raw is None:
            raw = os.getenv(_LEGACY_AI_ENABLED_ENV, "false")
        return _to_bool(raw, False)

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

        provider = _text(pick("provider", "C2F_LLM_PROVIDER", _DEFAULT_PROVIDER)).lower() or _DEFAULT_PROVIDER
        provider_defaults = {
            "openai": (_DEFAULT_OPENAI_BASE_URL, _DEFAULT_OPENAI_MODEL),
            "gemini": (_DEFAULT_GEMINI_BASE_URL, _DEFAULT_GEMINI_MODEL),
        }
        default_base, default_model = provider_defaults.get(
            provider,
            ("", ""),
        )
        if "api_key" in user_cfg:
            api_key = user_cfg.get("api_key")
        elif has_user_config:
            # Tenant-level injected config should not silently inherit global env keys.
            api_key = ""
        else:
            api_key = os.getenv("C2F_LLM_API_KEY")
            if api_key is None and "api_key" in settings_cfg:
                api_key = settings_cfg.get("api_key")
        normalized_api_key = _text(
            api_key
            or (
                os.getenv("OPENAI_API_KEY")
                if (not has_user_config and provider == "openai")
                else ""
            )
        )
        platform_enabled = AIAdapter._platform_ai_enabled()
        runtime_enabled_override = bool(
            has_user_config
            and ("enabled" in user_cfg)
            and _to_bool(user_cfg.get("enabled"), False)
        )
        effective_platform_enabled = bool(platform_enabled or runtime_enabled_override)
        local_enabled = _to_bool(pick("enabled", _LEGACY_AI_ENABLED_ENV, True), True)
        enabled = bool(effective_platform_enabled and local_enabled and bool(normalized_api_key))
        resolved_model = _text(pick("model", "C2F_LLM_MODEL", default_model)) or default_model
        if provider == "gemini":
            resolved_model = _normalize_gemini_model_name(resolved_model)
            if not resolved_model or resolved_model.lower().startswith("gpt-"):
                resolved_model = _DEFAULT_GEMINI_MODEL
        return {
            "enabled": enabled,
            "provider": provider,
            "base_url": _text(pick("base_url", "C2F_LLM_BASE_URL", default_base)) or default_base,
            "model": resolved_model,
            "api_key": normalized_api_key,
            "timeout_seconds": max(5, _to_int(pick("timeout_seconds", "C2F_LLM_TIMEOUT_SECONDS", 45), 45)),
            "temperature": _to_float(pick("temperature", "C2F_LLM_TEMPERATURE", 0.1), 0.1),
            "max_tokens": max(300, _to_int(pick("max_tokens", "C2F_LLM_MAX_TOKENS", 1800), 1800)),
        }

    def ask_json(self, system_prompt: str, user_payload: dict) -> dict:
        if not self.enabled:
            raise AIProviderError(
                "AI features are disabled. Set C2F_AI_FEATURES_ENABLED=true with C2F_LLM_API_KEY, or configure AI in Org Admin."
            )
        if self.provider is None:
            self.provider = ProviderFactory.create(self.config)
        return self.provider.ask_json(system_prompt=system_prompt, user_payload=user_payload)
