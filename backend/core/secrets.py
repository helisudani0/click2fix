from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any


_CACHE_LOCK = threading.Lock()
_VAULT_CACHE: dict[tuple[str, str, str | None], str] = {}
_SECRET_SPEC_KEYS = {"from_env", "from_file", "from_vault", "secret_ref", "default", "required", "value"}


def _trim(value: Any) -> str:
    return str(value or "").strip()


def vault_provider_status() -> dict[str, Any]:
    addr = _trim(os.getenv("C2F_VAULT_ADDR") or os.getenv("VAULT_ADDR"))
    token = _trim(os.getenv("C2F_VAULT_TOKEN") or os.getenv("VAULT_TOKEN"))
    namespace = _trim(os.getenv("C2F_VAULT_NAMESPACE") or os.getenv("VAULT_NAMESPACE"))
    return {
        "configured": bool(addr and token),
        "address": addr or None,
        "namespace": namespace or None,
        "token_configured": bool(token),
        "supported_secret_refs": ["env://VAR", "file://path", "vault://secret/path#field"],
    }


def _read_file_secret(path_value: str) -> str:
    path = _trim(path_value)
    if not path:
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def _vault_headers() -> dict[str, str]:
    token = _trim(os.getenv("C2F_VAULT_TOKEN") or os.getenv("VAULT_TOKEN"))
    namespace = _trim(os.getenv("C2F_VAULT_NAMESPACE") or os.getenv("VAULT_NAMESPACE"))
    headers = {}
    if token:
        headers["X-Vault-Token"] = token
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    return headers


def _vault_addr() -> str:
    return _trim(os.getenv("C2F_VAULT_ADDR") or os.getenv("VAULT_ADDR")).rstrip("/")


def _read_vault_secret(secret_ref: str) -> str:
    addr = _vault_addr()
    if not addr:
        return ""

    raw_ref = _trim(secret_ref)
    if raw_ref.startswith("vault://"):
        raw_ref = raw_ref[len("vault://") :]
    path_part, _, field = raw_ref.partition("#")
    path = path_part.lstrip("/")
    cache_key = (addr, path, field or None)
    with _CACHE_LOCK:
        cached = _VAULT_CACHE.get(cache_key)
        if cached is not None:
            return cached

    url = f"{addr}/v1/{path}"
    req = urllib.request.Request(url, headers=_vault_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, TimeoutError, ValueError):
        return ""

    data = payload.get("data")
    if isinstance(data, Mapping) and isinstance(data.get("data"), Mapping):
        data = data.get("data")
    if not isinstance(data, Mapping):
        return ""

    if field:
        resolved = _trim(data.get(field))
    elif len(data) == 1:
        resolved = _trim(next(iter(data.values())))
    else:
        resolved = ""

    with _CACHE_LOCK:
        _VAULT_CACHE[cache_key] = resolved
    return resolved


def resolve_secret_value(value: Any, *, default: str = "", _depth: int = 0) -> str:
    if _depth > 4:
        return _trim(default)
    if value is None:
        return _trim(default)

    if isinstance(value, Mapping) and set(value.keys()).issubset(_SECRET_SPEC_KEYS):
        if "value" in value and value.get("value") not in {None, ""}:
            return resolve_secret_value(value.get("value"), default=_trim(value.get("default", default)), _depth=_depth + 1)
        if value.get("from_env"):
            env_name = _trim(value.get("from_env"))
            return resolve_secret_env(env_name, fallback=value.get("default", default), _depth=_depth + 1)
        if value.get("from_file"):
            path_value = _trim(value.get("from_file"))
            resolved = _read_file_secret(path_value)
            return resolved or _trim(value.get("default", default))
        if value.get("from_vault"):
            secret_ref = _trim(value.get("from_vault"))
            resolved = _read_vault_secret(secret_ref)
            return resolved or _trim(value.get("default", default))
        if value.get("secret_ref"):
            return resolve_secret_value(value.get("secret_ref"), default=_trim(value.get("default", default)), _depth=_depth + 1)
        return _trim(value.get("default", default))

    text_value = _trim(value)
    if not text_value:
        return _trim(default)
    if text_value.startswith("env://"):
        return resolve_secret_env(text_value[len("env://") :], fallback=default, _depth=_depth + 1)
    if text_value.startswith("file://"):
        resolved = _read_file_secret(text_value[len("file://") :])
        return resolved or _trim(default)
    if text_value.startswith("vault://"):
        resolved = _read_vault_secret(text_value)
        return resolved or _trim(default)
    return text_value


def resolve_secret_env(env_name: str, fallback: Any = "", *, _depth: int = 0) -> str:
    candidate = os.getenv(_trim(env_name))
    if candidate not in {None, ""}:
        return resolve_secret_value(candidate, default="", _depth=_depth + 1)
    return resolve_secret_value(fallback, default="", _depth=_depth + 1)


def resolve_settings_tree(node: Any) -> Any:
    if isinstance(node, list):
        return [resolve_settings_tree(item) for item in node]
    if isinstance(node, Mapping):
        if set(node.keys()).issubset(_SECRET_SPEC_KEYS) and any(
            key in node for key in ("from_env", "from_file", "from_vault", "secret_ref", "value")
        ):
            return resolve_secret_value(node)
        return {str(key): resolve_settings_tree(value) for key, value in node.items()}
    if isinstance(node, str) and (
        node.strip().startswith("env://")
        or node.strip().startswith("file://")
        or node.strip().startswith("vault://")
    ):
        return resolve_secret_value(node)
    return node
