from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import urlsplit

from core.settings import SETTINGS

DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173",
    "http://localhost:3000",
)


def normalize_origin(origin: str | None) -> str:
    value = str(origin or "").strip()
    if not value:
        return ""
    if value == "*":
        return value
    parsed = urlsplit(value)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return value.rstrip("/")


def _origin_host(origin: str | None) -> str:
    value = normalize_origin(origin)
    if not value or value == "*":
        return ""
    try:
        return str(urlsplit(value).hostname or "").strip().lower()
    except Exception:
        return ""


def _split_host_values(raw_value: Any) -> list[str]:
    raw = str(raw_value or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _normalize_host(value: str) -> str:
    token = str(value or "").strip()
    if not token:
        return ""
    try:
        parsed = urlsplit(token if "://" in token else f"//{token}")
        host = str(parsed.hostname or "").strip().lower()
        if host:
            return host
    except Exception:
        pass
    return token.strip("[]").lower()


def request_host_candidates(headers: Mapping[str, Any] | None) -> set[str]:
    if not headers:
        return set()
    candidates: set[str] = set()
    for header_name in ("host", "x-forwarded-host", "x-original-host", "x-forwarded-server"):
        for token in _split_host_values(headers.get(header_name)):
            host = _normalize_host(token)
            if host:
                candidates.add(host)
    return candidates


def origin_matches_request_hosts(origin: str | None, headers: Mapping[str, Any] | None) -> bool:
    origin_host = _origin_host(origin)
    if not origin_host:
        return False
    return origin_host in request_host_candidates(headers)


def _cfg_origins() -> list[str]:
    cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    raw = cfg.get("cors_origins")
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _env_origins() -> list[str]:
    raw = str(os.getenv("C2F_CORS_ORIGINS") or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def configured_cors_origins(defaults: Iterable[str] = DEFAULT_CORS_ORIGINS) -> list[str]:
    raw_origins = _env_origins() or _cfg_origins() or list(defaults)
    normalized: list[str] = []
    for origin in raw_origins:
        value = normalize_origin(origin)
        if not value or value == "*" or value in normalized:
            continue
        normalized.append(value)
    if normalized:
        return normalized
    return [normalize_origin(origin) for origin in defaults if normalize_origin(origin)]
