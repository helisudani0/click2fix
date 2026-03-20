from __future__ import annotations

import os
from collections.abc import Iterable
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
