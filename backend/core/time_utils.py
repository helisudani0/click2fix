from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping


UTC = timezone.utc
_NO_TZ_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?$")


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(tz=UTC)


def utc_now_naive() -> datetime:
    """Return UTC now without tzinfo for DB fields that store naive timestamps."""
    return utc_now().replace(tzinfo=None)


def parse_utc_datetime(value: Any) -> datetime | None:
    """Parse common timestamp shapes and normalize them to UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=UTC)
        except (TypeError, ValueError, OSError):
            return None
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        normalized = raw.replace("Z", "+00:00")
        if _NO_TZ_ISO_RE.match(normalized):
            normalized = f"{normalized}+00:00"
        try:
            dt = datetime.fromisoformat(normalized)
        except ValueError:
            try:
                dt = datetime.fromtimestamp(float(raw), tz=UTC)
            except (TypeError, ValueError, OSError):
                return None
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def utc_iso(value: Any, *, fallback: str | None = None) -> str | None:
    """Render value as UTC ISO-8601 string with explicit Z suffix."""
    dt = parse_utc_datetime(value)
    if dt is None:
        return fallback
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_iso_now() -> str:
    return utc_iso(utc_now()) or ""


def to_json_safe(value: Any) -> Any:
    """Recursively coerce datetime objects to UTC Z-strings."""
    if isinstance(value, datetime):
        return utc_iso(value)
    if isinstance(value, Mapping):
        return {str(k): to_json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [to_json_safe(v) for v in value]
    return value


def serialize_row(row: Any) -> dict | None:
    """Serialize SQLAlchemy rows/mappings into JSON-safe dictionaries."""
    if row is None:
        return None
    if hasattr(row, "_mapping"):
        return to_json_safe(dict(row._mapping))
    if isinstance(row, Mapping):
        return to_json_safe(dict(row))
    if isinstance(row, dict):
        return to_json_safe(row)
    try:
        return to_json_safe(dict(row))
    except Exception:
        return {"value": to_json_safe(row)}


def row_to_json_list(row: Any) -> list | None:
    """Serialize SQLAlchemy rows/sequences into JSON-safe lists."""
    if row is None:
        return None
    if hasattr(row, "_mapping"):
        values = list(row._mapping.values())
    elif isinstance(row, Mapping):
        values = list(row.values())
    elif isinstance(row, (list, tuple)):
        values = list(row)
    else:
        values = [row]
    return [to_json_safe(v) for v in values]
