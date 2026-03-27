from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from sqlalchemy import text

from core.time_utils import utc_now_naive
from db.database import connect

AI_REMEDIATION_CONFIG_KEY = "ai_remediation"
ALLOWED_AI_PROVIDERS = {"openai", "gemini"}


def _to_text(value: Any) -> str:
    return str(value or "").strip()


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def coerce_ai_provider_config(
    value: Any,
    *,
    source_label: str = "request body",
    status_code: int = 400,
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=status_code, detail="ai_config must be an object")

    out: dict[str, Any] = {}
    provider = _to_text(value.get("provider")).lower()
    if provider:
        if provider not in ALLOWED_AI_PROVIDERS:
            raise HTTPException(
                status_code=status_code,
                detail=f"Unsupported AI provider '{provider}' in {source_label}",
            )
        out["provider"] = provider

    for key in ("base_url", "model", "api_key"):
        if key in value:
            out[key] = _to_text(value.get(key))

    if "enabled" in value:
        out["enabled"] = _to_bool(value.get("enabled"), True)

    if "timeout_seconds" in value:
        timeout_seconds = _to_int(value.get("timeout_seconds"), -1)
        if timeout_seconds < 1:
            raise HTTPException(
                status_code=status_code,
                detail=f"timeout_seconds in {source_label} must be >= 1",
            )
        out["timeout_seconds"] = timeout_seconds

    if "max_tokens" in value:
        max_tokens = _to_int(value.get("max_tokens"), -1)
        if max_tokens < 1:
            raise HTTPException(
                status_code=status_code,
                detail=f"max_tokens in {source_label} must be >= 1",
            )
        out["max_tokens"] = max_tokens

    if "temperature" in value:
        try:
            temperature = float(value.get("temperature"))
        except Exception as exc:
            raise HTTPException(
                status_code=status_code,
                detail=f"temperature in {source_label} must be a number",
            ) from exc
        if temperature < 0 or temperature > 2:
            raise HTTPException(
                status_code=status_code,
                detail=f"temperature in {source_label} must be between 0 and 2",
            )
        out["temperature"] = temperature

    return out


def _extract_ai_config_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    if isinstance(node.get("ai_config"), dict):
        return node.get("ai_config") or {}
    if isinstance(node.get("ai_remediation"), dict):
        return node.get("ai_remediation") or {}
    if any(
        key in node
        for key in (
            "provider",
            "base_url",
            "model",
            "api_key",
            "timeout_seconds",
            "temperature",
            "max_tokens",
            "enabled",
        )
    ):
        return node
    return {}


def load_active_tenant_ai_config(org_id: Any) -> dict[str, Any]:
    tenant_id = _to_int(org_id, 0)
    if tenant_id < 1:
        return {}

    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT config_json
                FROM tenant_config_revisions
                WHERE org_id=:tenant_id
                  AND config_key=:config_key
                  AND LOWER(COALESCE(status, 'draft'))='active'
                ORDER BY version DESC, id DESC
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id, "config_key": AI_REMEDIATION_CONFIG_KEY},
        ).fetchone()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Tenant config store is unavailable for AI settings",
        ) from exc
    finally:
        db.close()

    if not row:
        return {}

    raw_json = (
        row._mapping.get("config_json")
        if hasattr(row, "_mapping")
        else (row[0] if isinstance(row, (tuple, list)) and row else row)
    )
    if isinstance(raw_json, str):
        try:
            node = json.loads(raw_json)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Active tenant ai_remediation config is not valid JSON",
            ) from exc
    elif isinstance(raw_json, dict):
        node = raw_json
    else:
        return {}

    parsed = _extract_ai_config_node(node)
    return coerce_ai_provider_config(
        parsed,
        source_label="tenant ai_remediation config",
        status_code=503,
    )


def upsert_active_tenant_ai_config(
    *,
    org_id: Any,
    actor: str,
    ai_config: dict[str, Any],
    notes: str | None = None,
) -> dict[str, Any]:
    tenant_id = _to_int(org_id, 0)
    if tenant_id < 1:
        raise HTTPException(status_code=400, detail="Tenant scope is required for AI config update")

    normalized = coerce_ai_provider_config(
        ai_config,
        source_label="system ai config",
        status_code=400,
    )
    if "enabled" not in normalized:
        normalized["enabled"] = _to_bool(normalized.get("api_key"), False)

    db = connect()
    try:
        current_version = (
            db.execute(
                text(
                    """
                    SELECT COALESCE(MAX(version), 0)
                    FROM tenant_config_revisions
                    WHERE org_id=:tenant_id
                      AND config_key=:config_key
                    """
                ),
                {"tenant_id": tenant_id, "config_key": AI_REMEDIATION_CONFIG_KEY},
            ).scalar()
            or 0
        )
        next_version = int(current_version) + 1
        now = utc_now_naive()

        db.execute(
            text(
                """
                UPDATE tenant_config_revisions
                SET status='retired', retired_at=:retired_at, updated_by=:updated_by
                WHERE org_id=:tenant_id
                  AND config_key=:config_key
                  AND LOWER(COALESCE(status, 'draft'))='active'
                """
            ),
            {
                "tenant_id": tenant_id,
                "config_key": AI_REMEDIATION_CONFIG_KEY,
                "retired_at": now,
                "updated_by": actor,
            },
        )

        db.execute(
            text(
                """
                INSERT INTO tenant_config_revisions
                (org_id, config_key, version, status, config_json, notes, created_by, updated_by, activated_at)
                VALUES
                (:tenant_id, :config_key, :version, 'active', :config_json, :notes, :created_by, :updated_by, :activated_at)
                """
            ),
            {
                "tenant_id": tenant_id,
                "config_key": AI_REMEDIATION_CONFIG_KEY,
                "version": next_version,
                "config_json": json.dumps(
                    {"ai_remediation": normalized},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ),
                "notes": _to_text(notes) or "Updated from v1 system ai config UI",
                "created_by": _to_text(actor) or "system",
                "updated_by": _to_text(actor) or "system",
                "activated_at": now,
            },
        )

        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="Failed to persist AI configuration") from exc
    finally:
        db.close()

    return normalized


def mask_api_key(value: Any) -> str:
    raw = _to_text(value)
    if not raw:
        return ""
    if len(raw) <= 8:
        return "*" * len(raw)
    return f"{raw[:4]}***{raw[-4:]}"


def to_public_ai_config(config: dict[str, Any]) -> dict[str, Any]:
    node = dict(config or {})
    raw_key = _to_text(node.get("api_key"))
    return {
        "enabled": _to_bool(node.get("enabled"), False),
        "provider": _to_text(node.get("provider")),
        "base_url": _to_text(node.get("base_url")),
        "model": _to_text(node.get("model")),
        "timeout_seconds": _to_int(node.get("timeout_seconds"), 0),
        "temperature": node.get("temperature"),
        "max_tokens": _to_int(node.get("max_tokens"), 0),
        "has_api_key": bool(raw_key),
        "api_key_masked": mask_api_key(raw_key),
    }
