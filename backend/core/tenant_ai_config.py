from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from typing import Any

from fastapi import HTTPException
from sqlalchemy import text

from core.time_utils import utc_now_naive
from db.database import connect

AI_REMEDIATION_CONFIG_KEY = "ai_remediation"
logger = logging.getLogger(__name__)
_AI_CONFIG_ENCRYPTION_KEY_ENV = "C2F_AI_CONFIG_ENCRYPTION_KEY"
_AI_CONFIG_ENCRYPTION_PREFIX = "enc:v1:"
_FERNET = None
_FERNET_INIT = False


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


_PROVIDER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def _normalize_provider(value: Any, *, status_code: int) -> str:
    provider = _to_text(value).lower()
    if not provider:
        return ""
    if not _PROVIDER_PATTERN.match(provider):
        raise HTTPException(
            status_code=status_code,
            detail="provider must match ^[a-z0-9][a-z0-9._-]{0,63}$",
        )
    return provider


def _get_fernet():
    global _FERNET, _FERNET_INIT
    if _FERNET_INIT:
        return _FERNET
    _FERNET_INIT = True

    raw = _to_text(os.getenv(_AI_CONFIG_ENCRYPTION_KEY_ENV))
    if not raw:
        return None

    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception as exc:
        logger.warning(
            "AI config encryption key is set but cryptography is unavailable; API keys will be stored unencrypted (%s)",
            exc.__class__.__name__,
        )
        return None

    try:
        derived = base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())
        _FERNET = Fernet(derived)
    except Exception as exc:
        logger.warning("Failed to initialize AI config encryption; storing API keys unencrypted (%s)", exc.__class__.__name__)
        _FERNET = None
    return _FERNET


def _encrypt_api_key(value: Any) -> str:
    raw = _to_text(value)
    if not raw:
        return ""
    if raw.startswith(_AI_CONFIG_ENCRYPTION_PREFIX):
        return raw

    fernet = _get_fernet()
    if not fernet:
        return raw
    try:
        token = fernet.encrypt(raw.encode("utf-8")).decode("utf-8")
        return f"{_AI_CONFIG_ENCRYPTION_PREFIX}{token}"
    except Exception as exc:
        logger.warning("Failed to encrypt tenant AI API key; storing plaintext (%s)", exc.__class__.__name__)
        return raw


def _decrypt_api_key(value: Any) -> str:
    raw = _to_text(value)
    if not raw:
        return ""
    if not raw.startswith(_AI_CONFIG_ENCRYPTION_PREFIX):
        return raw

    token = raw[len(_AI_CONFIG_ENCRYPTION_PREFIX) :]
    fernet = _get_fernet()
    if not fernet:
        logger.error(
            "Encrypted tenant AI API key found but encryption runtime is unavailable. "
            "Set %s and ensure cryptography is installed.",
            _AI_CONFIG_ENCRYPTION_KEY_ENV,
        )
        return ""
    try:
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        logger.warning("Failed to decrypt tenant AI API key (%s)", exc.__class__.__name__)
        return ""


def _with_encrypted_api_key(config: dict[str, Any]) -> dict[str, Any]:
    node = dict(config or {})
    if "api_key" in node:
        node["api_key"] = _encrypt_api_key(node.get("api_key"))
    return node


def _with_decrypted_api_key(config: dict[str, Any]) -> dict[str, Any]:
    node = dict(config or {})
    if "api_key" in node:
        node["api_key"] = _decrypt_api_key(node.get("api_key"))
    return node


def ai_feature_disabled_detail(feature_label: str = "AI feature") -> str:
    feature = _to_text(feature_label) or "AI feature"
    return f"{feature} is disabled. Enable it in Org Admin / Platform AI Configuration."


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
    provider = _normalize_provider(value.get("provider"), status_code=status_code)
    if provider:
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


def _close_quietly(db) -> None:
    try:
        if db is not None:
            db.close()
    except Exception:
        pass


def _ensure_tenant_config_store_best_effort() -> None:
    """
    Keep v1 deployments resilient when DB schema drift leaves out
    tenant_config_revisions.
    """
    try:
        from db import database as db_database

        table = getattr(db_database, "tenant_config_revisions", None)
        engine = getattr(db_database, "engine", None)
        if table is None or engine is None:
            return
        table.create(bind=engine, checkfirst=True)
    except Exception as exc:
        logger.debug("tenant config store ensure failed: %s", exc)


def _fetch_active_tenant_ai_row(db, tenant_id: int):
    return db.execute(
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


def load_active_tenant_ai_config(org_id: Any) -> dict[str, Any]:
    tenant_id = _to_int(org_id, 0)
    if tenant_id < 1:
        return {}

    row = None
    db = None
    try:
        db = connect()
        row = _fetch_active_tenant_ai_row(db, tenant_id)
    except Exception as first_exc:
        _close_quietly(db)
        _ensure_tenant_config_store_best_effort()
        retry_db = None
        try:
            retry_db = connect()
            row = _fetch_active_tenant_ai_row(retry_db, tenant_id)
        except Exception as retry_exc:
            logger.warning(
                "Tenant AI config store unavailable for org_id=%s; using env fallback (%s, retry=%s)",
                tenant_id,
                first_exc.__class__.__name__,
                retry_exc.__class__.__name__,
            )
            return {}
        finally:
            _close_quietly(retry_db)
    else:
        _close_quietly(db)

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
        except Exception:
            logger.warning(
                "Ignoring invalid tenant ai_remediation JSON for org_id=%s",
                tenant_id,
            )
            return {}
    elif isinstance(raw_json, dict):
        node = raw_json
    else:
        return {}

    parsed = _extract_ai_config_node(node)
    try:
        coerced = coerce_ai_provider_config(
            parsed,
            source_label="tenant ai_remediation config",
            status_code=503,
        )
        return _with_decrypted_api_key(coerced)
    except HTTPException as exc:
        logger.warning(
            "Ignoring invalid tenant ai_remediation config for org_id=%s: %s",
            tenant_id,
            exc.detail,
        )
        return {}


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

    _ensure_tenant_config_store_best_effort()
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
                    {"ai_remediation": _with_encrypted_api_key(normalized)},
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
        "encryption_active": bool(_get_fernet()),
    }


def require_active_tenant_ai_config(
    org_id: Any,
    *,
    feature_label: str = "AI feature",
) -> dict[str, Any]:
    config = load_active_tenant_ai_config(org_id)
    if not config or not _to_bool(config.get("enabled"), False):
        raise HTTPException(status_code=503, detail=ai_feature_disabled_detail(feature_label))
    if not _to_text(config.get("api_key")):
        raise HTTPException(
            status_code=503,
            detail=(
                f"{_to_text(feature_label) or 'AI feature'} is enabled but API key is missing. "
                "Update Org Admin / Platform AI Configuration."
            ),
        )
    return config
