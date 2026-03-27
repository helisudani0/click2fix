import os
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text

from core.ai_providers import AIAdapter
from core.ingest_gateway_client import IngestGatewayClient
from core.indexer_client import IndexerClient
from core.scheduler import scheduler as core_scheduler
from core.security import require_role
from core.settings import SETTINGS
from core.tenant_ai_config import (
    coerce_ai_provider_config,
    load_active_tenant_ai_config,
    to_public_ai_config,
    upsert_active_tenant_ai_config,
)
from core.time_utils import utc_iso, utc_now
from core.wazuh_client import WazuhClient
from core.execution_reconciler import reconcile_orphan_executions
from db.database import connect


router = APIRouter(prefix="/system")
_started_at = utc_now()
_OVERVIEW_HEALTH_CACHE_TTL_SECONDS = max(
    1.0,
    float(os.getenv("C2F_OVERVIEW_HEALTH_CACHE_TTL_SECONDS", "15")),
)
_overview_health_cache_lock = threading.Lock()
_overview_health_cache: dict[str, object] = {
    "expires_at": 0.0,
    "integration": None,
    "queue_summary": None,
}


def _mask(value: str | None) -> str | None:
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}***{value[-2:]}"


def _safe_settings() -> dict:
    cfg = SETTINGS if isinstance(SETTINGS, dict) else {}
    wazuh = cfg.get("wazuh", {}) if isinstance(cfg.get("wazuh", {}), dict) else {}
    indexer = cfg.get("indexer", {}) if isinstance(cfg.get("indexer", {}), dict) else {}
    ingest = cfg.get("analytics_ingest", {}) if isinstance(cfg.get("analytics_ingest", {}), dict) else {}
    ingest_event_driven = (
        ingest.get("event_driven", {})
        if isinstance(ingest.get("event_driven", {}), dict)
        else {}
    )
    active_response = cfg.get("active_response", {}) if isinstance(cfg.get("active_response", {}), dict) else {}
    orchestration = cfg.get("orchestration", {}) if isinstance(cfg.get("orchestration", {}), dict) else {}
    endpoint_connectors = (
        cfg.get("endpoint_connectors", {})
        if isinstance(cfg.get("endpoint_connectors", {}), dict)
        else {}
    )
    endpoint_windows = (
        endpoint_connectors.get("windows", {})
        if isinstance(endpoint_connectors.get("windows", {}), dict)
        else {}
    )
    endpoint_linux = (
        endpoint_connectors.get("linux", {})
        if isinstance(endpoint_connectors.get("linux", {}), dict)
        else {}
    )
    auth = cfg.get("auth", {}) if isinstance(cfg.get("auth", {}), dict) else {}
    oidc = auth.get("oidc", {}) if isinstance(auth.get("oidc", {}), dict) else {}
    ldap = auth.get("ldap", {}) if isinstance(auth.get("ldap", {}), dict) else {}
    approval_policy = cfg.get("approval_policy", {}) if isinstance(cfg.get("approval_policy", {}), dict) else {}

    commands = active_response.get("commands", [])
    safe_commands = []
    if isinstance(commands, list):
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            safe_commands.append(
                {
                    "id": cmd.get("id") or cmd.get("command"),
                    "label": cmd.get("label"),
                    "description": cmd.get("description"),
                    "command": cmd.get("command"),
                    "category": cmd.get("category", "response"),
                    "risk": cmd.get("risk", "medium"),
                    "custom": bool(cmd.get("custom")),
                    "inputs": [
                        {
                            "name": inp.get("name"),
                            "label": inp.get("label"),
                            "placeholder": inp.get("placeholder"),
                        }
                        for inp in (cmd.get("inputs") or [])
                        if isinstance(inp, dict)
                    ],
                }
            )

    return {
        "wazuh": {
            "url": wazuh.get("url"),
            "verify_ssl": wazuh.get("verify_ssl"),
            "timeout": wazuh.get("timeout"),
        },
        "indexer": {
            "enabled": indexer.get("enabled"),
            "url": indexer.get("url"),
            "verify_ssl": indexer.get("verify_ssl"),
            "timeout": indexer.get("timeout"),
            "alerts_index": indexer.get("alerts_index"),
        },
        "analytics_ingest": {
            "enabled": ingest.get("enabled"),
            "interval_seconds": ingest.get("interval_seconds"),
            "limit": ingest.get("limit"),
            "query": ingest.get("query"),
            "event_driven": {
                "enabled": ingest_event_driven.get("enabled"),
                "worker_interval_seconds": ingest_event_driven.get("worker_interval_seconds"),
                "batch_size": ingest_event_driven.get("batch_size"),
                "max_attempts": ingest_event_driven.get("max_attempts"),
                "retry_base_seconds": ingest_event_driven.get("retry_base_seconds"),
                "retry_max_seconds": ingest_event_driven.get("retry_max_seconds"),
                "lock_timeout_seconds": ingest_event_driven.get("lock_timeout_seconds"),
            },
        },
        "active_response": {
            "enabled": active_response.get("enabled"),
            "commands": safe_commands,
        },
        "orchestration": {
            "mode": orchestration.get("mode"),
            "bulk_max_workers": orchestration.get("bulk_max_workers"),
            "timeout_seconds": orchestration.get("timeout_seconds"),
            "stop_on_error": orchestration.get("stop_on_error"),
            "active_response_fallback_to_endpoint": orchestration.get(
                "active_response_fallback_to_endpoint",
                False,
            ),
        },
        "endpoint_connectors": {
            "windows": {
                "enabled": endpoint_windows.get("enabled"),
                "transport": endpoint_windows.get("transport"),
                "use_https": endpoint_windows.get("use_https"),
                "port": endpoint_windows.get("port"),
                "verify_tls": endpoint_windows.get("verify_tls"),
                "username": endpoint_windows.get("username"),
                "username_env": endpoint_windows.get("username_env"),
                "password": _mask(endpoint_windows.get("password")),
                "password_env": endpoint_windows.get("password_env"),
            },
            "linux": {
                "enabled": endpoint_linux.get("enabled"),
                "port": endpoint_linux.get("port"),
                "username": endpoint_linux.get("username"),
                "username_env": endpoint_linux.get("username_env"),
                "password": _mask(endpoint_linux.get("password")),
                "password_env": endpoint_linux.get("password_env"),
                "key_file": endpoint_linux.get("key_file"),
            },
        },
        "auth": {
            "oidc": {
                "enabled": oidc.get("enabled"),
                "issuer_url": oidc.get("issuer_url"),
                "discovery_url": oidc.get("discovery_url"),
                "client_id": oidc.get("client_id"),
                "client_secret": _mask(oidc.get("client_secret")),
                "redirect_uri": oidc.get("redirect_uri"),
                "frontend_redirect": oidc.get("frontend_redirect"),
            },
            "ldap": {
                "enabled": ldap.get("enabled"),
                "server": ldap.get("server"),
                "base_dn": ldap.get("base_dn"),
                "user_filter": ldap.get("user_filter"),
                "use_ssl": ldap.get("use_ssl"),
                "bind_dn": ldap.get("bind_dn"),
                "bind_password": _mask(ldap.get("bind_password")),
                "default_role": ldap.get("default_role"),
            },
        },
        "approval_policy": approval_policy,
    }


def _normalize_version_label(raw: str | None) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if text.lower() in {"latest", "dev"}:
        return text.lower()
    return text if text.lower().startswith("v") else f"v{text}"


def _org_id_from_user(user: dict | None) -> int:
    if not isinstance(user, dict):
        return 0
    try:
        return int(user.get("org_id") or 0)
    except Exception:
        return 0


def _effective_ai_config_payload(org_id: int) -> dict:
    tenant_cfg = load_active_tenant_ai_config(org_id)
    if tenant_cfg:
        return {
            "source": "tenant_config",
            **to_public_ai_config(tenant_cfg),
        }
    env_cfg = AIAdapter().config
    return {
        "source": "environment",
        **to_public_ai_config(env_cfg),
    }


def _collect_integration_health() -> tuple[dict, dict]:
    manager = WazuhClient().status()
    indexer = IndexerClient().status()
    ingest_gateway = IngestGatewayClient()

    if ingest_gateway.enabled:
        try:
            queue_response = ingest_gateway.list_ingestion_queue(
                params={"limit": 1, "offset": 0, "include_payload": False}
            )
            queue_summary = queue_response.get("data", queue_response)
            ingestion_worker = queue_summary.get("worker") or {"enabled": True, "running": True}
        except Exception:
            queue_summary = {"status_counts": {}, "total": 0}
            ingestion_worker = {"enabled": False, "running": False}
    else:
        queue_summary = {"status_counts": {}, "total": 0}
        ingestion_worker = {"enabled": False, "running": False}

    integration = {
        "wazuh_manager": manager,
        "indexer": indexer,
        "ingestion_worker": ingestion_worker,
    }
    return integration, queue_summary


def _get_cached_integration_health() -> tuple[dict, dict]:
    now = time.time()
    with _overview_health_cache_lock:
        expires_at = float(_overview_health_cache.get("expires_at") or 0.0)
        cached_integration = _overview_health_cache.get("integration")
        cached_queue_summary = _overview_health_cache.get("queue_summary")
        if (
            cached_integration is not None
            and cached_queue_summary is not None
            and now < expires_at
        ):
            return dict(cached_integration), dict(cached_queue_summary)

    integration, queue_summary = _collect_integration_health()

    with _overview_health_cache_lock:
        _overview_health_cache["integration"] = dict(integration)
        _overview_health_cache["queue_summary"] = dict(queue_summary)
        _overview_health_cache["expires_at"] = now + _OVERVIEW_HEALTH_CACHE_TTL_SECONDS

    return integration, queue_summary


@router.get("/version")
def system_version():
    candidates = [
        os.getenv("C2F_IMAGE_TAG"),
        os.getenv("APP_VERSION"),
        os.getenv("CLICK2FIX_VERSION"),
        os.getenv("VITE_APP_VERSION"),
    ]
    version = next((v for v in (_normalize_version_label(x) for x in candidates) if v), "")
    if not version:
        version = _normalize_version_label(os.getenv("IMAGE_TAG")) or "dev"
    return {"version": version, "source": "env"}


@router.get("/ai-config")
def get_system_ai_config(user=Depends(require_role("admin"))):
    org_id = _org_id_from_user(user if isinstance(user, dict) else None)
    return {
        "org_id": org_id,
        "ai_config": _effective_ai_config_payload(org_id),
    }


@router.put("/ai-config")
async def update_system_ai_config(request: Request, user=Depends(require_role("admin"))):
    body: dict = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    payload = body.get("ai_config") if isinstance(body.get("ai_config"), dict) else body
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="ai_config must be an object")

    org_id = _org_id_from_user(user if isinstance(user, dict) else None)
    if org_id < 1:
        raise HTTPException(status_code=400, detail="Tenant scope is required for AI config update")

    existing = load_active_tenant_ai_config(org_id)
    preserve_api_key = bool(body.get("preserve_api_key", True))
    updates = coerce_ai_provider_config(
        payload,
        source_label="system ai config",
        status_code=400,
    )

    if preserve_api_key and (("api_key" not in updates) or not str(updates.get("api_key") or "").strip()):
        if str(existing.get("api_key") or "").strip():
            updates["api_key"] = str(existing.get("api_key") or "").strip()

    merged = dict(existing or {})
    merged.update(updates)
    if "enabled" not in merged:
        merged["enabled"] = bool(existing.get("enabled")) if isinstance(existing, dict) else False
    if bool(merged.get("enabled")) and not str(merged.get("api_key") or "").strip():
        raise HTTPException(status_code=400, detail="api_key is required when AI is enabled")

    actor = str((user or {}).get("sub") or "admin") if isinstance(user, dict) else "admin"
    notes = str(body.get("notes") or "").strip() or "Updated from Org Admin AI configuration"
    saved = upsert_active_tenant_ai_config(
        org_id=org_id,
        actor=actor,
        ai_config=merged,
        notes=notes,
    )
    return {
        "status": "saved",
        "org_id": org_id,
        "ai_config": {
            "source": "tenant_config",
            **to_public_ai_config(saved),
        },
    }


@router.get("/overview")
def overview(user=Depends(require_role("admin"))):
    db = connect()
    try:
        approvals_pending = db.execute(
            text("SELECT COUNT(*) FROM approvals WHERE status='PENDING'")
        ).scalar() or 0
        approvals_review = db.execute(
            text("SELECT COUNT(*) FROM approvals WHERE status='IN_REVIEW'")
        ).scalar() or 0
        executions_total = db.execute(text("SELECT COUNT(*) FROM executions")).scalar() or 0
        cases_total = db.execute(text("SELECT COUNT(*) FROM cases")).scalar() or 0
        alerts_total = db.execute(text("SELECT COUNT(*) FROM alerts_store")).scalar() or 0
        audit_total = db.execute(text("SELECT COUNT(*) FROM audit_logs")).scalar() or 0
        changes_total = db.execute(text("SELECT COUNT(*) FROM change_requests")).scalar() or 0
        changes_open = db.execute(
            text("SELECT COUNT(*) FROM change_requests WHERE status IN ('PROPOSED','APPROVED')")
        ).scalar() or 0
    finally:
        db.close()

    integration, queue_summary = _get_cached_integration_health()

    return {
        "started_at": utc_iso(_started_at),
        "scheduler_running": core_scheduler.running,
        "integration": integration,
        "counts": {
            "approvals_pending": approvals_pending,
            "approvals_in_review": approvals_review,
            "executions_total": executions_total,
            "cases_total": cases_total,
            "alerts_total": alerts_total,
            "audit_total": audit_total,
            "changes_total": changes_total,
            "changes_open": changes_open,
            "ingestion_queue_total": int(queue_summary.get("total") or 0),
            "ingestion_queue_status": queue_summary.get("status_counts") or {},
        },
        "settings": _safe_settings(),
    }


@router.post("/executions/reconcile")
def reconcile_executions(
    timeout_seconds: int = Query(default=300, ge=60, le=3600),
    user=Depends(require_role("admin")),
):
    """Reconcile orphaned executions and cleanup stale records."""
    try:
        result = reconcile_orphan_executions(timeout_seconds=timeout_seconds)
        return {
            "ok": True,
            "message": "Reconciliation completed",
            "result": result
        }
    except Exception:
        return {
            "ok": False,
            "error": "Reconciliation failed"
        }
