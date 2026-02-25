from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from core.indexer_client import IndexerClient
from core.scheduler import scheduler as core_scheduler
from core.security import require_role
from core.settings import SETTINGS
from core.time_utils import utc_iso, utc_now
from core.wazuh_client import WazuhClient
from core.execution_reconciler import reconcile_orphan_executions
from db.database import connect


router = APIRouter(prefix="/system")
_started_at = utc_now()


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
            "active_response_fallback_to_endpoint": orchestration.get("active_response_fallback_to_endpoint"),
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

    manager = WazuhClient().status()
    indexer = IndexerClient().status()

    return {
        "started_at": utc_iso(_started_at),
        "scheduler_running": core_scheduler.running,
        "integration": {
            "wazuh_manager": manager,
            "indexer": indexer,
        },
        "counts": {
            "approvals_pending": approvals_pending,
            "approvals_in_review": approvals_review,
            "executions_total": executions_total,
            "cases_total": cases_total,
            "alerts_total": alerts_total,
            "audit_total": audit_total,
            "changes_total": changes_total,
            "changes_open": changes_open,
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
