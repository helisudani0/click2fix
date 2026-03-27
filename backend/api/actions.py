import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text

try:
    from core.active_defense import action_requires_approval_handshake
except ImportError:  # Backward-compatible fallback for v1.1.x deployments.
    def action_requires_approval_handshake(*_args, **_kwargs):
        return False
from core.actions import ensure_public_action, get_action, list_actions, normalize_args, resolve_action_dispatch
from core.action_capability_resolver import capability_resolver
from core.action_execution import execute_action, orchestration_mode, resolve_agent_ids
from core.audit import log_audit
from core.endpoint_executor import EndpointExecutor
from core.global_shell_ai import (
    enforce_command_safety,
    build_command_assistant_plan,
    next_command_from_failure,
    summarize_failure_from_result,
    vulnerability_matches_record,
)
from core.indexer_client import IndexerClient
from core.launch_guardrails import register_launch, should_emit_burst
from core.security import recent_auth_window_seconds, require_recent_auth, require_role
from core.security_monitoring import record_security_event
from core.time_utils import utc_now_naive
from core.wazuh_client import WazuhClient
from core.ws_bus import publish_event
from db.database import connect

router = APIRouter(prefix="/actions")
client = WazuhClient()
indexer = IndexerClient()
logger = logging.getLogger(__name__)

_FLEET_TARGETS = {"all", "*", "fleet", "all-active"}
_CONNECTED_STATUSES = {"active", "connected", "online"}
_GLOBAL_SHELL_MAX_COMMAND_CHARS = 20000
_GLOBAL_SHELL_MAX_ASSIST_ATTEMPTS = 8
_AI_REMEDIATION_CONFIG_KEY = "ai_remediation"
_ALLOWED_AI_PROVIDERS = {"openai", "gemini"}


def _ps_single_quoted(value: str) -> str:
    raw = str(value or "")
    return "'" + raw.replace("'", "''") + "'"


def _wrap_cmd_for_powershell(raw_command: str) -> str:
    """
    Build a cmd.exe invocation that survives PowerShell parsing.

    We wrap the full command in double-quotes for cmd /c so operators like
    && and || are handled by cmd, not by PowerShell's parser.
    """
    raw = str(raw_command or "").strip()
    if not raw:
        return "cmd.exe /d /s /c \"\""
    normalized = raw.lower()
    if normalized.startswith("cmd ") or normalized.startswith("cmd.exe "):
        # Avoid double-wrapping analyst-provided cmd invocations.
        return raw
    return f"$c={_ps_single_quoted(raw)}; cmd.exe /d /s /c $c"




def _coerce_custom_os_command_arguments(
    arguments: list[str],
    *,
    command: str,
    verify_kb: str = "",
    verify_min_build: str = "",
    verify_stdout_contains: str = "",
    run_as_system: bool = False,
) -> list[str]:
    """
    Enforce the custom-os-command positional schema:
    [command, verify_kb, verify_min_build, verify_stdout_contains, run_as_system]

    This keeps Global Shell stable even if an older container loads a stale action
    schema that does not yet include optional trailing fields.
    """
    existing = [str(v) for v in (arguments or [])]
    command_value = str(command or "").strip()
    if existing:
        existing_cmd = str(existing[0] or "").strip()
        if existing_cmd:
            command_value = existing_cmd

    normalized = [
        command_value,
        str(verify_kb or ""),
        str(verify_min_build or ""),
        str(verify_stdout_contains or ""),
        "true" if bool(run_as_system) else "false",
    ]
    return normalized



def _first_real_agent_id(values) -> str | None:
    for value in values or []:
        raw = str(value or "").strip()
        if not raw:
            continue
        if raw in {"000", "0"}:
            continue
        return raw
    return None


def _extract_items(data):
    if isinstance(data, dict):
        return (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
    if isinstance(data, list):
        return data
    return []


def _agent_status(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    status = agent.get("status")
    if status is None and isinstance(agent.get("agent"), dict):
        status = agent.get("agent", {}).get("status")
    return str(status or "").strip().lower()


def _normalize_agent_identifier(value: str) -> str:
    raw = str(value or "").strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_agent_id_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = [str(part).strip() for part in value]
    else:
        items = [str(value).strip()]

    out = []
    seen = set()
    for item in items:
        norm = _normalize_agent_identifier(item)
        if not norm or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _agent_groups(agent: dict) -> set[str]:
    if not isinstance(agent, dict):
        return set()

    values = []
    for key in ("group", "groups", "group_name"):
        raw = agent.get(key)
        if raw is None:
            continue
        if isinstance(raw, (list, tuple, set)):
            values.extend([str(item).strip() for item in raw if str(item).strip()])
        else:
            text = str(raw).strip()
            if not text:
                continue
            if "," in text:
                values.extend([part.strip() for part in text.split(",") if part.strip()])
            else:
                values.append(text)

    return {str(item).strip().lower() for item in values if str(item).strip()}


def _agent_platform(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    os_node = agent.get("os")
    if isinstance(os_node, dict):
        name = str(
            os_node.get("name")
            or os_node.get("platform")
            or os_node.get("full")
            or ""
        )
    else:
        name = str(agent.get("os_name") or agent.get("os") or "")
    lowered = name.strip().lower()
    if "windows" in lowered:
        return "windows"
    if any(token in lowered for token in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "alpine")):
        return "linux"
    return ""


def _determine_agent_os(
    agent_id: str | None = None,
    group: str | None = None,
    agent_ids: list[str] | None = None,
) -> str:
    if agent_ids:
        first = _first_real_agent_id(agent_ids)
        if first:
            executor = EndpointExecutor(client)
            target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
            platform = str(target.get("platform") or "").strip().lower()
            return "windows" if platform == "windows" else "linux"

    if agent_id:
        agent_val = str(agent_id).strip()
        if agent_val.lower() in _FLEET_TARGETS:
            fleet_ids = client.get_agent_ids()
            first = _first_real_agent_id(fleet_ids)
            if not first:
                raise HTTPException(status_code=404, detail="No agents found in fleet")
            executor = EndpointExecutor(client)
            target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
            platform = str(target.get("platform") or "").strip().lower()
            return "windows" if platform == "windows" else "linux"
        executor = EndpointExecutor(client)
        target = executor._resolve_agent_target(agent_id)  # noqa: SLF001 - internal fallback resolver
        platform = str(target.get("platform") or "").strip().lower()
        return "windows" if platform == "windows" else "linux"

    if not group:
        raise HTTPException(status_code=400, detail="agent_id or group is required")

    agents = client.get_agent_ids(group=group)
    first = _first_real_agent_id(agents)
    if not first:
        raise HTTPException(status_code=404, detail=f"No agents found in group {group}")
    executor = EndpointExecutor(client)
    target = executor._resolve_agent_target(first)  # noqa: SLF001 - internal fallback resolver
    platform = str(target.get("platform") or "").strip().lower()
    return "windows" if platform == "windows" else "linux"


def _to_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _store_execution_targets(conn, execution_id: int, rows) -> None:
    if not execution_id or not rows or not isinstance(rows, list):
        return
    for row in rows:
        if not isinstance(row, dict):
            continue
        conn.execute(
            text(
                """
                INSERT INTO execution_targets
                (execution_id, agent_id, agent_name, target_ip, platform, ok, status_code, stdout, stderr)
                VALUES (:execution_id, :agent_id, :agent_name, :target_ip, :platform, :ok, :status_code, :stdout, :stderr)
                """
            ),
            {
                "execution_id": int(execution_id),
                "agent_id": str(row.get("agent_id") or ""),
                "agent_name": str(row.get("agent_name") or ""),
                "target_ip": str(row.get("target_ip") or row.get("ip") or ""),
                "platform": str(row.get("platform") or ""),
                "ok": bool(row.get("ok")),
                "status_code": int(row.get("status_code") or 0),
                "stdout": _to_text(row.get("stdout")),
                "stderr": _to_text(row.get("stderr")),
            },
        )


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _coerce_assist_attempts(value: Any, default: int = 3) -> int:
    parsed = _to_int(value, default)
    if parsed < 1:
        return 1
    if parsed > _GLOBAL_SHELL_MAX_ASSIST_ATTEMPTS:
        return _GLOBAL_SHELL_MAX_ASSIST_ATTEMPTS
    return parsed


def _coerce_vulnerability_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {}
    for key in (
        "id",
        "cve",
        "title",
        "severity",
        "package_name",
        "condition",
        "verify_kb",
        "verify_min_build",
    ):
        raw = value.get(key)
        if raw is None:
            continue
        text = str(raw).strip()
        if text:
            out[key] = text

    package = value.get("package")
    if isinstance(package, dict):
        package_name = str(package.get("name") or "").strip()
        if package_name and "package_name" not in out:
            out["package_name"] = package_name
        package_condition = str(package.get("condition") or "").strip()
        if package_condition and "condition" not in out:
            out["condition"] = package_condition

    references = value.get("references")
    if isinstance(references, list):
        refs = [str(item).strip() for item in references if str(item).strip()]
        if refs:
            out["references"] = refs[:20]
    elif references is not None:
        text = str(references).strip()
        if text:
            out["references"] = [text]

    agent_ids = _normalize_agent_id_list(value.get("agent_ids") or value.get("affected_agent_ids"))
    if agent_ids:
        out["agent_ids"] = agent_ids
    return out


def _coerce_ai_provider_config(value: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    source_label = "request body" if source == "request" else "tenant ai_remediation config"
    status_code = 400 if source == "request" else 503
    out: dict[str, Any] = {}
    provider = str(value.get("provider") or "").strip().lower()
    if provider:
        if provider not in _ALLOWED_AI_PROVIDERS:
            raise HTTPException(status_code=status_code, detail=f"Unsupported AI provider '{provider}' in {source_label}")
        out["provider"] = provider
    for key in ("base_url", "model", "api_key"):
        if key not in value:
            continue
        out[key] = str(value.get(key) or "").strip()
    if "enabled" in value:
        out["enabled"] = _to_bool(value.get("enabled"), True)
    if "timeout_seconds" in value:
        timeout_seconds = _to_int(value.get("timeout_seconds"), -1)
        if timeout_seconds < 1:
            raise HTTPException(status_code=status_code, detail=f"timeout_seconds in {source_label} must be >= 1")
        out["timeout_seconds"] = timeout_seconds
    if "max_tokens" in value:
        max_tokens = _to_int(value.get("max_tokens"), -1)
        if max_tokens < 1:
            raise HTTPException(status_code=status_code, detail=f"max_tokens in {source_label} must be >= 1")
        out["max_tokens"] = max_tokens
    if "temperature" in value:
        try:
            temperature = float(value.get("temperature"))
        except Exception as exc:
            raise HTTPException(status_code=status_code, detail=f"temperature in {source_label} must be a number") from exc
        if temperature < 0 or temperature > 2:
            raise HTTPException(status_code=status_code, detail=f"temperature in {source_label} must be between 0 and 2")
        out["temperature"] = temperature
    return out


def _coerce_ai_shorthand_config(body: dict[str, Any]) -> dict[str, Any]:
    mapping = {
        "ai_provider": "provider",
        "ai_base_url": "base_url",
        "ai_model": "model",
        "ai_api_key": "api_key",
        "ai_timeout_seconds": "timeout_seconds",
        "ai_temperature": "temperature",
        "ai_max_tokens": "max_tokens",
        "ai_enabled": "enabled",
    }
    out: dict[str, Any] = {}
    for source_key, target_key in mapping.items():
        if source_key not in body:
            continue
        out[target_key] = body.get(source_key)
    return out


def _extract_ai_config_node(node: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    if isinstance(node.get("ai_config"), dict):
        return node.get("ai_config") or {}
    if isinstance(node.get("ai_remediation"), dict):
        return node.get("ai_remediation") or {}
    if any(key in node for key in ("provider", "base_url", "model", "api_key", "timeout_seconds", "temperature", "max_tokens", "enabled")):
        return node
    return {}


def _load_active_tenant_ai_config(org_id: Any) -> dict[str, Any]:
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
            {"tenant_id": tenant_id, "config_key": _AI_REMEDIATION_CONFIG_KEY},
        ).fetchone()
    except Exception as exc:
        logger.warning(
            "Tenant AI config lookup unavailable for org_id=%s; using env/request fallback (%s)",
            tenant_id,
            exc.__class__.__name__,
        )
        return {}
    finally:
        try:
            db.close()
        except Exception:
            pass
    if not row:
        return {}
    raw_json = row._mapping.get("config_json") if hasattr(row, "_mapping") else (row[0] if isinstance(row, (tuple, list)) and row else row)
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
        return _coerce_ai_provider_config(parsed, source="tenant")
    except HTTPException as exc:
        logger.warning(
            "Ignoring invalid tenant ai_remediation config for org_id=%s: %s",
            tenant_id,
            exc.detail,
        )
        return {}


def _resolve_ai_provider_config(*, body: dict[str, Any], user: Any) -> dict[str, Any] | None:
    if "ai_config" in body and body.get("ai_config") is not None and not isinstance(body.get("ai_config"), dict):
        raise HTTPException(status_code=400, detail="ai_config must be a JSON object")
    request_cfg = _coerce_ai_provider_config(body.get("ai_config"), source="request")
    if request_cfg:
        return request_cfg
    shorthand_cfg = _coerce_ai_provider_config(_coerce_ai_shorthand_config(body), source="request")
    if shorthand_cfg:
        return shorthand_cfg
    tenant_cfg = _load_active_tenant_ai_config((user or {}).get("org_id") if isinstance(user, dict) else None)
    return tenant_cfg or None


def _build_global_shell_dispatch(
    *,
    command_to_run: str,
    run_as_system: bool,
    verify_kb: str,
    verify_min_build: str,
    verify_stdout_contains: str,
) -> tuple[dict[str, Any], list[str]]:
    transport_action_id = "custom-os-command"
    action = get_action(transport_action_id)
    arguments = _coerce_custom_os_command_arguments(
        normalize_args(
            action,
            {
                "command": command_to_run,
                "verify_kb": verify_kb,
                "verify_min_build": verify_min_build,
                "verify_stdout_contains": verify_stdout_contains,
                "run_as_system": "true" if bool(run_as_system) else "false",
            },
        ),
        command=command_to_run,
        verify_kb=verify_kb,
        verify_min_build=verify_min_build,
        verify_stdout_contains=verify_stdout_contains,
        run_as_system=bool(run_as_system),
    )
    dispatch = resolve_action_dispatch(action, arguments)
    return dispatch, arguments


def _result_rows_ok(payload: Any) -> bool:
    result = payload if isinstance(payload, dict) else {}
    rows = result.get("results")
    if isinstance(rows, list) and rows:
        return all(bool(row.get("ok")) for row in rows if isinstance(row, dict))
    failed = _to_int(result.get("failed"), 0)
    if failed > 0:
        return False
    if "ok" in result:
        return bool(result.get("ok"))
    return False


def _result_rows_status(payload: Any) -> str:
    result = payload if isinstance(payload, dict) else {}
    total = _to_int(result.get("total"), 0)
    success = _to_int(result.get("success"), 0)
    failed = _to_int(result.get("failed"), 0)
    if total > 0 and success > 0 and failed > 0:
        return "PARTIAL"
    if total > 0 and success > 0 and failed == 0:
        return "SUCCESS"
    return "FAILED"


def _result_rows_counts(rows: Any, *, fallback_total: int = 0) -> dict[str, int]:
    valid_rows = [row for row in (rows or []) if isinstance(row, dict)]
    success = sum(1 for row in valid_rows if row.get("ok"))
    failed = sum(1 for row in valid_rows if not row.get("ok"))
    completed = len(valid_rows)
    total = max(int(fallback_total or 0), completed)
    return {
        "total": total,
        "completed": completed,
        "success": success,
        "failed": failed,
    }


def _check_vulnerability_clearance(
    *,
    vulnerability_context: dict[str, Any],
    selected_ids: list[str],
) -> dict[str, Any]:
    scoped = _normalize_agent_id_list(selected_ids)
    if not vulnerability_context or not scoped:
        return {"checked": False, "reason": "missing_context_or_targets"}
    if not indexer.enabled:
        return {"checked": False, "reason": "indexer_disabled"}
    try:
        raw = indexer.search_vulnerabilities_fleet(limit=10000, agent_ids=scoped)
        rows = indexer.extract_vulnerabilities(raw)
    except Exception as exc:
        return {"checked": False, "reason": "indexer_error", "error": _to_text(exc)}

    matches = [
        row
        for row in rows
        if isinstance(row, dict) and vulnerability_matches_record(row, vulnerability_context, scoped)
    ]
    return {
        "checked": True,
        "cleared": len(matches) == 0,
        "remaining_count": len(matches),
    }


def _run_global_shell_async_job(
    execution_id: int,
    action_id: str,
    shell: str,
    selected_ids: list[str],
    raw_command: str,
    run_as_system: bool,
    verify_kb: str = "",
    verify_min_build: str = "",
    verify_stdout_contains: str = "",
    assistant_plan: dict[str, Any] | None = None,
    auto_remediate: bool = False,
    max_attempts: int = 1,
    vulnerability_context: dict[str, Any] | None = None,
    ai_config: dict[str, Any] | None = None,
    allow_destructive: bool = False,
) -> None:
    db = connect()
    execution = None
    target_rows = None
    step_name = "orchestration"
    step_stdout = ""
    step_stderr = ""
    execution_status = "FAILED"
    step_status = "FAILED"
    current_raw_command = str(raw_command or "").strip()
    current_run_as_system = bool(run_as_system)
    current_verify_kb = str(verify_kb or "").strip()
    current_verify_min_build = str(verify_min_build or "").strip()
    current_verify_stdout_contains = str(verify_stdout_contains or "").strip()
    attempts_budget = _coerce_assist_attempts(max_attempts, 1 if not auto_remediate else 3)
    used_commands: list[str] = []
    attempt_records: list[dict[str, Any]] = []
    last_failure = ""
    final_result_payload: dict[str, Any] = {}
    effective_context = _coerce_vulnerability_context(vulnerability_context)
    incremental_rows_persisted = False
    batch_size = max(1, min(len(selected_ids), 20))
    if not auto_remediate:
        attempts_budget = 1

    if not current_raw_command and isinstance(assistant_plan, dict):
        rec = assistant_plan.get("recommended")
        if isinstance(rec, dict):
            current_raw_command = str(rec.get("command") or "").strip()
            current_run_as_system = bool(current_run_as_system or rec.get("run_as_system"))
            if not current_verify_kb:
                current_verify_kb = str(rec.get("verify_kb") or "").strip()
            if not current_verify_min_build:
                current_verify_min_build = str(rec.get("verify_min_build") or "").strip()

    try:
        def _batch_progress_callback(progress: dict[str, Any]) -> None:
            nonlocal incremental_rows_persisted
            rows = progress.get("rows") if isinstance(progress, dict) else []
            if rows:
                _store_execution_targets(db, int(execution_id), rows)
                incremental_rows_persisted = True
            db.execute(
                text(
                    """
                    UPDATE executions
                    SET
                        status=:status,
                        target_total=:target_total,
                        target_completed=:target_completed,
                        target_success=:target_success,
                        target_failed=:target_failed,
                        batch_size=:batch_size
                    WHERE id=:id
                    """
                ),
                {
                    "status": "PARTIAL",
                    "target_total": int(progress.get("total") or len(selected_ids)),
                    "target_completed": int(progress.get("completed") or 0),
                    "target_success": int(progress.get("success") or 0),
                    "target_failed": int(progress.get("failed") or 0),
                    "batch_size": batch_size,
                    "id": execution_id,
                },
            )
            db.commit()

        db.execute(
            text("UPDATE executions SET status=:status WHERE id=:id"),
            {"status": "RUNNING", "id": execution_id},
        )
        db.commit()
        publish_event(
            int(execution_id),
            {
                "type": "execution_started",
                "step": "orchestration",
                "status": "RUNNING",
                "stdout": f"action={action_id}; targets={len(selected_ids)}",
                "stderr": "",
            },
        )

        for attempt_no in range(1, attempts_budget + 1):
            if not current_raw_command:
                last_failure = "No command available for this attempt"
                break
            if len(current_raw_command) > _GLOBAL_SHELL_MAX_COMMAND_CHARS:
                last_failure = f"command exceeds {_GLOBAL_SHELL_MAX_COMMAND_CHARS} characters"
                attempt_records.append(
                    {
                        "attempt": attempt_no,
                        "command": current_raw_command,
                        "command_used": "",
                        "run_as_system": bool(current_run_as_system),
                        "verify_kb": current_verify_kb,
                        "verify_min_build": current_verify_min_build,
                        "verify_stdout_contains": current_verify_stdout_contains,
                        "risk_score": 100,
                        "risk_reasons": ["Command length limit exceeded"],
                        "ok": False,
                        "failure": last_failure,
                        "vulnerability_check": {"checked": False, "reason": "not_executed"},
                    }
                )
                break
            try:
                safety = enforce_command_safety(
                    current_raw_command,
                    shell=shell,
                    allow_destructive=allow_destructive,
                )
            except HTTPException as exc:
                last_failure = _to_text(exc.detail or exc)
                attempt_records.append(
                    {
                        "attempt": attempt_no,
                        "command": current_raw_command,
                        "command_used": "",
                        "run_as_system": bool(current_run_as_system),
                        "verify_kb": current_verify_kb,
                        "verify_min_build": current_verify_min_build,
                        "verify_stdout_contains": current_verify_stdout_contains,
                        "risk_score": 100,
                        "risk_reasons": ["Blocked by safety guard"],
                        "ok": False,
                        "failure": last_failure,
                        "vulnerability_check": {"checked": False, "reason": "blocked"},
                    }
                )
                break
            used_commands.append(current_raw_command)
            command_to_run = current_raw_command
            if str(shell or "").strip().lower() == "cmd":
                command_to_run = _wrap_cmd_for_powershell(current_raw_command)
            dispatch, _ = _build_global_shell_dispatch(
                command_to_run=command_to_run,
                run_as_system=current_run_as_system,
                verify_kb=current_verify_kb,
                verify_min_build=current_verify_min_build,
                verify_stdout_contains=current_verify_stdout_contains,
            )

            publish_event(
                int(execution_id),
                {
                    "type": "step_start",
                    "step": f"orchestration:attempt-{attempt_no}",
                    "status": "RUNNING",
                    "stdout": f"attempt={attempt_no}; command={current_raw_command}",
                    "stderr": "",
                },
            )

            attempt_ok = False
            failure_summary = ""
            vuln_check: dict[str, Any] = {"checked": False, "reason": "not_requested"}
            result_payload: dict[str, Any] = {}
            result_status = "FAILED"
            try:
                execution = execute_action(
                    client,
                    action_id,
                    dispatch,
                    selected_ids,
                    execution_id=int(execution_id),
                    context={"_batch_progress_callback": _batch_progress_callback},
                )
                step_name = execution.get("channel") or "orchestration"
                result_payload = execution.get("result") if isinstance(execution.get("result"), dict) else {}
                final_result_payload = result_payload
                if isinstance(result_payload.get("results"), list):
                    target_rows = result_payload.get("results")
                result_status = _result_rows_status(result_payload)
                attempt_ok = _result_rows_ok(result_payload)
                if not attempt_ok:
                    failure_summary = summarize_failure_from_result(result_payload) or "Execution returned target failures."
            except HTTPException as exc:
                step_name = "endpoint" if isinstance(exc.detail, dict) else "orchestration"
                if isinstance(exc.detail, dict):
                    failure_summary = _to_text(exc.detail.get("message") or exc.detail)
                    result_obj = exc.detail.get("result")
                    result_payload = result_obj if isinstance(result_obj, dict) else {}
                    if isinstance(result_payload.get("results"), list):
                        target_rows = result_payload.get("results")
                    final_result_payload = result_payload or final_result_payload
                else:
                    failure_summary = _to_text(exc.detail)
            except Exception as exc:
                step_name = "orchestration"
                failure_summary = _to_text(exc)

            if attempt_ok and effective_context:
                vuln_check = _check_vulnerability_clearance(
                    vulnerability_context=effective_context,
                    selected_ids=selected_ids,
                )
                if vuln_check.get("checked") and not vuln_check.get("cleared"):
                    remaining = _to_int(vuln_check.get("remaining_count"), 0)
                    attempt_ok = False
                    failure_summary = (
                        f"Command executed but vulnerability still present for {remaining} target(s) in indexer."
                    )
            elif not effective_context:
                vuln_check = {"checked": False, "reason": "no_vulnerability_context"}

            attempt_record = {
                "attempt": attempt_no,
                "command": current_raw_command,
                "command_used": command_to_run,
                "run_as_system": bool(current_run_as_system),
                "verify_kb": current_verify_kb,
                "verify_min_build": current_verify_min_build,
                "verify_stdout_contains": current_verify_stdout_contains,
                "risk_score": _to_int(safety.get("risk_score"), 0),
                "risk_reasons": safety.get("reasons") or [],
                "ok": bool(attempt_ok),
                "failure": failure_summary,
                "vulnerability_check": vuln_check,
                "result_summary": {
                    "success": _to_int(result_payload.get("success"), 0),
                    "failed": _to_int(result_payload.get("failed"), 0),
                    "total": _to_int(result_payload.get("total"), 0),
                },
            }
            attempt_records.append(attempt_record)

            db.execute(
                text(
                    """
                    INSERT INTO execution_steps
                    (execution_id, step, stdout, stderr, status)
                    VALUES (:execution_id, :step, :stdout, :stderr, :status)
                    """
                ),
                {
                    "execution_id": execution_id,
                    "step": f"orchestration_attempt_{attempt_no}",
                    "stdout": json.dumps(attempt_record, default=str),
                    "stderr": "" if attempt_ok else failure_summary,
                    "status": "SUCCESS" if attempt_ok else "FAILED",
                },
            )
            db.commit()

            publish_event(
                int(execution_id),
                {
                    "type": "step_done" if attempt_ok or result_status == "PARTIAL" else "step_failed",
                    "step": f"orchestration:attempt-{attempt_no}",
                    "status": "SUCCESS" if attempt_ok else result_status,
                    "stdout": json.dumps(attempt_record.get("result_summary"), default=str),
                    "stderr": "" if attempt_ok else failure_summary,
                },
            )

            if attempt_ok:
                execution_status = "SUCCESS"
                step_status = "SUCCESS"
                last_failure = ""
                break

            if result_status == "PARTIAL":
                execution_status = "PARTIAL"
                step_status = "PARTIAL"

            last_failure = failure_summary or "Execution attempt failed."
            if attempt_no >= attempts_budget:
                break

            next_attempt = next_command_from_failure(
                plan=assistant_plan or {},
                used_commands=used_commands,
                failure_text=last_failure,
                current_run_as_system=current_run_as_system,
                shell=shell,
                execution_result=result_payload,
                allow_destructive=allow_destructive,
                ai_config=ai_config,
            )
            if not next_attempt:
                break

            next_command = str(next_attempt.get("command") or "").strip()
            if not next_command:
                break
            current_raw_command = next_command
            current_run_as_system = bool(next_attempt.get("run_as_system", current_run_as_system))
            next_verify_kb = str(next_attempt.get("verify_kb") or "").strip()
            next_verify_min_build = str(next_attempt.get("verify_min_build") or "").strip()
            next_verify_stdout = str(next_attempt.get("verify_stdout_contains") or "").strip()
            if next_verify_kb:
                current_verify_kb = next_verify_kb
            if next_verify_min_build:
                current_verify_min_build = next_verify_min_build
            if next_verify_stdout:
                current_verify_stdout_contains = next_verify_stdout

        if execution_status == "PARTIAL":
            step_status = "PARTIAL"
            step_stderr = last_failure or "Global shell remediation completed with partial target success."
        elif execution_status != "SUCCESS":
            step_status = "FAILED"
            step_stderr = last_failure or "Global shell remediation did not complete successfully."
        detail_payload = {
            "attempts": attempt_records,
            "final_result": final_result_payload,
            "auto_remediate": bool(auto_remediate),
            "max_attempts": attempts_budget,
        }
        step_stdout = json.dumps(detail_payload, default=str)

        db.execute(
            text(
                """
                INSERT INTO execution_steps
                (execution_id, step, stdout, stderr, status)
                VALUES (:execution_id, :step, :stdout, :stderr, :status)
                """
            ),
            {
                "execution_id": execution_id,
                "step": "orchestration",
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )
        current_status = db.execute(
            text("SELECT status FROM executions WHERE id=:id"),
            {"id": execution_id},
        ).scalar()
        current_upper = str(current_status or "").strip().upper()
        if current_upper in {"KILLED", "CANCELLED"}:
            execution_status = current_upper
        counts = _result_rows_counts(target_rows, fallback_total=len(selected_ids))
        db.execute(
            text(
                """
                UPDATE executions
                SET
                    status=:status,
                    finished_at=COALESCE(finished_at, :finished_at),
                    target_total=:target_total,
                    target_completed=:target_completed,
                    target_success=:target_success,
                    target_failed=:target_failed,
                    batch_size=:batch_size
                WHERE id=:id
                """
            ),
            {
                "status": execution_status,
                "finished_at": utc_now_naive(),
                "target_total": counts["total"],
                "target_completed": counts["completed"],
                "target_success": counts["success"],
                "target_failed": counts["failed"],
                "batch_size": batch_size,
                "id": execution_id,
            },
        )
        if target_rows and not incremental_rows_persisted:
            _store_execution_targets(db, int(execution_id), target_rows)
        db.commit()

        publish_event(
            int(execution_id),
            {
                "type": "execution_finished",
                "step": step_name,
                "status": execution_status,
                "stdout": "",
                "stderr": step_stderr if step_status == "FAILED" else "",
            },
        )
    finally:
        db.close()


@router.get("")
def actions(user=Depends(require_role("analyst"))):
    return list_actions()


@router.get("/connector-status")
def connector_status(user=Depends(require_role("admin"))):
    executor = EndpointExecutor(client)
    return {
        "orchestration_mode": orchestration_mode(),
        "connectors": executor.connector_status(),
    }


@router.get("/capabilities/{action_id}")
def action_capabilities(action_id: str, user=Depends(require_role("analyst"))):
    """Get capabilities for a specific action."""
    try:
        action_id = ensure_public_action(action_id)
        capabilities = capability_resolver.get_action_capability_summary(action_id)
        return {
            "action_id": action_id,
            "capabilities": capabilities
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get capabilities: {str(e)}")


@router.post("/validate")
async def validate_action(request: Request, user=Depends(require_role("analyst"))):
    """Validate action prerequisites before execution."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    action_id = body.get("action_id")
    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    args = body.get("args", [])

    if not action_id:
        raise HTTPException(status_code=400, detail="action_id is required")
    action_id = ensure_public_action(action_id)

    try:
        agent_os = _determine_agent_os(agent_id=agent_id, group=group, agent_ids=agent_ids)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent information: {str(e)}")

    # Get connector status
    executor = EndpointExecutor(client)
    connector_status = executor.connector_status()
    if agent_os == "windows":
        probe_agent = str(agent_id or "").strip()
        if probe_agent.lower() in _FLEET_TARGETS:
            probe_agent = ""
        if not probe_agent and agent_ids:
            probe_agent = str(_first_real_agent_id(agent_ids) or "").strip()
        if not probe_agent and group:
            group_ids = client.get_agent_ids(group=group)
            probe_agent = str(_first_real_agent_id(group_ids) or "").strip()
        connector_status.setdefault("connectors", {}).setdefault("windows", {})[
            "credentials_configured"
        ] = executor.has_windows_credentials(probe_agent or None)
    elif agent_os == "linux":
        connector_status.setdefault("connectors", {}).setdefault("linux", {})[
            "credentials_configured"
        ] = bool(
            connector_status.get("connectors", {})
            .get("linux", {})
            .get("credentials_configured", False)
        )

    action = get_action(action_id)
    normalized_args = normalize_args(action, args)

    # Validate prerequisites using normalized positional args (matches action.inputs ordering).
    is_valid, errors = capability_resolver.validate_action_prerequisites(
        action_id, agent_os, normalized_args, connector_status
    )

    # Get preferred channel
    preferred_channel = capability_resolver.resolve_preferred_channel(
        action_id, agent_os, connector_status
    )

    # Get timeout
    timeout_seconds = capability_resolver.get_timeout_seconds(action_id)

    return {
        "action_id": action_id,
        "agent_id": agent_id,
        "agent_os": agent_os,
        "is_valid": is_valid,
        "errors": errors,
        "preferred_channel": preferred_channel,
        "timeout_seconds": timeout_seconds,
        "connector_status": connector_status
    }


@router.post("/test-capability")
async def test_action_capability(request: Request, user=Depends(require_role("admin"))):
    """Test action capability with validation and execution."""
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    action_id = body.get("action_id") or "endpoint-healthcheck"
    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []
    args = body.get("args", [])

    if not agent_id and not group and not agent_ids:
        raise HTTPException(status_code=400, detail="agent_id, agent_ids or group is required")
    action_id = ensure_public_action(action_id)

    try:
        agent_os = _determine_agent_os(agent_id=agent_id, group=group, agent_ids=agent_ids)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get agent information: {str(e)}")

    # Get connector status
    executor = EndpointExecutor(client)
    connector_status = executor.connector_status()
    if agent_os == "windows":
        probe_agent = str(agent_id or "").strip()
        if probe_agent.lower() in _FLEET_TARGETS:
            probe_agent = ""
        if not probe_agent and agent_ids:
            probe_agent = str(_first_real_agent_id(agent_ids) or "").strip()
        if not probe_agent and group:
            group_ids = client.get_agent_ids(group=group)
            probe_agent = str(_first_real_agent_id(group_ids) or "").strip()
        connector_status.setdefault("connectors", {}).setdefault("windows", {})[
            "credentials_configured"
        ] = executor.has_windows_credentials(probe_agent or None)

    action = get_action(action_id)
    normalized_args = normalize_args(action, args)

    # Validate prerequisites using normalized positional args (matches action.inputs ordering).
    is_valid, validation_errors = capability_resolver.validate_action_prerequisites(
        action_id, agent_os, normalized_args, connector_status
    )

    result = {
        "action_id": action_id,
        "agent_id": agent_id,
        "agent_os": agent_os,
        "validation_passed": is_valid,
        "validation_errors": validation_errors,
        "preferred_channel": capability_resolver.resolve_preferred_channel(action_id, agent_os, connector_status),
        "timeout_seconds": capability_resolver.get_timeout_seconds(action_id),
        "connector_status": connector_status
    }

    # If validation passes, attempt execution
    if is_valid:
        try:
            arguments = normalized_args
            dispatch = resolve_action_dispatch(action, arguments)

            resolved_agent_ids = []
            if agent_ids:
                resolved_agent_ids = [str(a).strip() for a in agent_ids if str(a).strip()]
            else:
                resolved_agent_ids = resolve_agent_ids(client, target=agent_id, group=group)
            if exclude_agent_ids:
                exclude_norm = {str(a).strip() for a in exclude_agent_ids if str(a).strip()}
                resolved_agent_ids = [
                    aid for aid in resolved_agent_ids if str(aid).strip() not in exclude_norm
                ]
            if not resolved_agent_ids:
                raise HTTPException(status_code=404, detail="No agents resolved for target")

            execution = execute_action(client, action_id, dispatch, resolved_agent_ids)
            
            result.update({
                "execution_status": "success",
                "execution_channel": execution.get("channel"),
                "execution_mode": execution.get("mode"),
                "execution_result": execution.get("result"),
                "resolved_agents": resolved_agent_ids,
            })
            
            log_audit(
                "action_capability_tested",
                actor=user.get("sub"),
                entity_type="action",
                entity_id=action_id,
                detail=f"target={group or agent_id}; channel={execution.get('channel')}; validation_passed=true",
                org_id=user.get("org_id"),
                ip_address=request.client.host if request.client else None,
            )
            
        except Exception as e:
            result.update({
                "execution_status": "failed",
                "execution_error": str(e)
            })
            
            log_audit(
                "action_capability_test_failed",
                actor=user.get("sub"),
                entity_type="action",
                entity_id=action_id,
                detail=f"target={group or agent_id}; validation_passed=true; execution_error={str(e)}",
                org_id=user.get("org_id"),
                ip_address=request.client.host if request.client else None,
            )
    else:
        log_audit(
            "action_capability_test_failed",
            actor=user.get("sub"),
            entity_type="action",
            entity_id=action_id,
            detail=f"target={group or agent_id}; validation_passed=false; errors={','.join(validation_errors)}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )

    return result


@router.post("/test")
async def test_action_path(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    target = body.get("agent_id")
    group = body.get("group")
    action_id = body.get("action_id") or "endpoint-healthcheck"

    if not target and not group:
        raise HTTPException(status_code=400, detail="agent_id or group is required")
    action_id = ensure_public_action(action_id)

    action = get_action(action_id)
    dispatch = resolve_action_dispatch(action, [])
    agent_ids = resolve_agent_ids(client, target=target, group=group)
    execution = execute_action(client, action_id, dispatch, agent_ids)

    log_audit(
        "action_tested",
        actor=user.get("sub"),
        entity_type="action",
        entity_id=action_id,
        detail=f"target={group or target}; agents={len(agent_ids)}; mode={execution.get('mode')}",
        org_id=user.get("org_id"),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "ok",
        "action_id": action_id,
        "target": group or target,
        "agents": agent_ids,
        "channel": execution.get("channel"),
        "mode": execution.get("mode"),
        "command_used": execution.get("command_used"),
        "attempts": execution.get("attempts"),
        "result": execution.get("result"),
    }


@router.post("/run")
async def run_action(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []
    action_id = body.get("action_id")
    args = body.get("args")

    if not action_id or (not agent_id and not group and not agent_ids):
        raise HTTPException(status_code=400, detail="action_id and agent_id, agent_ids, or group are required")
    action_id = ensure_public_action(action_id)

    action = get_action(action_id)
    arguments = normalize_args(action, args)
    dispatch = resolve_action_dispatch(action, arguments)
    if agent_ids:
        resolved_agent_ids = _normalize_agent_id_list(agent_ids)
    else:
        resolved_agent_ids = resolve_agent_ids(client, target=agent_id, group=group)
    if exclude_agent_ids:
        exclude_norm = {str(a).strip() for a in exclude_agent_ids if str(a).strip()}
        resolved_agent_ids = [
            aid for aid in resolved_agent_ids if str(aid).strip() not in exclude_norm
        ]
    if not resolved_agent_ids:
        raise HTTPException(status_code=404, detail="No agents resolved for target")
    if action_requires_approval_handshake(
        action_id,
        target_count=len(resolved_agent_ids),
        context={"tenant_id": user.get("org_id")},
    ):
        from api.approvals import create_approval_request_record

        approval = create_approval_request_record(
            request=request,
            user=user,
            agent_ids=resolved_agent_ids,
            action_id=action_id,
            args=args,
            justification=body.get("justification") or body.get("reason"),
            incident_priority=body.get("incident_priority") or body.get("priority"),
            incident_score=body.get("incident_score") or body.get("score"),
        )
        return {
            "status": "pending_approval",
            "approval_id": approval.get("approval_id") or approval.get("id"),
            "approval": approval,
            "result": None,
        }
    execution = execute_action(client, action_id, dispatch, resolved_agent_ids)

    if group:
        target_label = f"group:{group}"
    elif agent_ids:
        target_label = "multi:" + ",".join(resolved_agent_ids)
    else:
        target_label = str(agent_id or "")
    log_audit(
        "action_executed",
        actor=user.get("sub"),
        entity_type="action",
        entity_id=action_id,
        detail=f"target={target_label}; channel={execution.get('channel')}; targets={len(resolved_agent_ids)}",
        org_id=user.get("org_id"),
        ip_address=request.client.host if request.client else None,
    )

    return {
        "status": "executed",
        "channel": execution.get("channel"),
        "mode": execution.get("mode"),
        "command_used": execution.get("command_used"),
        "attempts": execution.get("attempts"),
        "result": execution.get("result"),
    }


@router.post("/global-shell/assist")
async def global_shell_assist(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    shell = str(body.get("shell") or "powershell").strip().lower()
    if shell not in {"powershell", "cmd"}:
        raise HTTPException(status_code=400, detail="shell must be 'powershell' or 'cmd'")
    prompt = str(body.get("prompt") or body.get("assistant_prompt") or "").strip()
    scoped_agent_ids = _normalize_agent_id_list(body.get("agent_ids") or body.get("agents"))
    single_agent = _normalize_agent_identifier(body.get("agent_id") or "")
    if single_agent:
        scoped_agent_ids = _normalize_agent_id_list([*scoped_agent_ids, single_agent])
    allow_destructive = _to_bool(body.get("allow_destructive"), False)
    vulnerability_context = _coerce_vulnerability_context(
        body.get("vulnerability_context") or body.get("vulnerability")
    )
    ai_config = _resolve_ai_provider_config(body=body if isinstance(body, dict) else {}, user=user)
    if not prompt and not vulnerability_context:
        raise HTTPException(
            status_code=400,
            detail="prompt or vulnerability_context is required",
        )

    plan = build_command_assistant_plan(
        prompt=prompt,
        shell=shell,
        vulnerability_context=vulnerability_context,
        scoped_agent_ids=scoped_agent_ids,
        allow_destructive=allow_destructive,
        ai_config=ai_config,
    )
    if isinstance(plan, dict):
        plan = dict(plan)
        plan.pop("session_id", None)
    recommended = plan.get("recommended")
    if not isinstance(recommended, dict) or not str(recommended.get("command") or "").strip():
        raise HTTPException(
            status_code=422,
            detail="No safe command candidate could be inferred from prompt/context",
        )
    return {
        "ok": True,
        "shell": shell,
        "plan": plan,
        "recommended": recommended,
        "candidate_count": len(plan.get("candidates") or []),
    }


@router.post("/global-shell")
async def run_global_shell(request: Request, user=Depends(require_role("admin"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    shell = str(body.get("shell") or "powershell").strip().lower()
    if shell not in {"powershell", "cmd"}:
        logger.warning("global-shell rejected: invalid shell=%s", shell)
        raise HTTPException(status_code=400, detail="shell must be 'powershell' or 'cmd'")
    async_raw = body.get("async")
    async_mode = True if async_raw is None else _to_bool(async_raw, True)

    assistant_prompt = str(body.get("assistant_prompt") or body.get("prompt") or "").strip()
    vulnerability_context = _coerce_vulnerability_context(
        body.get("vulnerability_context") or body.get("vulnerability")
    )
    effective_context = dict(vulnerability_context or {})
    allow_destructive = _to_bool(body.get("allow_destructive"), False)
    auto_remediate = _to_bool(body.get("auto_remediate"), False)
    max_attempts = _coerce_assist_attempts(
        body.get("max_attempts"),
        3 if auto_remediate else 1,
    )
    raw_command = str(body.get("command") or "").strip()
    ai_config = _resolve_ai_provider_config(body=body if isinstance(body, dict) else {}, user=user)

    run_as_system_explicit = body.get("run_as_system")
    run_as_system = _to_bool(run_as_system_explicit, False)
    raw_justification = str(body.get("justification") or body.get("reason") or "").strip()
    justification_provided = len(raw_justification) >= 12
    justification = (
        raw_justification
        if justification_provided
        else "Global shell execution requested by analyst."
    )

    verify_kb = str(body.get("verify_kb") or "").strip()
    verify_min_build = str(body.get("verify_min_build") or "").strip()
    verify_stdout_contains = str(body.get("verify_stdout_contains") or "").strip()

    target_agent_id = _normalize_agent_identifier(body.get("agent_id") or "")
    target_group = str(body.get("group") or "").strip()
    target_group_key = target_group.lower()
    target_agent_ids = _normalize_agent_id_list(body.get("agent_ids") or body.get("agents"))
    if target_agent_ids:
        target_mode = "multi"
    elif target_group:
        target_mode = "group"
    elif target_agent_id and target_agent_id.lower() not in _FLEET_TARGETS:
        target_mode = "agent"
    else:
        target_mode = "fleet"

    requested_set = set(target_agent_ids)
    if target_mode == "agent" and target_agent_id:
        requested_set.add(target_agent_id)

    exclude_set = set(_normalize_agent_id_list(body.get("exclude_agent_ids") or body.get("exclude_agents")))

    agents_data = client.get_agents(use_cache=True)
    agents = [item for item in _extract_items(agents_data) if isinstance(item, dict)]
    connected_total = 0
    connected_windows = 0
    skipped_non_windows = 0
    excluded_count = 0
    selected_ids = []
    seen = set()

    for agent in agents:
        agent_id = _normalize_agent_identifier(agent.get("id") or agent.get("agent_id") or "")
        if not agent_id or agent_id in {"000", "0"}:
            continue

        in_scope = False
        if target_mode == "fleet":
            in_scope = True
        elif target_mode == "group":
            in_scope = bool(target_group_key and target_group_key in _agent_groups(agent))
        elif target_mode == "multi":
            in_scope = agent_id in requested_set
        else:
            in_scope = bool(target_agent_id and agent_id == target_agent_id)
        if not in_scope:
            continue

        status = _agent_status(agent)
        if status not in _CONNECTED_STATUSES:
            continue
        connected_total += 1

        platform = _agent_platform(agent)
        if platform != "windows":
            skipped_non_windows += 1
            continue
        connected_windows += 1

        if agent_id in exclude_set:
            excluded_count += 1
            continue
        if agent_id in seen:
            continue
        seen.add(agent_id)
        selected_ids.append(agent_id)

    if not selected_ids:
        detail = "No connected Windows agents available after filtering"
        if target_mode == "agent":
            detail = "Requested agent is not connected as a Windows endpoint or was excluded"
        elif target_mode == "multi":
            detail = "No requested agents are connected Windows endpoints after exclusions"
        elif target_mode == "group":
            detail = f"No connected Windows agents found in group '{target_group}' after exclusions"
        raise HTTPException(
            status_code=404,
            detail=detail,
        )

    assistant_plan: dict[str, Any] = {}
    assistant_recommended: dict[str, Any] = {}
    assistant_generated_command = False
    assistant_plan_error = ""

    should_build_plan = bool(assistant_prompt or effective_context) or not raw_command
    if should_build_plan:
        planning_prompt = assistant_prompt
        if not planning_prompt:
            planning_prompt = (
                "Remediate this vulnerability safely using the shortest viable command."
                if effective_context
                else "Generate the safest shortest viable command for this task."
            )
        try:
            planned = build_command_assistant_plan(
                prompt=planning_prompt,
                shell=shell,
                vulnerability_context=effective_context,
                scoped_agent_ids=selected_ids,
                allow_destructive=allow_destructive,
                ai_config=ai_config,
            )
            if isinstance(planned, dict):
                assistant_plan = dict(planned)
                assistant_plan.pop("session_id", None)
                recommended = planned.get("recommended")
                if isinstance(recommended, dict):
                    assistant_recommended = recommended
        except HTTPException as exc:
            if not raw_command:
                raise
            assistant_plan_error = _to_text(exc.detail or exc)
        except Exception as exc:
            if not raw_command:
                raise HTTPException(status_code=503, detail=f"AI planning failed: {_to_text(exc)}")
            assistant_plan_error = _to_text(exc)

    if not raw_command:
        recommended_command = str(assistant_recommended.get("command") or "").strip()
        if not recommended_command:
            raise HTTPException(
                status_code=422,
                detail="No safe command candidate could be inferred from prompt/context",
            )
        raw_command = recommended_command
        assistant_generated_command = True
        if run_as_system_explicit is None:
            run_as_system = _to_bool(assistant_recommended.get("run_as_system"), run_as_system)
        if not verify_kb:
            verify_kb = str(assistant_recommended.get("verify_kb") or "").strip()
        if not verify_min_build:
            verify_min_build = str(assistant_recommended.get("verify_min_build") or "").strip()
        if not verify_stdout_contains:
            verify_stdout_contains = str(assistant_recommended.get("verify_stdout_contains") or "").strip()

    if not raw_command:
        raise HTTPException(status_code=400, detail="command is required")
    if len(raw_command) > _GLOBAL_SHELL_MAX_COMMAND_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"command exceeds {_GLOBAL_SHELL_MAX_COMMAND_CHARS} characters",
        )

    try:
        initial_safety = enforce_command_safety(
            raw_command,
            shell=shell,
            allow_destructive=allow_destructive,
        )
    except HTTPException as exc:
        record_security_event(
            "execution.global_shell_blocked",
            severity="warning",
            request=request,
            user=user if isinstance(user, dict) else None,
            detail=str(exc.detail),
            metadata={
                "shell": shell,
                "target_mode": target_mode,
                "target_count": len(selected_ids),
                "run_as_system": bool(run_as_system),
            },
        )
        raise

    command_to_run = raw_command
    if shell == "cmd":
        command_to_run = _wrap_cmd_for_powershell(raw_command)

    effective_run_as_system = bool(run_as_system)
    execution_action_id = "global-shell"
    transport_action_id = "custom-os-command"
    _, arguments = _build_global_shell_dispatch(
        command_to_run=command_to_run,
        run_as_system=effective_run_as_system,
        verify_kb=verify_kb,
        verify_min_build=verify_min_build,
        verify_stdout_contains=verify_stdout_contains,
    )
    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None
    initial_risk_score = _to_int(initial_safety.get("risk_score"), 0)

    if effective_run_as_system or len(selected_ids) >= 25:
        require_recent_auth(
            user,
            request,
            max_age_seconds=recent_auth_window_seconds("global_shell", 3600),
            action_label="high-impact Global Shell execution",
        )

    if initial_risk_score >= 60 or effective_run_as_system or len(selected_ids) >= 25:
        record_security_event(
            "execution.global_shell_launch",
            severity="warning" if (initial_risk_score >= 80 or effective_run_as_system or len(selected_ids) >= 25) else "info",
            request=request,
            user=user if isinstance(user, dict) else None,
            detail="Global Shell launch requested",
            metadata={
                "shell": shell,
                "target_mode": target_mode,
                "target_count": len(selected_ids),
                "run_as_system": bool(effective_run_as_system),
                "risk_score": initial_risk_score,
                "assistant_used": bool(assistant_plan),
                "auto_remediate": bool(auto_remediate),
            },
        )
        if effective_run_as_system or len(selected_ids) >= 25 or initial_risk_score >= 80:
            recent_high_impact = register_launch(
                "execution.global_shell_launch",
                actor=actor,
                window_seconds=900,
            )
        else:
            recent_high_impact = 0
        if should_emit_burst(recent_high_impact):
            record_security_event(
                "execution.global_shell_burst",
                severity="warning",
                request=request,
                user=user if isinstance(user, dict) else None,
                detail="Repeated high-impact Global Shell launches detected",
                metadata={
                    "target_count": len(selected_ids),
                    "run_as_system": bool(effective_run_as_system),
                    "risk_score": initial_risk_score,
                    "recent_count": recent_high_impact,
                    "window_seconds": 900,
                },
            )

    assistant_meta = {
        "used": bool(assistant_plan),
        "prompt": assistant_prompt,
        "generated_command": bool(assistant_generated_command),
        "auto_remediate": bool(auto_remediate),
        "max_attempts": int(max_attempts),
        "recommended": assistant_recommended if assistant_recommended else None,
        "candidate_count": len(assistant_plan.get("candidates") or []) if isinstance(assistant_plan, dict) else 0,
        "risk_score": _to_int(initial_safety.get("risk_score"), 0),
        "risk_reasons": initial_safety.get("reasons") or [],
        "allow_destructive": bool(allow_destructive),
    }
    if assistant_plan_error:
        assistant_meta["error"] = assistant_plan_error

    global_shell_high_impact = bool(
        effective_run_as_system
        or len(selected_ids) >= 25
        or initial_risk_score >= 70
    )
    if global_shell_high_impact and action_requires_approval_handshake(
        transport_action_id,
        target_count=len(selected_ids),
        context={
            "tenant_id": org_id,
            "run_as_system": bool(effective_run_as_system),
            "high_impact": bool(initial_risk_score >= 80),
        },
    ):
        from api.approvals import create_approval_request_record

        approval = create_approval_request_record(
            request=request,
            user=user,
            agent_ids=selected_ids,
            action_id=transport_action_id,
            args={
                "command": command_to_run,
                "verify_kb": verify_kb,
                "verify_min_build": verify_min_build,
                "verify_stdout_contains": verify_stdout_contains,
                "run_as_system": effective_run_as_system,
            },
            justification=justification or "Global shell execution requires explicit approval",
            incident_priority=body.get("incident_priority") or body.get("priority"),
            incident_score=body.get("incident_score") or body.get("score"),
        )
        return {
            "status": "pending_approval",
            "action_id": execution_action_id,
            "transport_action_id": transport_action_id,
            "command": raw_command,
            "command_used": command_to_run,
            "run_as_system": effective_run_as_system,
            "agent_ids": selected_ids,
            "approval_id": approval.get("approval_id") or approval.get("id"),
            "approval": approval,
            "assistant": assistant_meta,
        }

    if async_mode:
        db = connect()
        try:
            started_at = utc_now_naive()
            target = "multi:" + ",".join(selected_ids)
            inserted = db.execute(
                text(
                    """
                    INSERT INTO executions
                    (approval_id, agent, playbook, action, args, status, approved_by, started_at, alert_id, org_id,
                     target_total, target_completed, target_success, target_failed, batch_size)
                    VALUES (:approval_id, :agent, :playbook, :action, :args, :status, :approved_by, :started_at, :alert_id, :org_id,
                            :target_total, :target_completed, :target_success, :target_failed, :batch_size)
                    RETURNING id
                    """
                ),
                {
                    "approval_id": None,
                    "agent": target,
                    "playbook": execution_action_id,
                    "action": execution_action_id,
                    "args": json.dumps(arguments, default=str),
                    "status": "QUEUED",
                    "approved_by": actor,
                    "started_at": started_at,
                    "alert_id": None,
                    "org_id": org_id,
                    "target_total": len(selected_ids),
                    "target_completed": 0,
                    "target_success": 0,
                    "target_failed": 0,
                    "batch_size": max(1, min(len(selected_ids), 20)),
                },
            )
            execution_id = int(inserted.scalar())
            if justification:
                db.execute(
                    text(
                        """
                        INSERT INTO execution_metadata (execution_id, justification)
                        VALUES (:execution_id, :justification)
                        """
                    ),
                    {"execution_id": execution_id, "justification": justification},
                )
            db.commit()
        finally:
            db.close()

        worker = threading.Thread(
            target=_run_global_shell_async_job,
            args=(
                execution_id,
                execution_action_id,
                shell,
                selected_ids,
                raw_command,
                effective_run_as_system,
                verify_kb,
                verify_min_build,
                verify_stdout_contains,
                assistant_plan if isinstance(assistant_plan, dict) else {},
                bool(auto_remediate),
                int(max_attempts),
                effective_context,
                ai_config if isinstance(ai_config, dict) else None,
                bool(allow_destructive),
            ),
            daemon=True,
        )
        worker.start()

        summary = {
            "target_mode": target_mode,
            "requested_agents": len(requested_set) if requested_set else None,
            "connected_agents_seen": connected_total,
            "connected_windows_seen": connected_windows,
            "targeted_agents": len(selected_ids),
            "excluded_agents": excluded_count,
            "skipped_non_windows": skipped_non_windows,
            "success": 0,
            "failed": 0,
        }

        log_audit(
            "global_shell_queued",
            actor=actor,
            entity_type="execution",
            entity_id=str(execution_id),
            detail=(
                f"shell={shell}; targeted={summary['targeted_agents']}; "
                f"target_mode={target_mode}; "
                f"connected_seen={summary['connected_agents_seen']}; "
                f"skipped_non_windows={summary['skipped_non_windows']}; "
                f"run_as_system={'yes' if effective_run_as_system else 'no'}; "
                f"assistant_used={'yes' if assistant_meta['used'] else 'no'}; "
                f"auto_remediate={'yes' if auto_remediate else 'no'}; "
                f"justification_provided={'yes' if justification_provided else 'no'}"
            ),
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )

        return {
            "status": "queued",
            "action_id": execution_action_id,
            "transport_action_id": transport_action_id,
            "shell": shell,
            "command": raw_command,
            "command_used": command_to_run,
            "run_as_system": effective_run_as_system,
            "execution_id": execution_id,
            "agent_ids": selected_ids,
            "summary": summary,
            "justification_provided": bool(justification_provided),
            "history_available": True,
            "assistant": assistant_meta,
        }

    attempts_budget = _coerce_assist_attempts(max_attempts, 1 if not auto_remediate else 3)
    if not auto_remediate:
        attempts_budget = 1

    used_commands: list[str] = []
    attempt_records: list[dict[str, Any]] = []
    current_raw_command = raw_command
    current_run_as_system = effective_run_as_system
    current_verify_kb = verify_kb
    current_verify_min_build = verify_min_build
    current_verify_stdout_contains = verify_stdout_contains
    last_execution = None
    last_result: dict[str, Any] = {}
    last_failure = ""

    for attempt_no in range(1, attempts_budget + 1):
        if len(current_raw_command) > _GLOBAL_SHELL_MAX_COMMAND_CHARS:
            last_failure = f"command exceeds {_GLOBAL_SHELL_MAX_COMMAND_CHARS} characters"
            attempt_records.append(
                {
                    "attempt": attempt_no,
                    "command": current_raw_command,
                    "command_used": "",
                    "run_as_system": bool(current_run_as_system),
                    "verify_kb": current_verify_kb,
                    "verify_min_build": current_verify_min_build,
                    "verify_stdout_contains": current_verify_stdout_contains,
                    "risk_score": 100,
                    "risk_reasons": ["Command length limit exceeded"],
                    "ok": False,
                    "failure": last_failure,
                    "vulnerability_check": {"checked": False, "reason": "not_executed"},
                }
            )
            break

        try:
            attempt_safety = enforce_command_safety(
                current_raw_command,
                shell=shell,
                allow_destructive=allow_destructive,
            )
            risk_score = _to_int(attempt_safety.get("risk_score"), 0)
            risk_reasons = attempt_safety.get("reasons") or []
        except HTTPException as exc:
            last_failure = _to_text(exc.detail or exc)
            attempt_records.append(
                {
                    "attempt": attempt_no,
                    "command": current_raw_command,
                    "command_used": "",
                    "run_as_system": bool(current_run_as_system),
                    "verify_kb": current_verify_kb,
                    "verify_min_build": current_verify_min_build,
                    "verify_stdout_contains": current_verify_stdout_contains,
                    "risk_score": 100,
                    "risk_reasons": ["Blocked by safety guard"],
                    "ok": False,
                    "failure": last_failure,
                    "vulnerability_check": {"checked": False, "reason": "blocked"},
                }
            )
            break

        used_commands.append(current_raw_command)
        current_command_used = (
            current_raw_command if shell == "powershell" else _wrap_cmd_for_powershell(current_raw_command)
        )
        attempt_dispatch, _ = _build_global_shell_dispatch(
            command_to_run=current_command_used,
            run_as_system=current_run_as_system,
            verify_kb=current_verify_kb,
            verify_min_build=current_verify_min_build,
            verify_stdout_contains=current_verify_stdout_contains,
        )
        attempt_ok = False
        failure = ""
        vuln_check: dict[str, Any] = {"checked": False, "reason": "not_requested"}
        try:
            last_execution = execute_action(client, execution_action_id, attempt_dispatch, selected_ids)
            last_result = last_execution.get("result") if isinstance(last_execution.get("result"), dict) else {}
            attempt_ok = _result_rows_ok(last_result)
            if not attempt_ok:
                failure = summarize_failure_from_result(last_result) or "Execution returned target failures."
        except HTTPException as exc:
            if isinstance(exc.detail, dict):
                last_result = exc.detail.get("result") if isinstance(exc.detail.get("result"), dict) else {}
                failure = _to_text(exc.detail.get("message") or exc.detail)
            else:
                failure = _to_text(exc.detail)
        except Exception as exc:
            failure = _to_text(exc)

        if attempt_ok and effective_context:
            vuln_check = _check_vulnerability_clearance(
                vulnerability_context=effective_context,
                selected_ids=selected_ids,
            )
            if vuln_check.get("checked") and not vuln_check.get("cleared"):
                remain = _to_int(vuln_check.get("remaining_count"), 0)
                attempt_ok = False
                failure = f"Command executed but vulnerability is still present for {remain} target(s)."
        elif not effective_context:
            vuln_check = {"checked": False, "reason": "no_vulnerability_context"}

        attempt_records.append(
            {
                "attempt": attempt_no,
                "command": current_raw_command,
                "command_used": current_command_used,
                "run_as_system": bool(current_run_as_system),
                "verify_kb": current_verify_kb,
                "verify_min_build": current_verify_min_build,
                "verify_stdout_contains": current_verify_stdout_contains,
                "risk_score": risk_score,
                "risk_reasons": risk_reasons,
                "ok": bool(attempt_ok),
                "failure": failure,
                "vulnerability_check": vuln_check,
                "result_summary": {
                    "success": _to_int(last_result.get("success"), 0),
                    "failed": _to_int(last_result.get("failed"), 0),
                    "total": _to_int(last_result.get("total"), 0),
                },
            }
        )
        if attempt_ok:
            last_failure = ""
            break

        last_failure = failure or "Execution attempt failed."
        if attempt_no >= attempts_budget:
            break

        next_attempt = next_command_from_failure(
            plan=assistant_plan or {},
            used_commands=used_commands,
            failure_text=last_failure,
            current_run_as_system=current_run_as_system,
            shell=shell,
            execution_result=last_result,
            allow_destructive=allow_destructive,
            ai_config=ai_config,
        )
        if not next_attempt:
            break
        next_command = str(next_attempt.get("command") or "").strip()
        if not next_command:
            break
        current_raw_command = next_command
        current_run_as_system = bool(next_attempt.get("run_as_system", current_run_as_system))
        next_verify_kb = str(next_attempt.get("verify_kb") or "").strip()
        next_verify_min_build = str(next_attempt.get("verify_min_build") or "").strip()
        next_verify_stdout = str(next_attempt.get("verify_stdout_contains") or "").strip()
        if next_verify_kb:
            current_verify_kb = next_verify_kb
        if next_verify_min_build:
            current_verify_min_build = next_verify_min_build
        if next_verify_stdout:
            current_verify_stdout_contains = next_verify_stdout

    summary = {
        "target_mode": target_mode,
        "requested_agents": len(requested_set) if requested_set else None,
        "connected_agents_seen": connected_total,
        "connected_windows_seen": connected_windows,
        "targeted_agents": len(selected_ids),
        "excluded_agents": excluded_count,
        "skipped_non_windows": skipped_non_windows,
        "success": int(last_result.get("success") or 0) if isinstance(last_result, dict) else 0,
        "failed": int(last_result.get("failed") or 0) if isinstance(last_result, dict) else len(selected_ids),
    }
    ok = bool(attempt_records and attempt_records[-1].get("ok"))
    return {
        "status": "executed" if ok else "executed_with_failures",
        "action_id": execution_action_id,
        "transport_action_id": transport_action_id,
        "shell": shell,
        "command": raw_command,
        "command_used": attempt_records[-1].get("command_used") if attempt_records else command_to_run,
        "run_as_system": effective_run_as_system,
        "channel": last_execution.get("channel") if isinstance(last_execution, dict) else "endpoint",
        "mode": last_execution.get("mode") if isinstance(last_execution, dict) else "endpoint",
        "attempts": [row.get("command") for row in attempt_records if row.get("command")],
        "agent_ids": selected_ids,
        "summary": summary,
        "justification_provided": bool(justification_provided),
        "result": last_result if isinstance(last_result, dict) else {"ok": False},
        "assistant": {
            **assistant_meta,
            "attempt_records": attempt_records,
            "failure": last_failure,
        },
    }
