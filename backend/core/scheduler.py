from __future__ import annotations

import json
import logging
import os
import shlex
import threading
import uuid
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException
from sqlalchemy import text

from core.actions import get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.audit import log_audit
from core.distributed_leases import acquire_or_renew_lease, release_lease
from core.ingest_gateway_client import IngestGatewayClient
from core.forensic_integrity import run_integrity_sweep
from core.indexer_client import IndexerClient
from core.settings import SETTINGS
from core.time_utils import serialize_row, utc_now_naive
from core.wazuh_client import WazuhClient
from db.database import connect

APSCHEDULER_AVAILABLE = True
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
except Exception:
    APSCHEDULER_AVAILABLE = False

    class CronTrigger:  # type: ignore[override]
        def __init__(self, expression: str, timezone: str = "UTC"):
            self.expression = str(expression)
            self.timezone = timezone

        @classmethod
        def from_crontab(cls, expression: str, timezone: str = "UTC"):
            parts = str(expression or "").strip().split()
            if len(parts) != 5:
                raise ValueError("Cron expression must contain 5 fields")
            return cls(expression, timezone=timezone)

    class _FallbackJob:
        def __init__(self, job_id: str):
            self.id = str(job_id)

    class BackgroundScheduler:  # type: ignore[override]
        def __init__(self, timezone: str = "UTC"):
            self.timezone = timezone
            self.running = False
            self._jobs: Dict[str, _FallbackJob] = {}

        def add_job(self, func, *args, **kwargs):
            job_id = str(kwargs.get("id") or f"job_{len(self._jobs) + 1}")
            replace_existing = bool(kwargs.get("replace_existing", False))
            if job_id in self._jobs and not replace_existing:
                raise ValueError(f"Job already exists: {job_id}")
            self._jobs[job_id] = _FallbackJob(job_id)
            return self._jobs[job_id]

        def remove_job(self, job_id: str):
            self._jobs.pop(str(job_id), None)

        def get_job(self, job_id: str):
            return self._jobs.get(str(job_id))

        def get_jobs(self):
            return list(self._jobs.values())

        def start(self):
            self.running = True

        def shutdown(self, wait: bool = False):
            self.running = False

logger = logging.getLogger(__name__)
if not APSCHEDULER_AVAILABLE:
    logger.warning(
        "apscheduler is not installed; scheduler runs in compatibility mode without timed execution"
    )

scheduler = BackgroundScheduler(timezone="UTC")

_SCHED_JOB_PREFIX = "scheduled_job_"
_HEALTHCHECK_POLICY_NAME = "Fleet Health-Check Policy"
_HEALTHCHECK_ACTION_ID = "endpoint-healthcheck"
_INTEGRITY_SWEEP_POLICY_NAME = "Evidence Integrity Sweep Policy"
_INTEGRITY_SWEEP_ACTION_ID = "integrity-sweep"
_DEFAULT_POLICY_CRON = "0 */6 * * *"
_ALLOWED_SCHEDULE_JOB_KINDS = {"action", "shell", "playbook"}
_SUPPORTED_SHELLS = {"powershell", "cmd", "bash", "sh"}

_ingest_cfg = SETTINGS.get("analytics_ingest", {}) if isinstance(SETTINGS, dict) else {}
INGEST_ENABLED = bool(_ingest_cfg.get("enabled", True))
INGEST_INTERVAL = max(60, int(_ingest_cfg.get("interval_seconds", 300)))
INGEST_LIMIT = max(10, min(1000, int(_ingest_cfg.get("limit", 200))))
INGEST_QUERY = _ingest_cfg.get("query")

_ingest_client = WazuhClient()
_ingest_indexer = IndexerClient()
_ingest_gateway = IngestGatewayClient()
_scheduler_client = WazuhClient()

_integrity_cfg = (
    SETTINGS.get("forensics_integrity", {})
    if isinstance(SETTINGS, dict) and isinstance(SETTINGS.get("forensics_integrity", {}), dict)
    else {}
)
_integrity_sweep_cfg = (
    _integrity_cfg.get("sweep", {})
    if isinstance(_integrity_cfg.get("sweep", {}), dict)
    else {}
)
INTEGRITY_SWEEP_ENABLED = bool(_integrity_sweep_cfg.get("enabled", True))
INTEGRITY_SWEEP_CRON = str(_integrity_sweep_cfg.get("cron", "0 2 * * *"))
INTEGRITY_SWEEP_MAX_ITEMS = max(1, int(_integrity_sweep_cfg.get("max_items", 2000)))

_scheduler_policy_cfg = (
    SETTINGS.get("scheduler_policy", {})
    if isinstance(SETTINGS, dict) and isinstance(SETTINGS.get("scheduler_policy", {}), dict)
    else {}
)
AUTO_CREATE_HEALTHCHECK_POLICY = bool(_scheduler_policy_cfg.get("auto_create", True))
HEALTHCHECK_POLICY_INTERVAL_HOURS = max(6, min(12, int(_scheduler_policy_cfg.get("interval_hours", 6))))

_scheduler_initialized = False
_scheduler_leadership_thread: threading.Thread | None = None
_scheduler_leadership_stop = threading.Event()
_scheduler_leadership_lock = threading.Lock()
_scheduler_has_leadership = False
_SCHEDULER_LEASE_NAME = str(os.getenv("C2F_SCHEDULER_LEASE_NAME", "backend.scheduler")).strip() or "backend.scheduler"
_SCHEDULER_OWNER_ID = str(os.getenv("C2F_SCHEDULER_OWNER_ID", f"scheduler-{uuid.uuid4().hex[:10]}")).strip()
_SCHEDULER_LEASE_TTL_SECONDS = max(15, int(os.getenv("C2F_SCHEDULER_LEASE_TTL_SECONDS", "45")))
_SCHEDULER_RENEW_SECONDS = max(
    5,
    min(
        int(os.getenv("C2F_SCHEDULER_LEASE_RENEW_SECONDS", "15")),
        max(5, _SCHEDULER_LEASE_TTL_SECONDS - 5),
    ),
)


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


INTEGRITY_SWEEP_ENABLED = _to_bool(_integrity_sweep_cfg.get("enabled", True), True)
AUTO_CREATE_HEALTHCHECK_POLICY = _to_bool(
    _scheduler_policy_cfg.get("auto_create", True),
    True,
)


def _job_runtime_id(job_id: int) -> str:
    return f"{_SCHED_JOB_PREFIX}{int(job_id)}"


def _parse_cron(cron_expr: str) -> CronTrigger:
    expr = str(cron_expr or "").strip()
    if not expr:
        expr = _DEFAULT_POLICY_CRON
    return CronTrigger.from_crontab(expr, timezone="UTC")


def _normalize_job_kind(value: Any, *, default: str = "action") -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        raw = str(default or "action").strip().lower()
    if raw not in _ALLOWED_SCHEDULE_JOB_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"job_kind must be one of {sorted(_ALLOWED_SCHEDULE_JOB_KINDS)}",
        )
    return raw


def _parse_payload_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if value is None:
        return {}
    if isinstance(value, str):
        text_value = str(value).strip()
        if not text_value:
            return {}
        try:
            parsed = json.loads(text_value)
        except Exception:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _to_payload_json(value: Any) -> str | None:
    payload = _parse_payload_json(value)
    if not payload:
        return None
    return json.dumps(payload, default=str)


def _ps_single_quoted(value: str) -> str:
    raw = str(value or "")
    return "'" + raw.replace("'", "''") + "'"


def _wrap_cmd_for_powershell(raw_command: str) -> str:
    raw = str(raw_command or "").strip()
    if not raw:
        return "cmd.exe /d /s /c \"\""
    lowered = raw.lower()
    if lowered.startswith("cmd ") or lowered.startswith("cmd.exe "):
        return raw
    return f"$c={_ps_single_quoted(raw)}; cmd.exe /d /s /c $c"


def _wrap_linux_shell_command(raw_command: str, *, shell: str) -> str:
    raw = str(raw_command or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if shell == "bash":
        if lowered.startswith("bash ") or lowered.startswith("/bin/bash "):
            return raw
        return f"bash -lc {shlex.quote(raw)}"
    if shell == "sh":
        if lowered.startswith("sh ") or lowered.startswith("/bin/sh "):
            return raw
        return f"sh -lc {shlex.quote(raw)}"
    return raw


def _prepare_shell_command(raw_command: str, shell: str) -> str:
    normalized_shell = str(shell or "").strip().lower()
    if normalized_shell == "cmd":
        return _wrap_cmd_for_powershell(raw_command)
    if normalized_shell in {"bash", "sh"}:
        return _wrap_linux_shell_command(raw_command, shell=normalized_shell)
    return str(raw_command or "").strip()


def _coerce_custom_command_arguments(
    arguments: list[str],
    *,
    command: str,
    verify_kb: str = "",
    verify_min_build: str = "",
    verify_stdout_contains: str = "",
    run_as_system: bool = False,
) -> list[str]:
    existing = [str(v) for v in (arguments or [])]
    command_value = str(command or "").strip()
    if existing:
        first = str(existing[0] or "").strip()
        if first:
            command_value = first
    return [
        command_value,
        str(verify_kb or ""),
        str(verify_min_build or ""),
        str(verify_stdout_contains or ""),
        "true" if bool(run_as_system) else "false",
    ]


def _build_shell_dispatch(payload: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    shell = str(payload.get("shell") or "powershell").strip().lower()
    if shell not in _SUPPORTED_SHELLS:
        raise HTTPException(
            status_code=400,
            detail=f"shell must be one of {sorted(_SUPPORTED_SHELLS)}",
        )
    raw_command = str(
        payload.get("command")
        or payload.get("shell_command")
        or payload.get("script")
        or ""
    ).strip()
    if not raw_command:
        raise HTTPException(status_code=400, detail="shell jobs require payload.command")
    run_as_system = _to_bool(payload.get("run_as_system"), False)
    verify_kb = str(payload.get("verify_kb") or "").strip()
    verify_min_build = str(payload.get("verify_min_build") or "").strip()
    verify_stdout_contains = str(payload.get("verify_stdout_contains") or "").strip()
    command_to_run = _prepare_shell_command(raw_command, shell)

    action = get_action("custom-os-command")
    arguments = _coerce_custom_command_arguments(
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
        run_as_system=run_as_system,
    )
    dispatch = resolve_action_dispatch(action, arguments)
    return raw_command, dispatch


def _normalize_playbook_steps(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    steps = payload.get("steps") if isinstance(payload, dict) else None
    if not isinstance(steps, list):
        return []
    out: List[Dict[str, Any]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        step_id = str(step.get("id") or f"step_{index + 1}").strip() or f"step_{index + 1}"
        action_id = str(step.get("action") or step.get("command") or "").strip()
        if not action_id:
            raise HTTPException(status_code=400, detail=f"Playbook step '{step_id}' has no action")
        if action_id.lower() == "global-shell":
            action_id = "custom-os-command"
        raw_args = step.get("args")
        if raw_args is None:
            raw_args = {}
        if not isinstance(raw_args, (dict, list, str)):
            raise HTTPException(status_code=400, detail=f"Playbook step '{step_id}' args are invalid")
        out.append(
            {
                "id": step_id,
                "action": action_id,
                "args": raw_args,
                "reason": str(step.get("reason") or "Scheduled playbook step").strip() or "Scheduled playbook step",
            }
        )
    return out


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _store_execution_targets(conn, execution_id: int, rows: Iterable[Dict[str, Any]]) -> None:
    for row in rows or []:
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
                "ok": _to_bool(row.get("ok"), False),
                "status_code": int(row.get("status_code") or 0),
                "stdout": _to_text(row.get("stdout")),
                "stderr": _to_text(row.get("stderr")),
            },
        )


def _result_counts(payload: Dict[str, Any] | None, target_rows: List[Dict[str, Any]]) -> Dict[str, int]:
    rows = [row for row in (target_rows or []) if isinstance(row, dict)]
    row_total = len(rows)
    row_success = sum(1 for row in rows if _to_bool(row.get("ok"), False))
    row_failed = row_total - row_success

    payload_node = payload if isinstance(payload, dict) else {}
    payload_total = _to_int(payload_node.get("total"), 0)
    payload_success = _to_int(payload_node.get("success"), 0)
    payload_failed = _to_int(payload_node.get("failed"), 0)
    payload_completed = _to_int(payload_node.get("completed"), payload_success + payload_failed)

    total = max(row_total, payload_total, payload_completed)
    success = max(row_success, payload_success)
    failed = max(row_failed, payload_failed)
    completed = max(row_total, payload_completed, success + failed)
    total = max(total, completed)
    return {
        "total": max(0, int(total)),
        "completed": max(0, int(completed)),
        "success": max(0, int(success)),
        "failed": max(0, int(failed)),
    }


def _result_status(payload: Dict[str, Any] | None, target_rows: List[Dict[str, Any]]) -> str:
    payload_node = payload if isinstance(payload, dict) else {}
    explicit = str(payload_node.get("overall_status") or payload_node.get("status") or "").strip().upper()
    if explicit in {"SUCCESS", "FAILED", "PARTIAL"}:
        return explicit

    counts = _result_counts(payload_node, target_rows)
    total = int(counts.get("total") or 0)
    success = int(counts.get("success") or 0)
    failed = int(counts.get("failed") or 0)
    if total > 0 and success > 0 and failed > 0:
        return "PARTIAL"
    if total > 0 and failed == 0 and success > 0:
        return "SUCCESS"
    if total > 0 and failed > 0 and success == 0:
        return "FAILED"
    if "ok" in payload_node:
        return "SUCCESS" if _to_bool(payload_node.get("ok"), False) else "FAILED"
    return "FAILED"


def ingest_alerts():
    if not INGEST_ENABLED:
        return

    alerts = []
    if _ingest_indexer.enabled:
        try:
            data = _ingest_indexer.search_alerts(limit=INGEST_LIMIT, query=INGEST_QUERY)
            alerts = _ingest_indexer.extract_alerts(data)
        except Exception as exc:
            logger.warning("Analytics ingest: indexer unavailable (%s)", exc)
            alerts = []

    if not alerts:
        try:
            raw_alerts = _ingest_client.get_alerts(INGEST_LIMIT)
        except Exception as exc:
            logger.warning("Analytics ingest: manager unavailable (%s)", exc)
            return

        alerts = raw_alerts
        if isinstance(raw_alerts, dict):
            alerts = (
                raw_alerts.get("data", {}).get("affected_items")
                or raw_alerts.get("affected_items")
                or raw_alerts.get("items")
                or []
            )
        if not isinstance(alerts, list):
            alerts = []

    if alerts:
        try:
            if _ingest_gateway.enabled:
                _ingest_gateway.ingest_wazuh_alerts(
                    {
                        "tenant_id": None,
                        "actor": "scheduler",
                        "source_type": "endpoint",
                        "alerts": [item for item in alerts if isinstance(item, dict)],
                    }
                )
        except Exception as exc:
            logger.warning("Analytics ingest: queue enqueue failed (%s)", exc)


def run_integrity_sweep_job() -> Dict[str, Any]:
    try:
        return run_integrity_sweep(max_items=INTEGRITY_SWEEP_MAX_ITEMS)
    except Exception as exc:
        logger.error("Periodic integrity sweep failed: %s", exc)
        return {
            "ok": False,
            "error": str(exc),
        }


def _list_db_jobs(org_id: Optional[int] = None) -> List[Dict[str, Any]]:
    db = connect()
    try:
        where = []
        params: Dict[str, Any] = {}
        if org_id is not None:
            where.append("(org_id=:org_id OR org_id IS NULL)")
            params["org_id"] = int(org_id)
        where_sql = f"WHERE {' AND '.join(where)}" if where else ""
        rows = db.execute(
            text(
                f"""
                SELECT
                    id,
                    name,
                    playbook,
                    job_kind,
                    payload_json,
                    target,
                    cron,
                    enabled,
                    require_approval,
                    last_run,
                    org_id
                FROM scheduled_jobs
                {where_sql}
                ORDER BY id DESC
                """
            ),
            params,
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            item = serialize_row(row) or {}
            try:
                item["job_kind"] = _normalize_job_kind(item.get("job_kind"), default="action")
            except HTTPException:
                item["job_kind"] = "action"
            item["payload"] = _parse_payload_json(item.get("payload_json"))
            runtime_id = _job_runtime_id(int(item["id"]))
            item["runtime_job_id"] = runtime_id
            item["runtime_registered"] = scheduler.get_job(runtime_id) is not None
            out.append(item)
        return out
    finally:
        db.close()


def list_jobs(org_id: Optional[int] = None) -> List[Dict[str, Any]]:
    return _list_db_jobs(org_id=org_id)


def sync_policy_jobs() -> None:
    try:
        db = connect()
        try:
            rows = db.execute(
                text("SELECT id, cron, enabled FROM scheduled_jobs")
            ).fetchall()
        finally:
            db.close()
    except Exception as exc:
        logger.error("Failed to sync scheduler jobs: %s", exc)
        return

    known_runtime_ids = set()
    for row in rows:
        if hasattr(row, "_mapping"):
            job_id = int(row._mapping["id"])
            cron_expr = str(row._mapping["cron"] or _DEFAULT_POLICY_CRON)
            enabled = _to_bool(row._mapping["enabled"], False)
        else:
            job_id = int(row[0])
            cron_expr = str(row[1] or _DEFAULT_POLICY_CRON)
            enabled = _to_bool(row[2], False)

        runtime_id = _job_runtime_id(job_id)
        known_runtime_ids.add(runtime_id)

        if not enabled:
            if scheduler.get_job(runtime_id):
                scheduler.remove_job(runtime_id)
            continue

        try:
            trigger = _parse_cron(cron_expr)
        except Exception as exc:
            logger.error("Invalid cron expression for job %s: %s (%s)", job_id, cron_expr, exc)
            if scheduler.get_job(runtime_id):
                scheduler.remove_job(runtime_id)
            continue

        scheduler.add_job(
            run_scheduled_job,
            trigger=trigger,
            id=runtime_id,
            args=[job_id],
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            misfire_grace_time=300,
        )

    for job in scheduler.get_jobs():
        if not job.id.startswith(_SCHED_JOB_PREFIX):
            continue
        if job.id not in known_runtime_ids:
            scheduler.remove_job(job.id)


def _create_execution_record(
    db,
    *,
    target: str,
    action_id: str,
    org_id: Optional[int],
    args_payload: Any = None,
) -> int:
    args_text = "[]"
    if args_payload is not None:
        args_text = _to_text(args_payload)
    inserted = db.execute(
        text(
            """
            INSERT INTO executions
            (approval_id, agent, playbook, action, args, status, approved_by, started_at, alert_id, org_id)
            VALUES (:approval_id, :agent, :playbook, :action, :args, :status, :approved_by, :started_at, :alert_id, :org_id)
            RETURNING id
            """
        ),
        {
            "approval_id": None,
            "agent": target,
            "playbook": action_id,
            "action": action_id,
            "args": args_text,
            "status": "RUNNING",
            "approved_by": "scheduler",
            "started_at": utc_now_naive(),
            "alert_id": None,
            "org_id": org_id,
        },
    )
    return int(inserted.scalar())


def _request_scheduled_approval(
    *,
    target: str,
    playbook: str,
    org_id: Optional[int],
    job_id: int,
) -> Dict[str, Any]:
    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO approvals
                (agent, playbook, requested_by, status, org_id)
                VALUES (:agent, :playbook, 'scheduler', 'PENDING', :org_id)
                """
            ),
            {
                "agent": target,
                "playbook": playbook,
                "org_id": org_id,
            },
        )
        db.execute(
            text("UPDATE scheduled_jobs SET last_run=:last_run WHERE id=:id"),
            {"last_run": utc_now_naive(), "id": int(job_id)},
        )
        db.commit()
    finally:
        db.close()

    log_audit(
        "scheduler_job_approval_requested",
        actor="scheduler",
        entity_type="scheduler_job",
        entity_id=str(job_id),
        detail=f"target={target}; playbook={playbook}",
        org_id=org_id,
        ip_address=None,
    )
    return {"ok": True, "job_id": job_id, "mode": "approval_requested"}


def _resolve_job_row(job_id: int) -> Optional[Dict[str, Any]]:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT
                    id,
                    name,
                    playbook,
                    job_kind,
                    payload_json,
                    target,
                    cron,
                    enabled,
                    require_approval,
                    org_id
                FROM scheduled_jobs
                WHERE id=:id
                """
            ),
            {"id": int(job_id)},
        ).fetchone()
    finally:
        db.close()
    if not row:
        return None
    if hasattr(row, "_mapping"):
        item = serialize_row(row)
        if not isinstance(item, dict):
            return None
        try:
            item["job_kind"] = _normalize_job_kind(item.get("job_kind"), default="action")
        except HTTPException:
            item["job_kind"] = "action"
        item["payload"] = _parse_payload_json(item.get("payload_json"))
        return item
    return {
        "id": row[0],
        "name": row[1],
        "playbook": row[2],
        "job_kind": (
            _normalize_job_kind(row[3], default="action")
            if str(row[3] or "").strip().lower() in _ALLOWED_SCHEDULE_JOB_KINDS
            else "action"
        ),
        "payload_json": row[4],
        "payload": _parse_payload_json(row[4]),
        "target": row[5],
        "cron": row[6],
        "enabled": row[7],
        "require_approval": row[8],
        "org_id": row[9],
    }


def _execute_scheduled_playbook_steps(
    *,
    db,
    execution_id: int,
    steps: List[Dict[str, Any]],
    agent_ids: List[str],
) -> Dict[str, Any]:
    target_rows_by_agent: Dict[str, Dict[str, Any]] = {}
    overall_status = "SUCCESS"
    trace: List[Dict[str, Any]] = []

    for index, step in enumerate(steps):
        step_id = str(step.get("id") or f"step_{index + 1}").strip() or f"step_{index + 1}"
        step_action = str(step.get("action") or "").strip()
        step_status = "FAILED"
        step_stdout = ""
        step_stderr = ""
        step_rows: List[Dict[str, Any]] = []
        result_payload: Dict[str, Any] = {}
        try:
            action = get_action(step_action)
            arguments = normalize_args(action, step.get("args"))
            dispatch = resolve_action_dispatch(action, arguments)
            execution = execute_action(
                _scheduler_client,
                step_action,
                dispatch,
                agent_ids,
                execution_id=execution_id,
            )
            result_payload = execution.get("result") if isinstance(execution, dict) else {}
            if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                step_rows = [row for row in (result_payload.get("results") or []) if isinstance(row, dict)]
                for row in step_rows:
                    agent_id = str(row.get("agent_id") or "").strip()
                    if agent_id:
                        target_rows_by_agent[agent_id] = row
            step_status = _result_status(result_payload, step_rows)
            step_stdout = _to_text(execution)
            if step_status != "SUCCESS":
                step_stderr = _to_text(
                    result_payload.get("message")
                    or ("Scheduled playbook step returned partial target failures." if step_status == "PARTIAL" else "Scheduled playbook step failed.")
                )
        except HTTPException as exc:
            step_status = "FAILED"
            err = exc.detail.get("message") if isinstance(exc.detail, dict) else exc.detail
            step_stderr = _to_text(err)
            detail_payload = exc.detail.get("result") if isinstance(exc.detail, dict) else None
            if isinstance(detail_payload, dict):
                result_payload = detail_payload
                if isinstance(detail_payload.get("results"), list):
                    step_rows = [row for row in (detail_payload.get("results") or []) if isinstance(row, dict)]
                    for row in step_rows:
                        agent_id = str(row.get("agent_id") or "").strip()
                        if agent_id:
                            target_rows_by_agent[agent_id] = row
        except Exception as exc:
            step_status = "FAILED"
            step_stderr = _to_text(exc)

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
                "step": f"scheduler:{step_id}",
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )
        db.commit()
        trace.append(
            {
                "id": step_id,
                "action": step_action,
                "status": step_status,
                "summary": {
                    "total": _to_int(result_payload.get("total"), len(step_rows)),
                    "success": _to_int(result_payload.get("success"), sum(1 for row in step_rows if _to_bool(row.get("ok"), False))),
                    "failed": _to_int(result_payload.get("failed"), sum(1 for row in step_rows if not _to_bool(row.get("ok"), False))),
                },
            }
        )
        if step_status == "FAILED":
            overall_status = "FAILED"
            break
        if step_status == "PARTIAL" and overall_status == "SUCCESS":
            overall_status = "PARTIAL"

    target_rows = list(target_rows_by_agent.values())
    counts = _result_counts({}, target_rows)
    return {
        "status": overall_status,
        "counts": counts,
        "target_rows": target_rows,
        "trace": trace,
    }


def run_scheduled_job(job_id: int) -> Dict[str, Any]:
    row = _resolve_job_row(job_id)
    if not row:
        return {"ok": False, "error": "job_not_found", "job_id": int(job_id)}
    if not _to_bool(row.get("enabled"), False):
        return {"ok": False, "error": "job_disabled", "job_id": int(job_id)}

    target = str(row.get("target") or "all").strip() or "all"
    job_kind = _normalize_job_kind(row.get("job_kind"), default="action")
    payload = row.get("payload") if isinstance(row.get("payload"), dict) else _parse_payload_json(row.get("payload_json"))
    action_id = str(row.get("playbook") or _HEALTHCHECK_ACTION_ID).strip()
    if job_kind == "shell":
        action_id = "global-shell"
    elif job_kind == "playbook":
        action_id = str(row.get("playbook") or "scheduled-playbook").strip() or "scheduled-playbook"
    org_id = row.get("org_id")

    if _to_bool(row.get("require_approval"), False):
        return _request_scheduled_approval(
            target=target,
            playbook=action_id,
            org_id=org_id,
            job_id=int(job_id),
        )

    db = connect()
    execution_id = None
    execution_status = "FAILED"
    step_status = "FAILED"
    step_stdout = ""
    step_stderr = ""
    target_rows: List[Dict[str, Any]] = []
    result_payload: Dict[str, Any] = {}
    counts: Dict[str, int] = {"total": 0, "completed": 0, "success": 0, "failed": 0}
    try:
        execution_id = _create_execution_record(
            db,
            target=target,
            action_id=action_id,
            org_id=org_id,
            args_payload={"job_kind": job_kind, "payload": payload},
        )
        if job_kind == "action" and str(action_id).strip().lower() == _INTEGRITY_SWEEP_ACTION_ID:
            try:
                sweep = run_integrity_sweep_job()
                step_stdout = _to_text(sweep)
                if not _to_bool(sweep.get("ok"), False):
                    execution_status = "FAILED"
                    step_status = "FAILED"
                    step_stderr = _to_text(sweep.get("error") or "integrity_sweep_failed")
                else:
                    execution_status = "SUCCESS"
                    step_status = "SUCCESS"
            except Exception as exc:
                execution_status = "FAILED"
                step_status = "FAILED"
                step_stderr = _to_text(exc)
        else:
            try:
                agent_ids = resolve_agent_ids(_scheduler_client, target=target, group=None)
                if job_kind == "shell":
                    shell_command, dispatch = _build_shell_dispatch(payload)
                    execution = execute_action(
                        _scheduler_client,
                        "global-shell",
                        dispatch,
                        agent_ids,
                        execution_id=execution_id,
                    )
                    result_payload = execution.get("result") if isinstance(execution, dict) else {}
                    if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                        target_rows = [r for r in (result_payload.get("results") or []) if isinstance(r, dict)]
                    counts = _result_counts(result_payload, target_rows)
                    execution_status = _result_status(result_payload, target_rows)
                    step_status = execution_status
                    step_stdout = _to_text(
                        {
                            "kind": "shell",
                            "command": shell_command,
                            "shell": str(payload.get("shell") or "powershell"),
                            "result": execution,
                        }
                    )
                elif job_kind == "playbook":
                    steps = _normalize_playbook_steps(payload)
                    if not steps:
                        raise HTTPException(
                            status_code=400,
                            detail="playbook jobs require payload.steps with at least one step",
                        )
                    playbook_run = _execute_scheduled_playbook_steps(
                        db=db,
                        execution_id=int(execution_id),
                        steps=steps,
                        agent_ids=agent_ids,
                    )
                    target_rows = playbook_run.get("target_rows") or []
                    counts = playbook_run.get("counts") or _result_counts({}, target_rows)
                    execution_status = str(playbook_run.get("status") or "FAILED").upper()
                    step_status = execution_status
                    step_stdout = _to_text(
                        {
                            "kind": "playbook",
                            "step_count": len(steps),
                            "trace": playbook_run.get("trace") or [],
                        }
                    )
                    if execution_status != "SUCCESS":
                        step_stderr = "Scheduled playbook completed with failed or partial steps."
                else:
                    action = get_action(action_id)
                    arguments = normalize_args(action, payload.get("args") if isinstance(payload, dict) else [])
                    dispatch = resolve_action_dispatch(action, arguments)
                    execution = execute_action(
                        _scheduler_client,
                        action_id,
                        dispatch,
                        agent_ids,
                        execution_id=execution_id,
                    )
                    result_payload = execution.get("result") if isinstance(execution, dict) else {}
                    if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                        target_rows = [r for r in (result_payload.get("results") or []) if isinstance(r, dict)]
                    counts = _result_counts(result_payload, target_rows)
                    execution_status = _result_status(result_payload, target_rows)
                    step_status = execution_status
                    step_stdout = _to_text(execution)
            except HTTPException as exc:
                execution_status = "FAILED"
                step_status = "FAILED"
                err = exc.detail.get("message") if isinstance(exc.detail, dict) else exc.detail
                step_stderr = _to_text(err)
                if isinstance(exc.detail, dict):
                    result_payload = exc.detail.get("result")
                    if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                        target_rows = [r for r in (result_payload.get("results") or []) if isinstance(r, dict)]
                counts = _result_counts(result_payload if isinstance(result_payload, dict) else {}, target_rows)
            except Exception as exc:
                execution_status = "FAILED"
                step_status = "FAILED"
                step_stderr = _to_text(exc)
                counts = _result_counts({}, target_rows)

            if not step_stderr and execution_status != "SUCCESS":
                step_stderr = _to_text(
                    (result_payload if isinstance(result_payload, dict) else {}).get("message")
                    or ("Scheduled playbook returned target failures." if job_kind == "playbook" else "Scheduled action returned target failures.")
                )

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
                "step": "scheduler",
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )
        if target_rows:
            _store_execution_targets(db, execution_id, target_rows)
        db.execute(
            text(
                """
                UPDATE executions
                SET
                    status=:status,
                    finished_at=:finished_at,
                    target_total=:target_total,
                    target_completed=:target_completed,
                    target_success=:target_success,
                    target_failed=:target_failed
                WHERE id=:id
                """
            ),
            {
                "status": execution_status,
                "finished_at": utc_now_naive(),
                "target_total": int(counts.get("total") or 0),
                "target_completed": int(counts.get("completed") or 0),
                "target_success": int(counts.get("success") or 0),
                "target_failed": int(counts.get("failed") or 0),
                "id": execution_id,
            },
        )
        db.execute(
            text("UPDATE scheduled_jobs SET last_run=:last_run WHERE id=:id"),
            {"last_run": utc_now_naive(), "id": int(job_id)},
        )
        db.commit()
    finally:
        db.close()

    log_audit(
        "scheduler_job_executed",
        actor="scheduler",
        entity_type="scheduler_job",
        entity_id=str(job_id),
        detail=(
            f"kind={job_kind}; action={action_id}; target={target}; status={execution_status}; "
            f"execution_id={execution_id}"
        ),
        org_id=org_id,
        ip_address=None,
    )
    return {
        "ok": execution_status == "SUCCESS",
        "job_id": int(job_id),
        "execution_id": execution_id,
        "status": execution_status,
        "job_kind": job_kind,
        "action_id": action_id,
        "target": target,
    }


def create_job(
    *,
    name: str,
    playbook: str,
    job_kind: str = "action",
    payload: Optional[Dict[str, Any]] = None,
    target: str,
    cron: str,
    enabled: bool,
    require_approval: bool,
    org_id: Optional[int],
) -> Dict[str, Any]:
    _parse_cron(cron)
    normalized_kind = _normalize_job_kind(job_kind, default="action")
    payload_json = _to_payload_json(payload)
    db = connect()
    try:
        inserted = db.execute(
            text(
                """
                INSERT INTO scheduled_jobs
                (name, playbook, job_kind, payload_json, target, cron, enabled, require_approval, last_run, org_id)
                VALUES (:name, :playbook, :job_kind, :payload_json, :target, :cron, :enabled, :require_approval, :last_run, :org_id)
                RETURNING id
                """
            ),
            {
                "name": str(name).strip(),
                "playbook": str(playbook).strip(),
                "job_kind": normalized_kind,
                "payload_json": payload_json,
                "target": str(target).strip() or "all",
                "cron": str(cron).strip(),
                "enabled": bool(enabled),
                "require_approval": bool(require_approval),
                "last_run": None,
                "org_id": org_id,
            },
        )
        job_id = int(inserted.scalar())
        db.commit()
    finally:
        db.close()
    sync_policy_jobs()
    rows = _list_db_jobs(org_id=org_id)
    for row in rows:
        if int(row["id"]) == int(job_id):
            return row
    return {"id": job_id}


def update_job(
    job_id: int,
    *,
    name: Optional[str] = None,
    playbook: Optional[str] = None,
    job_kind: Optional[str] = None,
    payload: Optional[Dict[str, Any]] = None,
    target: Optional[str] = None,
    cron: Optional[str] = None,
    enabled: Optional[bool] = None,
    require_approval: Optional[bool] = None,
) -> Dict[str, Any]:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT id, org_id
                FROM scheduled_jobs
                WHERE id=:id
                """
            ),
            {"id": int(job_id)},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scheduled job not found")
        org_id = row[1]

        updates: Dict[str, Any] = {}
        if name is not None:
            updates["name"] = str(name).strip() or "Scheduled Policy"
        if playbook is not None:
            updates["playbook"] = str(playbook).strip()
        if job_kind is not None:
            updates["job_kind"] = _normalize_job_kind(job_kind, default="action")
        if payload is not None:
            updates["payload_json"] = _to_payload_json(payload)
        if target is not None:
            updates["target"] = str(target).strip() or "all"
        if cron is not None:
            cron_value = str(cron).strip()
            _parse_cron(cron_value)
            updates["cron"] = cron_value
        if enabled is not None:
            updates["enabled"] = bool(enabled)
        if require_approval is not None:
            updates["require_approval"] = bool(require_approval)

        if updates:
            set_sql = ", ".join(f"{column}=:{column}" for column in updates.keys())
            db.execute(
                text(f"UPDATE scheduled_jobs SET {set_sql} WHERE id=:id"),
                {"id": int(job_id), **updates},
            )
            db.commit()
    finally:
        db.close()

    sync_policy_jobs()
    rows = _list_db_jobs(org_id=org_id)
    for row_item in rows:
        if int(row_item["id"]) == int(job_id):
            return row_item
    return {"id": int(job_id)}


def set_job_enabled(job_id: int, enabled: Optional[bool] = None) -> Dict[str, Any]:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT enabled, org_id
                FROM scheduled_jobs
                WHERE id=:id
                """
            ),
            {"id": int(job_id)},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Scheduled job not found")
        current_enabled = bool(row[0])
        org_id = row[1]
        next_enabled = (not current_enabled) if enabled is None else bool(enabled)
        db.execute(
            text("UPDATE scheduled_jobs SET enabled=:enabled WHERE id=:id"),
            {"enabled": next_enabled, "id": int(job_id)},
        )
        db.commit()
    finally:
        db.close()

    sync_policy_jobs()
    rows = _list_db_jobs(org_id=org_id)
    for row_item in rows:
        if int(row_item["id"]) == int(job_id):
            return row_item
    return {"id": int(job_id), "enabled": next_enabled}


def upsert_healthcheck_policy(
    interval_hours: int = 6,
    *,
    org_id: Optional[int],
    enabled: bool = True,
) -> Dict[str, Any]:
    every_hours = max(6, min(12, int(interval_hours or 6)))
    cron = f"0 */{every_hours} * * *"
    _parse_cron(cron)

    db = connect()
    try:
        existing = db.execute(
            text(
                """
                SELECT id
                FROM scheduled_jobs
                WHERE name=:name AND ((org_id IS NULL AND :org_id IS NULL) OR org_id=:org_id)
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {"name": _HEALTHCHECK_POLICY_NAME, "org_id": org_id},
        ).fetchone()
        if existing:
            job_id = int(existing[0])
            db.execute(
                text(
                    """
                    UPDATE scheduled_jobs
                    SET
                        playbook=:playbook,
                        job_kind='action',
                        payload_json=NULL,
                        target=:target,
                        cron=:cron,
                        enabled=:enabled,
                        require_approval=false
                    WHERE id=:id
                    """
                ),
                {
                    "id": job_id,
                    "playbook": _HEALTHCHECK_ACTION_ID,
                    "target": "all",
                    "cron": cron,
                    "enabled": bool(enabled),
                },
            )
        else:
            inserted = db.execute(
                text(
                    """
                    INSERT INTO scheduled_jobs
                    (name, playbook, job_kind, payload_json, target, cron, enabled, require_approval, last_run, org_id)
                    VALUES (:name, :playbook, 'action', NULL, :target, :cron, :enabled, false, :last_run, :org_id)
                    RETURNING id
                    """
                ),
                {
                    "name": _HEALTHCHECK_POLICY_NAME,
                    "playbook": _HEALTHCHECK_ACTION_ID,
                    "target": "all",
                    "cron": cron,
                    "enabled": bool(enabled),
                    "last_run": None,
                    "org_id": org_id,
                },
            )
            job_id = int(inserted.scalar())
        db.commit()
    finally:
        db.close()

    sync_policy_jobs()
    rows = _list_db_jobs(org_id=org_id)
    for row in rows:
        if int(row["id"]) == int(job_id):
            row["policy_interval_hours"] = every_hours
            return row
    return {"id": job_id, "policy_interval_hours": every_hours}


def upsert_integrity_sweep_policy(
    *,
    cron: Optional[str] = None,
    org_id: Optional[int],
    enabled: bool = True,
) -> Dict[str, Any]:
    cron_expr = str(cron if cron is not None else INTEGRITY_SWEEP_CRON).strip() or INTEGRITY_SWEEP_CRON
    _parse_cron(cron_expr)

    db = connect()
    try:
        existing = db.execute(
            text(
                """
                SELECT id
                FROM scheduled_jobs
                WHERE name=:name AND playbook=:playbook
                  AND ((org_id IS NULL AND :org_id IS NULL) OR org_id=:org_id)
                ORDER BY id DESC
                LIMIT 1
                """
            ),
            {
                "name": _INTEGRITY_SWEEP_POLICY_NAME,
                "playbook": _INTEGRITY_SWEEP_ACTION_ID,
                "org_id": org_id,
            },
        ).fetchone()
        if existing:
            job_id = int(existing[0])
            db.execute(
                text(
                    """
                    UPDATE scheduled_jobs
                    SET
                        playbook=:playbook,
                        job_kind='action',
                        payload_json=NULL,
                        target=:target,
                        cron=:cron,
                        enabled=:enabled,
                        require_approval=false
                    WHERE id=:id
                    """
                ),
                {
                    "id": job_id,
                    "playbook": _INTEGRITY_SWEEP_ACTION_ID,
                    "target": "all",
                    "cron": cron_expr,
                    "enabled": bool(enabled),
                },
            )
        else:
            inserted = db.execute(
                text(
                    """
                    INSERT INTO scheduled_jobs
                    (name, playbook, job_kind, payload_json, target, cron, enabled, require_approval, last_run, org_id)
                    VALUES (:name, :playbook, 'action', NULL, :target, :cron, :enabled, false, :last_run, :org_id)
                    RETURNING id
                    """
                ),
                {
                    "name": _INTEGRITY_SWEEP_POLICY_NAME,
                    "playbook": _INTEGRITY_SWEEP_ACTION_ID,
                    "target": "all",
                    "cron": cron_expr,
                    "enabled": bool(enabled),
                    "last_run": None,
                    "org_id": org_id,
                },
            )
            job_id = int(inserted.scalar())
        db.commit()
    finally:
        db.close()

    sync_policy_jobs()
    rows = _list_db_jobs(org_id=org_id)
    for row in rows:
        if int(row["id"]) == int(job_id):
            row["policy_cron"] = cron_expr
            return row
    return {"id": job_id, "policy_cron": cron_expr}


def _start_local_scheduler() -> None:
    global _scheduler_initialized
    if not _scheduler_initialized:
        if INGEST_ENABLED and scheduler.get_job("alerts_ingest") is None:
            scheduler.add_job(
                ingest_alerts,
                "interval",
                seconds=INGEST_INTERVAL,
                id="alerts_ingest",
                max_instances=1,
                coalesce=True,
            )
        if scheduler.get_job("integrity_sweep") is not None:
            scheduler.remove_job("integrity_sweep")
        _scheduler_initialized = True
    if not scheduler.running:
        scheduler.start()
 

def _sync_leader_scheduler_state() -> None:
    try:
        upsert_integrity_sweep_policy(
            cron=INTEGRITY_SWEEP_CRON,
            org_id=None,
            enabled=INTEGRITY_SWEEP_ENABLED,
        )
    except Exception as exc:
        logger.error("Failed to auto-create integrity sweep policy: %s", exc)
    if AUTO_CREATE_HEALTHCHECK_POLICY:
        try:
            upsert_healthcheck_policy(
                interval_hours=HEALTHCHECK_POLICY_INTERVAL_HOURS,
                org_id=None,
                enabled=True,
            )
        except Exception as exc:
            logger.error("Failed to auto-create health-check policy: %s", exc)
    try:
        sync_policy_jobs()
    except Exception as exc:
        logger.error("Failed to sync policy jobs on startup: %s", exc)


def _stop_local_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)


def _scheduler_leadership_loop() -> None:
    global _scheduler_has_leadership
    logger.info(
        "Starting scheduler leadership loop owner_id=%s lease=%ss renew=%ss",
        _SCHEDULER_OWNER_ID,
        _SCHEDULER_LEASE_TTL_SECONDS,
        _SCHEDULER_RENEW_SECONDS,
    )
    while not _scheduler_leadership_stop.is_set():
        acquired = False
        try:
            lease = acquire_or_renew_lease(
                lease_name=_SCHEDULER_LEASE_NAME,
                owner_id=_SCHEDULER_OWNER_ID,
                ttl_seconds=_SCHEDULER_LEASE_TTL_SECONDS,
                metadata={"component": "scheduler"},
            )
            acquired = bool(lease.get("acquired"))
        except Exception as exc:
            logger.error("Scheduler leadership renewal failed: %s", exc)

        if acquired:
            if not _scheduler_has_leadership:
                logger.info("Scheduler leadership acquired by %s", _SCHEDULER_OWNER_ID)
            _scheduler_has_leadership = True
            try:
                _start_local_scheduler()
                _sync_leader_scheduler_state()
            except Exception as exc:
                logger.error("Scheduler leader sync failed: %s", exc)
        else:
            if _scheduler_has_leadership:
                logger.warning("Scheduler leadership lost by %s", _SCHEDULER_OWNER_ID)
            _scheduler_has_leadership = False
            _stop_local_scheduler()

        _scheduler_leadership_stop.wait(float(_SCHEDULER_RENEW_SECONDS))

    _scheduler_has_leadership = False
    _stop_local_scheduler()
    logger.info("Scheduler leadership loop stopped")


def start_scheduler() -> None:
    global _scheduler_leadership_thread
    with _scheduler_leadership_lock:
        if _scheduler_leadership_thread and _scheduler_leadership_thread.is_alive():
            return
        _scheduler_leadership_stop.clear()
        _scheduler_leadership_thread = threading.Thread(
            target=_scheduler_leadership_loop,
            name="scheduler-leadership",
            daemon=True,
        )
        _scheduler_leadership_thread.start()


def stop_scheduler() -> None:
    global _scheduler_leadership_thread
    with _scheduler_leadership_lock:
        thread = _scheduler_leadership_thread
        _scheduler_leadership_stop.set()
    if thread and thread.is_alive():
        thread.join(timeout=max(1.0, float(_SCHEDULER_RENEW_SECONDS) + 2.0))
    with _scheduler_leadership_lock:
        if _scheduler_leadership_thread is thread and thread and not thread.is_alive():
            _scheduler_leadership_thread = None
    try:
        release_lease(
            lease_name=_SCHEDULER_LEASE_NAME,
            owner_id=_SCHEDULER_OWNER_ID,
        )
    except Exception:
        pass
    _stop_local_scheduler()
