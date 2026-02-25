from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, List, Optional

from fastapi import HTTPException
from sqlalchemy import text

from core.actions import get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.alert_store import store_alerts
from core.audit import log_audit
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

_ingest_cfg = SETTINGS.get("analytics_ingest", {}) if isinstance(SETTINGS, dict) else {}
INGEST_ENABLED = bool(_ingest_cfg.get("enabled", True))
INGEST_INTERVAL = max(60, int(_ingest_cfg.get("interval_seconds", 300)))
INGEST_LIMIT = max(10, min(1000, int(_ingest_cfg.get("limit", 200))))
INGEST_QUERY = _ingest_cfg.get("query")

_ingest_client = WazuhClient()
_ingest_indexer = IndexerClient()
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


def _to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


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
                "ok": bool(row.get("ok")),
                "status_code": int(row.get("status_code") or 0),
                "stdout": _to_text(row.get("stdout")),
                "stderr": _to_text(row.get("stderr")),
            },
        )


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
        store_alerts(alerts)


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
                SELECT id, name, playbook, target, cron, enabled, require_approval, last_run, org_id
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
) -> int:
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
            "args": "[]",
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
                SELECT id, name, playbook, target, cron, enabled, require_approval, org_id
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
        return serialize_row(row)
    return {
        "id": row[0],
        "name": row[1],
        "playbook": row[2],
        "target": row[3],
        "cron": row[4],
        "enabled": row[5],
        "require_approval": row[6],
        "org_id": row[7],
    }


def run_scheduled_job(job_id: int) -> Dict[str, Any]:
    row = _resolve_job_row(job_id)
    if not row:
        return {"ok": False, "error": "job_not_found", "job_id": int(job_id)}
    if not _to_bool(row.get("enabled"), False):
        return {"ok": False, "error": "job_disabled", "job_id": int(job_id)}

    target = str(row.get("target") or "all").strip() or "all"
    action_id = str(row.get("playbook") or _HEALTHCHECK_ACTION_ID).strip()
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
    execution_status = "SUCCESS"
    step_status = "SUCCESS"
    step_stdout = ""
    step_stderr = ""
    target_rows: List[Dict[str, Any]] = []
    try:
        execution_id = _create_execution_record(db, target=target, action_id=action_id, org_id=org_id)
        if str(action_id).strip().lower() == _INTEGRITY_SWEEP_ACTION_ID:
            try:
                sweep = run_integrity_sweep_job()
                step_stdout = _to_text(sweep)
                if not _to_bool(sweep.get("ok"), False):
                    execution_status = "FAILED"
                    step_status = "FAILED"
                    step_stderr = _to_text(sweep.get("error") or "integrity_sweep_failed")
            except Exception as exc:
                execution_status = "FAILED"
                step_status = "FAILED"
                step_stderr = _to_text(exc)
        else:
            try:
                action = get_action(action_id)
                arguments = normalize_args(action, [])
                dispatch = resolve_action_dispatch(action, arguments)
                agent_ids = resolve_agent_ids(_scheduler_client, target=target, group=None)
                execution = execute_action(
                    _scheduler_client,
                    action_id,
                    dispatch,
                    agent_ids,
                    execution_id=execution_id,
                )
                result_payload = execution.get("result") if isinstance(execution, dict) else None
                if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                    target_rows = [r for r in result_payload.get("results") if isinstance(r, dict)]
                step_stdout = _to_text(execution)
            except HTTPException as exc:
                execution_status = "FAILED"
                step_status = "FAILED"
                err = exc.detail.get("message") if isinstance(exc.detail, dict) else exc.detail
                step_stderr = _to_text(err)
                if isinstance(exc.detail, dict):
                    result_payload = exc.detail.get("result")
                    if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                        target_rows = [r for r in result_payload.get("results") if isinstance(r, dict)]
            except Exception as exc:
                execution_status = "FAILED"
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
                SET status=:status, finished_at=:finished_at
                WHERE id=:id
                """
            ),
            {"status": execution_status, "finished_at": utc_now_naive(), "id": execution_id},
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
            f"action={action_id}; target={target}; status={execution_status}; "
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
        "action_id": action_id,
        "target": target,
    }


def create_job(
    *,
    name: str,
    playbook: str,
    target: str,
    cron: str,
    enabled: bool,
    require_approval: bool,
    org_id: Optional[int],
) -> Dict[str, Any]:
    _parse_cron(cron)
    db = connect()
    try:
        inserted = db.execute(
            text(
                """
                INSERT INTO scheduled_jobs
                (name, playbook, target, cron, enabled, require_approval, last_run, org_id)
                VALUES (:name, :playbook, :target, :cron, :enabled, :require_approval, :last_run, :org_id)
                RETURNING id
                """
            ),
            {
                "name": str(name).strip(),
                "playbook": str(playbook).strip(),
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
                    SET playbook=:playbook, target=:target, cron=:cron, enabled=:enabled, require_approval=false
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
                    (name, playbook, target, cron, enabled, require_approval, last_run, org_id)
                    VALUES (:name, :playbook, :target, :cron, :enabled, false, :last_run, :org_id)
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
                    SET playbook=:playbook, target=:target, cron=:cron, enabled=:enabled, require_approval=false
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
                    (name, playbook, target, cron, enabled, require_approval, last_run, org_id)
                    VALUES (:name, :playbook, :target, :cron, :enabled, false, :last_run, :org_id)
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


def start_scheduler() -> None:
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


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
