import json
import os
import threading

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from sqlalchemy import text

try:
    from core.active_defense import action_requires_approval_handshake
except ImportError:  # Backward-compatible fallback for v1.1.x deployments.
    def action_requires_approval_handshake(*_args, **_kwargs):
        return False
from core.actions import ensure_public_action, get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.audit import log_audit
from core.launch_guardrails import register_launch, should_emit_burst
from core.security import recent_auth_window_seconds, require_recent_auth, require_role
from core.security_monitoring import record_security_event
from core.time_utils import utc_now_naive
from core.ws_bus import publish_event
from core.wazuh_client import WazuhClient
from core.wazuh_verification import (
    derive_verification_state,
    reconcile_pending_verifications_for_agents,
    run_post_action_verification,
)
from db.database import connect

router = APIRouter()
client = WazuhClient()


def _fleet_batch_size() -> int:
    raw = os.getenv("C2F_EXECUTION_BATCH_SIZE", "20")
    try:
        return max(1, min(int(raw), 100))
    except Exception:
        return 20


def _fleet_async_threshold() -> int:
    raw = os.getenv("C2F_EXECUTION_BATCH_THRESHOLD", "")
    try:
        return max(2, int(raw))
    except Exception:
        return max(21, _fleet_batch_size() + 1)


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
    if not execution_id or not rows:
        return
    if not isinstance(rows, list):
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


def _result_execution_status(payload) -> str:
    result = payload if isinstance(payload, dict) else {}
    total = int(result.get("total") or 0)
    success = int(result.get("success") or 0)
    failed = int(result.get("failed") or 0)
    if total > 0 and success > 0 and failed > 0:
        return "PARTIAL"
    if total > 0 and success > 0 and failed == 0:
        return "SUCCESS"
    return "FAILED"


def _skip_post_action_verification(action_id: str) -> bool:
    aid = str(action_id or "").strip().lower()
    return aid in {"sca-rescan", "sca_rescan", "sca"}


def _result_counts(rows, *, fallback_total: int = 0) -> dict:
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


def _update_execution_progress(
    conn,
    execution_id: int,
    *,
    status: str | None = None,
    finished: bool = False,
    target_total: int | None = None,
    target_completed: int | None = None,
    target_success: int | None = None,
    target_failed: int | None = None,
    batch_size: int | None = None,
) -> None:
    assignments = []
    params = {"id": int(execution_id)}
    if status:
        assignments.append("status=:status")
        params["status"] = str(status)
    if target_total is not None:
        assignments.append("target_total=:target_total")
        params["target_total"] = int(target_total)
    if target_completed is not None:
        assignments.append("target_completed=:target_completed")
        params["target_completed"] = int(target_completed)
    if target_success is not None:
        assignments.append("target_success=:target_success")
        params["target_success"] = int(target_success)
    if target_failed is not None:
        assignments.append("target_failed=:target_failed")
        params["target_failed"] = int(target_failed)
    if batch_size is not None:
        assignments.append("batch_size=:batch_size")
        params["batch_size"] = int(batch_size)
    if finished:
        assignments.append("finished_at=:finished_at")
        params["finished_at"] = utc_now_naive()
    if not assignments:
        return
    conn.execute(
        text(
            f"""
            UPDATE executions
            SET {", ".join(assignments)}
            WHERE id=:id
            """
        ),
        params,
    )


def _insert_execution_record(
    *,
    target: str,
    action_id: str,
    arguments,
    actor: str,
    org_id,
    alert_id: str | None,
    justification: str | None,
    initial_status: str,
    target_total: int,
    batch_size: int,
) -> int:
    db = connect()
    try:
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
                "playbook": action_id,
                "action": action_id,
                "args": json.dumps(arguments, default=str),
                "status": initial_status,
                "approved_by": actor,
                "started_at": utc_now_naive(),
                "alert_id": alert_id,
                "org_id": org_id,
                "target_total": int(target_total or 0),
                "target_completed": 0,
                "target_success": 0,
                "target_failed": 0,
                "batch_size": int(batch_size or 0),
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
                {
                    "execution_id": execution_id,
                    "justification": str(justification),
                },
            )
        db.commit()
        return execution_id
    finally:
        db.close()


def _log_case_events(
    conn,
    *,
    alert_id: str | None,
    case_id: int | None,
    action_id: str,
    actor: str,
    execution_id: int,
    execution_status: str,
    group: str | None = None,
) -> None:
    if not alert_id and not case_id:
        return
    from core.case_timeline import case_ids_for_alert, log_case_event

    target_cases = []
    if case_id:
        target_cases = [case_id]
    elif alert_id:
        target_cases = case_ids_for_alert(alert_id, conn=conn)

    for cid in target_cases:
        start_msg = f"Execution started for action {action_id}"
        finish_msg = f"Execution finished with status {execution_status}"
        if group:
            start_msg += f" on group {group}"
            finish_msg += f" on group {group}"
        log_case_event(
            cid,
            "execution_started",
            message=start_msg,
            actor=actor,
            alert_id=alert_id,
            execution_id=execution_id,
            action=action_id,
            conn=conn,
        )
        log_case_event(
            cid,
            "execution_finished",
            message=finish_msg,
            actor=actor,
            alert_id=alert_id,
            execution_id=execution_id,
            action=action_id,
            conn=conn,
        )
    if target_cases:
        conn.commit()


def _run_async_remediation_job(
    *,
    execution_id: int,
    action_id: str,
    dispatch,
    agent_ids: list[str],
    target: str,
    actor: str,
    org_id,
    alert_id: str | None,
    case_id: int | None,
    group: str | None,
    request_ip: str | None,
) -> None:
    db = connect()
    execution = None
    target_rows = None
    result_payload = {}
    verification_result = None
    reconcile_result = None
    step_name = "orchestration"
    step_stdout = ""
    step_stderr = ""
    execution_status = "FAILED"
    step_status = "FAILED"
    incremental_rows_persisted = False
    batch_size = _fleet_batch_size()

    def _batch_progress_callback(progress: dict) -> None:
        nonlocal incremental_rows_persisted
        rows = progress.get("rows") if isinstance(progress, dict) else []
        if rows:
            _store_execution_targets(db, execution_id, rows)
            incremental_rows_persisted = True
        _update_execution_progress(
            db,
            execution_id,
            status="PARTIAL",
            target_total=int(progress.get("total") or len(agent_ids)),
            target_completed=int(progress.get("completed") or 0),
            target_success=int(progress.get("success") or 0),
            target_failed=int(progress.get("failed") or 0),
            batch_size=batch_size,
        )
        db.commit()

    try:
        _update_execution_progress(
            db,
            execution_id,
            status="RUNNING",
            target_total=len(agent_ids),
            batch_size=batch_size if len(agent_ids) >= batch_size else len(agent_ids),
        )
        db.commit()

        publish_event(
            execution_id,
            {
                "type": "execution_started",
                "step": "orchestration",
                "status": "RUNNING",
                "stdout": f"action={action_id}; target={target}; targets={len(agent_ids)}",
                "stderr": "",
            },
        )

        try:
            execution = execute_action(
                client,
                action_id,
                dispatch,
                agent_ids,
                execution_id=execution_id,
                context={"_batch_progress_callback": _batch_progress_callback},
            )
            step_name = execution.get("channel") or "orchestration"
            detail = f"channel={execution.get('channel')}; command={execution.get('command_used')}"
            attempts = execution.get("attempts") or []
            if attempts:
                detail += f"; attempts={','.join(attempts)}"
            result_payload = execution.get("result") if isinstance(execution.get("result"), dict) else {}
            step_stdout = f"{detail}\n{json.dumps(result_payload, default=str)}"
            execution_status = _result_execution_status(result_payload)
            step_status = execution_status if execution_status != "FAILED" else "FAILED"
            if isinstance(result_payload.get("results"), list):
                target_rows = result_payload.get("results")
                if _skip_post_action_verification(action_id):
                    verification_result = {
                        "skipped": True,
                        "reason": "direct_sca_rescan_action",
                    }
                else:
                    publish_event(
                        execution_id,
                        {
                            "type": "step_start",
                            "step": "post_action_verification",
                            "status": "RUNNING",
                            "stdout": "Awaiting fresh Wazuh/SCA scan data...",
                            "stderr": "",
                        },
                    )
                    verification_result = run_post_action_verification(
                        client,
                        action_id,
                        execution_id,
                        target_rows or [],
                    )
                    verification_state_live = derive_verification_state(verification_result)
                    publish_event(
                        execution_id,
                        {
                            "type": "step_done" if verification_state_live.get("ok") else "step_failed",
                            "step": "post_action_verification",
                            "status": str(verification_state_live.get("step_status") or "SUCCESS"),
                            "stdout": json.dumps(
                                (verification_result or {}).get("summary")
                                if isinstance(verification_result, dict)
                                else {},
                                default=str,
                            ),
                            "stderr": str(verification_state_live.get("step_error") or ""),
                        },
                    )
        except HTTPException as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            if isinstance(exc.detail, dict):
                step_name = "endpoint"
                step_stderr = _to_text(exc.detail.get("message") or exc.detail)
                result_payload = exc.detail.get("result") if isinstance(exc.detail.get("result"), dict) else {}
                if isinstance(result_payload.get("results"), list):
                    target_rows = result_payload.get("results")
            else:
                step_name = "active_response" if "active response" in _to_text(exc.detail).lower() else "orchestration"
                step_stderr = _to_text(exc.detail)
        except Exception as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            step_stderr = _to_text(exc)

        counts = _result_counts(target_rows, fallback_total=len(agent_ids))
        if target_rows and not incremental_rows_persisted:
            _store_execution_targets(db, execution_id, target_rows)

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
                "step": step_name,
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )

        verification_state = derive_verification_state(verification_result)
        if verification_state.get("execution_status") and execution_status == "SUCCESS":
            execution_status = str(verification_state.get("execution_status") or execution_status)
        _update_execution_progress(
            db,
            execution_id,
            status=execution_status,
            finished=True,
            target_total=counts["total"],
            target_completed=counts["completed"],
            target_success=counts["success"],
            target_failed=counts["failed"],
            batch_size=batch_size if len(agent_ids) >= batch_size else len(agent_ids),
        )

        if verification_state.get("applicable"):
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
                    "step": "post_action_verification",
                    "stdout": json.dumps(verification_result, default=str),
                    "stderr": str(verification_state.get("step_error") or ""),
                    "status": str(verification_state.get("step_status") or "SUCCESS"),
                },
            )

        successful_agent_ids = [
            str(row.get("agent_id") or "").strip()
            for row in (target_rows or [])
            if isinstance(row, dict) and row.get("ok") and str(row.get("agent_id") or "").strip()
        ]
        if str(action_id or "").strip().lower() == "sca-rescan" and successful_agent_ids:
            reconcile_result = reconcile_pending_verifications_for_agents(
                client,
                successful_agent_ids,
                source_execution_id=execution_id,
                source_action_id=action_id,
            )
            if isinstance(reconcile_result, dict) and int(reconcile_result.get("updated") or 0) > 0:
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
                        "step": "pending_verification_reconcile",
                        "stdout": json.dumps(reconcile_result, default=str),
                        "stderr": "",
                        "status": "SUCCESS",
                    },
                )
        db.commit()
        _log_case_events(
            db,
            alert_id=alert_id,
            case_id=case_id,
            action_id=action_id,
            actor=actor,
            execution_id=execution_id,
            execution_status=execution_status,
            group=group,
        )

        publish_event(
            execution_id,
            {
                "type": "execution_finished",
                "step": step_name,
                "status": execution_status,
                "stdout": json.dumps(
                    {
                        "success": counts["success"],
                        "failed": counts["failed"],
                        "total": counts["total"],
                    },
                    default=str,
                ),
                "stderr": step_stderr if step_status == "FAILED" else "",
            },
        )
    finally:
        db.close()

    log_audit(
        "execution_finished",
        actor=actor,
        entity_type="execution",
        entity_id=str(execution_id),
        detail=f"target={target}; status={execution_status}; action={action_id}",
        org_id=org_id,
        ip_address=request_ip,
    )


def queue_remediation_execution(
    *,
    target: str,
    action_id: str,
    dispatch,
    arguments,
    agent_ids: list[str],
    actor: str,
    org_id,
    alert_id: str | None,
    case_id: int | None,
    group: str | None,
    justification: str | None,
    request_ip: str | None,
) -> int:
    batch_size = _fleet_batch_size()
    execution_id = _insert_execution_record(
        target=target,
        action_id=action_id,
        arguments=arguments,
        actor=actor,
        org_id=org_id,
        alert_id=alert_id,
        justification=justification,
        initial_status="QUEUED",
        target_total=len(agent_ids),
        batch_size=batch_size if len(agent_ids) >= batch_size else len(agent_ids),
    )
    worker = threading.Thread(
        target=_run_async_remediation_job,
        kwargs={
            "execution_id": execution_id,
            "action_id": action_id,
            "dispatch": dispatch,
            "agent_ids": list(agent_ids),
            "target": target,
            "actor": actor,
            "org_id": org_id,
            "alert_id": alert_id,
            "case_id": case_id,
            "group": group,
            "request_ip": request_ip,
        },
        daemon=True,
    )
    worker.start()
    return execution_id


@router.post("")
async def remediate(
    request: Request,
    agent_id: str | None = None,
    action_id: str | None = None,
    args: str | None = None,
    alert_id: str | None = None,
    case_id: int | None = None,
    group: str | None = None,
    user=Depends(require_role("admin")),
):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    agent_id = body.get("agent_id") or agent_id
    agent_ids = body.get("agent_ids") or body.get("agents")
    action_id = (
        body.get("action_id")
        or body.get("action")
        or body.get("playbook")
        or action_id
    )
    args = body.get("args") if "args" in body else args
    alert_id = body.get("alert_id") or alert_id
    case_id = body.get("case_id") or case_id
    group = body.get("group") or group
    justification = body.get("justification") or body.get("reason")
    async_raw = body.get("async")
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []

    if not action_id or (not agent_id and not group and not agent_ids):
        raise HTTPException(status_code=400, detail="action_id and agent_id or group are required")
    action_id = ensure_public_action(action_id)

    action = get_action(action_id)
    arguments = normalize_args(action, args)
    dispatch = resolve_action_dispatch(action, arguments)
    target = agent_id if agent_id else f"group:{group}"
    if agent_ids:
        agent_ids = [str(a).strip() for a in agent_ids if str(a).strip()]
        target = "multi:" + ",".join(agent_ids)
    else:
        agent_ids = resolve_agent_ids(client, target=target, group=group)
    if exclude_agent_ids:
        exclude_norm = {str(a).strip() for a in exclude_agent_ids if str(a).strip()}
        agent_ids = [a for a in agent_ids if str(a).strip() not in exclude_norm]
    if not agent_ids:
        raise HTTPException(status_code=404, detail="No agents resolved for target")
    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None
    if len(agent_ids) >= 25:
        record_security_event(
            "execution.fleet_remediation_launch",
            severity="warning",
            request=request,
            user=user if isinstance(user, dict) else None,
            detail="Fleet-wide remediation requested",
            metadata={
                "action_id": action_id,
                "target_count": len(agent_ids),
                "group": str(group or ""),
            },
        )
        recent_fleet = register_launch(
            "execution.fleet_remediation_launch",
            actor=actor,
            window_seconds=900,
        )
        if should_emit_burst(recent_fleet):
            record_security_event(
                "execution.fleet_remediation_burst",
                severity="warning",
                request=request,
                user=user if isinstance(user, dict) else None,
                detail="Repeated fleet-wide remediation launches detected",
                metadata={
                    "action_id": action_id,
                    "target_count": len(agent_ids),
                    "recent_count": recent_fleet,
                    "window_seconds": 900,
                },
            )
        require_recent_auth(
            user,
            request,
            max_age_seconds=recent_auth_window_seconds("fleet_remediation", 3600),
            action_label="fleet-wide remediation",
        )
    if action_requires_approval_handshake(action_id, target_count=len(agent_ids), context={"tenant_id": org_id}):
        from api.approvals import create_approval_request_record

        approval = create_approval_request_record(
            request=request,
            user=user,
            agent_ids=agent_ids,
            action_id=action_id,
            args=args,
            alert_id=alert_id,
            case_id=case_id,
            justification=justification,
            incident_priority=body.get("incident_priority") or body.get("priority"),
            incident_score=body.get("incident_score") or body.get("score"),
        )
        return {
            "agent": target,
            "action": action_id,
            "status": "PENDING_APPROVAL",
            "approval_id": approval.get("approval_id") or approval.get("id"),
            "approval": approval,
            "result": None,
            "summary": {
                "total": len(agent_ids),
                "completed": 0,
                "success": 0,
                "failed": 0,
                "remaining": len(agent_ids),
                "percent_complete": 0,
                "status": "PENDING_APPROVAL",
            },
        }
    if async_raw is None:
        async_mode = len(agent_ids) >= _fleet_async_threshold()
    else:
        async_mode = str(async_raw).strip().lower() in {"1", "true", "yes", "on"}

    if async_mode:
        execution_id = queue_remediation_execution(
            target=target,
            action_id=action_id,
            dispatch=dispatch,
            arguments=arguments,
            agent_ids=agent_ids,
            actor=actor,
            org_id=org_id,
            alert_id=alert_id,
            case_id=case_id,
            group=group,
            justification=justification,
            request_ip=request.client.host if request.client else None,
        )
        log_audit(
            "execution_queued",
            actor=actor,
            entity_type="execution",
            entity_id=str(execution_id),
            detail=f"target={target}; status=QUEUED; action={action_id}; targets={len(agent_ids)}",
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )
        return {
            "agent": target,
            "action": action_id,
            "execution_id": execution_id,
            "status": "QUEUED",
            "channel": "endpoint",
            "mode": "endpoint_batched",
            "command_used": action_id,
            "attempts": [action_id],
            "result": {
                "ok": False,
                "queued": True,
                "total": len(agent_ids),
                "success": 0,
                "failed": 0,
                "results": [],
            },
            "summary": {
                "total": len(agent_ids),
                "completed": 0,
                "success": 0,
                "failed": 0,
                "remaining": len(agent_ids),
                "percent_complete": 0,
                "status": "QUEUED",
            },
            "post_action_verification": None,
            "pending_verification_reconcile": None,
        }

    db = connect()
    execution_id = None
    execution = None
    step_name = "orchestration"
    step_stdout = ""
    step_stderr = ""
    verification_result = None
    reconcile_result = None
    execution_status = "SUCCESS"
    step_status = "SUCCESS"
    raised_http_exception = None
    target_rows = None
    try:
        started_at = utc_now_naive()
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
                "playbook": action_id,
                "action": action_id,
                "args": json.dumps(arguments, default=str),
                "status": "RUNNING",
                "approved_by": actor,
                "started_at": started_at,
                "alert_id": alert_id,
                "org_id": org_id,
                "target_total": len(agent_ids),
                "target_completed": 0,
                "target_success": 0,
                "target_failed": 0,
                "batch_size": _fleet_batch_size() if len(agent_ids) >= _fleet_batch_size() else len(agent_ids),
            },
        )
        execution_id = inserted.scalar()
        db.commit()

        if justification:
            db.execute(
                text(
                    """
                    INSERT INTO execution_metadata (execution_id, justification)
                    VALUES (:execution_id, :justification)
                    """
                ),
                {
                    "execution_id": execution_id,
                    "justification": str(justification),
                },
            )
            db.commit()

        publish_event(
            int(execution_id),
            {
                "type": "execution_started",
                "step": "orchestration",
                "status": "RUNNING",
                "stdout": f"action={action_id}; target={target}",
                "stderr": "",
            },
        )

        try:
            # Run orchestration in a worker thread so the event loop can keep serving
            # WebSockets (live execution streaming) and other requests.
            execution = await run_in_threadpool(
                lambda: execute_action(client, action_id, dispatch, agent_ids, execution_id=int(execution_id))
            )
            step_name = execution.get("channel") or "orchestration"
            detail = f"channel={execution.get('channel')}; command={execution.get('command_used')}"
            attempts = execution.get("attempts") or []
            if attempts:
                detail += f"; attempts={','.join(attempts)}"
            step_stdout = f"{detail}\n{json.dumps(execution.get('result'), default=str)}"
            result_payload = execution.get("result")
            if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                target_rows = result_payload.get("results")
                execution_status = _result_execution_status(result_payload)
                step_status = execution_status if execution_status != "FAILED" else "FAILED"
                if _skip_post_action_verification(action_id):
                    verification_result = {
                        "skipped": True,
                        "reason": "direct_sca_rescan_action",
                    }
                else:
                    publish_event(
                        int(execution_id),
                        {
                            "type": "step_start",
                            "step": "post_action_verification",
                            "status": "RUNNING",
                            "stdout": "Awaiting fresh Wazuh/SCA scan data...",
                            "stderr": "",
                        },
                    )
                    verification_result = await run_in_threadpool(
                        lambda: run_post_action_verification(
                            client,
                            action_id,
                            int(execution_id) if execution_id is not None else None,
                            target_rows or [],
                        )
                    )
                    verification_state_live = derive_verification_state(verification_result)
                    publish_event(
                        int(execution_id),
                        {
                            "type": "step_done" if verification_state_live.get("ok") else "step_failed",
                            "step": "post_action_verification",
                            "status": str(verification_state_live.get("step_status") or "SUCCESS"),
                            "stdout": json.dumps(
                                (verification_result or {}).get("summary")
                                if isinstance(verification_result, dict)
                                else {},
                                default=str,
                            ),
                            "stderr": str(verification_state_live.get("step_error") or ""),
                        },
                    )
        except HTTPException as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            if isinstance(exc.detail, dict):
                step_name = "endpoint"
                step_stderr = _to_text(exc.detail.get("message") or exc.detail)
            else:
                step_name = "active_response" if "active response" in _to_text(exc.detail).lower() else "orchestration"
                step_stderr = _to_text(exc.detail)
            raised_http_exception = exc
            if isinstance(exc.detail, dict):
                result_payload = exc.detail.get("result")
                if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                    target_rows = result_payload.get("results")
        except Exception as exc:
            execution_status = "FAILED"
            step_status = "FAILED"
            step_stderr = _to_text(exc)
            raised_http_exception = HTTPException(status_code=500, detail="Action execution failed")

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
                "step": step_name,
                "stdout": step_stdout,
                "stderr": step_stderr,
                "status": step_status,
            },
        )
        counts = _result_counts(target_rows, fallback_total=len(agent_ids))
        _update_execution_progress(
            db,
            execution_id,
            status=execution_status,
            finished=True,
            target_total=counts["total"],
            target_completed=counts["completed"],
            target_success=counts["success"],
            target_failed=counts["failed"],
            batch_size=_fleet_batch_size() if len(agent_ids) >= _fleet_batch_size() else len(agent_ids),
        )
        if target_rows:
            _store_execution_targets(db, int(execution_id), target_rows)
        verification_state = derive_verification_state(verification_result)
        if verification_state.get("execution_status") and execution_status == "SUCCESS":
            execution_status = str(verification_state.get("execution_status") or execution_status)
            _update_execution_progress(db, execution_id, status=execution_status)
        if verification_state.get("applicable"):
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
                    "step": "post_action_verification",
                    "stdout": json.dumps(verification_result, default=str),
                    "stderr": str(verification_state.get("step_error") or ""),
                    "status": str(verification_state.get("step_status") or "SUCCESS"),
                },
            )
        successful_agent_ids = [
            str(row.get("agent_id") or "").strip()
            for row in (target_rows or [])
            if isinstance(row, dict) and row.get("ok") and str(row.get("agent_id") or "").strip()
        ]
        if str(action_id or "").strip().lower() == "sca-rescan" and successful_agent_ids:
            reconcile_result = await run_in_threadpool(
                lambda: reconcile_pending_verifications_for_agents(
                    client,
                    successful_agent_ids,
                    source_execution_id=execution_id,
                    source_action_id=action_id,
                )
            )
            if isinstance(reconcile_result, dict) and int(reconcile_result.get("updated") or 0) > 0:
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
                        "step": "pending_verification_reconcile",
                        "stdout": json.dumps(reconcile_result, default=str),
                        "stderr": "",
                        "status": "SUCCESS",
                    },
                )
        db.commit()

        if alert_id or case_id:
            from core.case_timeline import case_ids_for_alert, log_case_event

            target_cases = []
            if case_id:
                target_cases = [case_id]
            elif alert_id:
                target_cases = case_ids_for_alert(alert_id, conn=db)

            for cid in target_cases:
                start_msg = f"Execution started for action {action_id}"
                finish_msg = f"Execution finished with status {execution_status}"
                if group:
                    start_msg += f" on group {group}"
                    finish_msg += f" on group {group}"
                log_case_event(
                    cid,
                    "execution_started",
                    message=start_msg,
                    actor=actor,
                    alert_id=alert_id,
                    execution_id=execution_id,
                    action=action_id,
                    conn=db,
                )
                log_case_event(
                    cid,
                    "execution_finished",
                    message=finish_msg,
                    actor=actor,
                    alert_id=alert_id,
                    execution_id=execution_id,
                    action=action_id,
                    conn=db,
                )
            if target_cases:
                db.commit()
    finally:
        db.close()

    log_audit(
        "execution_finished",
        actor=actor,
        entity_type="execution",
        entity_id=str(execution_id) if execution_id is not None else action_id,
        detail=f"target={target}; status={execution_status}; action={action_id}",
        org_id=org_id,
        ip_address=request.client.host if request.client else None,
    )

    if raised_http_exception is not None:
        raise HTTPException(
            status_code=raised_http_exception.status_code,
            detail=f"{_to_text(raised_http_exception.detail)} | execution_id={execution_id}",
        )

    summary_counts = _result_counts(target_rows, fallback_total=len(agent_ids))
    return {
        "agent": target,
        "action": action_id,
        "execution_id": execution_id,
        "status": execution_status,
        "channel": execution.get("channel") if execution else step_name,
        "mode": execution.get("mode") if execution else None,
        "command_used": execution.get("command_used") if execution else action_id,
        "attempts": execution.get("attempts") if execution else [action_id],
        "result": execution.get("result") if execution else {"ok": False},
        "summary": {
            **summary_counts,
            "remaining": max(0, summary_counts["total"] - summary_counts["completed"]),
            "percent_complete": (
                int(round((summary_counts["completed"] / max(1, summary_counts["total"])) * 100))
                if summary_counts["total"] > 0
                else 0
            ),
            "status": execution_status,
        },
        "post_action_verification": verification_result,
        "pending_verification_reconcile": reconcile_result,
    }
