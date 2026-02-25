import json

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool
from sqlalchemy import text

from core.actions import get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.audit import log_audit
from core.security import require_role
from core.time_utils import utc_now_naive
from core.ws_bus import publish_event
from core.wazuh_client import WazuhClient
from core.wazuh_verification import run_post_action_verification
from db.database import connect

router = APIRouter()
client = WazuhClient()


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
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []

    if not action_id or (not agent_id and not group and not agent_ids):
        raise HTTPException(status_code=400, detail="action_id and agent_id or group are required")

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

    db = connect()
    execution_id = None
    execution = None
    step_name = "orchestration"
    step_stdout = ""
    step_stderr = ""
    verification_result = None
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
                "args": json.dumps(arguments, default=str),
                "status": "RUNNING",
                "approved_by": actor,
                "started_at": started_at,
                "alert_id": alert_id,
                "org_id": org_id,
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
                verification_result = await run_in_threadpool(
                    lambda: run_post_action_verification(
                        client,
                        action_id,
                        int(execution_id) if execution_id is not None else None,
                        target_rows or [],
                    )
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
        if target_rows:
            _store_execution_targets(db, int(execution_id), target_rows)
        if isinstance(verification_result, dict) and not verification_result.get("skipped"):
            verification_ok = bool(verification_result.get("ok"))
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
                    "stderr": "" if verification_ok else "Post-action verification did not fully complete",
                    "status": "SUCCESS" if verification_ok else "FAILED",
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
        "post_action_verification": verification_result,
    }
