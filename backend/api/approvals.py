import json

from fastapi import APIRouter, Depends, HTTPException, Request

from core.actions import get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.approval_policy import get_policy
from core.audit import log_audit
from core.security import current_user, require_role, ROLE_LEVELS
from core.time_utils import serialize_row, utc_now_naive
from core.wazuh_client import WazuhClient
from db.database import connect
from sqlalchemy import text

router = APIRouter(prefix="/approvals")
client = WazuhClient()


def _serialize_row(row):
    return serialize_row(row) or {}


def _to_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
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


@router.post("/request")
async def request_approval(
    request: Request,
    agent_id: str | None = None,
    action_id: str | None = None,
    args: str | None = None,
    alert_id: str | None = None,
    case_id: int | None = None,
    group: str | None = None,
    justification: str | None = None,
    user=Depends(require_role("analyst")),
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
    alert_json = body.get("alert") or body.get("alert_json")
    justification = body.get("justification") or justification

    if not action_id or (not agent_id and not group and not agent_ids):
        raise HTTPException(status_code=400, detail="action_id and agent_id or group are required")

    if agent_ids:
        norm_ids = [str(a).strip() for a in agent_ids if str(a).strip()]
        if not norm_ids:
            raise HTTPException(status_code=400, detail="agent_ids must not be empty")
        agent_id = "multi:" + ",".join(norm_ids)

    if not agent_id and group:
        agent_id = f"group:{group}"

    action = get_action(action_id)
    arguments = normalize_args(action, args)
    policy = get_policy(action_id)
    if policy.get("justification_required") and not justification:
        raise HTTPException(status_code=400, detail="justification is required for this action")

    db = connect()
    requested_by = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None
    try:
        result = db.execute(
            text(
                """
                INSERT INTO approvals
                (agent, playbook, action, args, alert_id, alert_json, requested_by, status, org_id)
                VALUES (:agent, :playbook, :action, :args, :alert_id, :alert_json, :requested_by, :status, :org_id)
                RETURNING id
                """
            ),
            {
                "agent": agent_id,
                "playbook": action_id,
                "action": action_id,
                "args": json.dumps(arguments),
                "alert_id": alert_id,
                "alert_json": json.dumps(alert_json) if alert_json is not None else None,
                "requested_by": requested_by,
                "status": "PENDING",
                "org_id": org_id,
            },
        )

        approval_id = result.scalar()
        if justification:
            db.execute(
                text(
                    """
                    INSERT INTO approval_metadata (approval_id, justification)
                    VALUES (:approval_id, :justification)
                    """
                ),
                {"approval_id": approval_id, "justification": justification},
            )
        for req in policy.get("requirements", []):
            db.execute(
                text(
                    """
                    INSERT INTO approval_requirements
                    (approval_id, role, required_count, current_count, status)
                    VALUES (:approval_id, :role, :required_count, 0, 'PENDING')
                    """
                ),
                {
                    "approval_id": approval_id,
                    "role": req.get("role"),
                    "required_count": req.get("count", 1),
                },
            )
        target_cases = []
        if case_id:
            target_cases = [case_id]
        elif alert_id:
            from core.case_timeline import case_ids_for_alert, log_case_event

            target_cases = case_ids_for_alert(alert_id, conn=db)

        for cid in target_cases:
            msg = f"Approval requested for action {action_id}"
            if group:
                msg += f" on group {group}"
            log_case_event(
                cid,
                "approval_requested",
                message=msg,
                actor=requested_by,
                alert_id=alert_id,
                approval_id=approval_id,
                action=action_id,
                conn=db,
            )

        db.commit()
        log_audit(
            "approval_requested",
            actor=requested_by,
            entity_type="approval",
            entity_id=str(approval_id),
            detail=f"action={action_id}",
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "submitted", "id": approval_id}
    finally:
        db.close()


@router.get("/pending")
def pending(user=Depends(require_role("analyst"))):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    a.id,
                    a.agent,
                    COALESCE(a.action, a.playbook) AS action,
                    a.requested_by,
                    a.created_at,
                    a.alert_id,
                    COALESCE(SUM(r.required_count), 0) as required_total,
                    COALESCE(SUM(r.current_count), 0) as approved_total,
                    m.justification
                FROM approvals
                AS a
                LEFT JOIN approval_requirements r ON r.approval_id=a.id
                LEFT JOIN approval_metadata m ON m.approval_id=a.id
                WHERE a.status IN ('PENDING', 'IN_REVIEW')
                GROUP BY a.id, a.agent, a.action, a.playbook, a.requested_by, a.created_at, a.alert_id, m.justification
                ORDER BY a.created_at DESC
                """
            )
        ).fetchall()

        return [_serialize_row(row) for row in rows]
    finally:
        db.close()


@router.post("/{id}/approve")
def approve(id: int, request: Request, user=Depends(require_role("analyst"))):
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT status, agent, COALESCE(action, playbook) AS action, args, alert_id
                FROM approvals
                WHERE id=:id
                """
            ),
            {"id": id},
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Approval not found")

        status, agent_id, action_id, args, alert_id = row
        if status == "REJECTED":
            return {"status": "rejected"}
        if status == "APPROVED":
            return {"status": "already_approved"}

        action = get_action(action_id)
        arguments = normalize_args(action, args)
        dispatch = resolve_action_dispatch(action, arguments)

        approved_by = user.get("sub") if isinstance(user, dict) else str(user)
        org_id = user.get("org_id") if isinstance(user, dict) else None
        user_role = user.get("role") if isinstance(user, dict) else None
        user_level = ROLE_LEVELS.get(user_role, 0)

        existing = db.execute(
            text(
                """
                SELECT 1 FROM approval_decisions
                WHERE approval_id=:id AND decided_by=:decided_by
                LIMIT 1
                """
            ),
            {"id": id, "decided_by": approved_by},
        ).fetchone()
        if existing:
            return {"status": "already_voted"}

        req_rows = db.execute(
            text(
                """
                SELECT id, role, required_count, current_count
                FROM approval_requirements
                WHERE approval_id=:id
                ORDER BY id ASC
                """
            ),
            {"id": id},
        ).fetchall()
        if not req_rows:
            policy = get_policy(action_id)
            for req in policy.get("requirements", []):
                db.execute(
                    text(
                        """
                        INSERT INTO approval_requirements
                        (approval_id, role, required_count, current_count, status)
                        VALUES (:approval_id, :role, :required_count, 0, 'PENDING')
                        """
                    ),
                    {
                        "approval_id": id,
                        "role": req.get("role"),
                        "required_count": req.get("count", 1),
                    },
                )
            db.commit()
            req_rows = db.execute(
                text(
                    """
                    SELECT id, role, required_count, current_count
                    FROM approval_requirements
                    WHERE approval_id=:id
                    ORDER BY id ASC
                    """
                ),
                {"id": id},
            ).fetchall()

        eligible = []
        for req in req_rows:
            req_id, req_role, required_count, current_count = req
            req_level = ROLE_LEVELS.get(req_role, 0)
            if user_level >= req_level and (current_count or 0) < required_count:
                eligible.append((req_id, req_role, required_count, current_count, req_level))

        if not eligible:
            raise HTTPException(status_code=403, detail="No pending approvals for your role")

        eligible.sort(key=lambda r: r[4], reverse=True)
        req_id, req_role, required_count, current_count, _ = eligible[0]
        new_count = (current_count or 0) + 1
        req_status = "SATISFIED" if new_count >= required_count else "PENDING"

        db.execute(
            text(
                """
                UPDATE approval_requirements
                SET current_count=:current_count, status=:status
                WHERE id=:id
                """
            ),
            {"current_count": new_count, "status": req_status, "id": req_id},
        )
        db.execute(
            text(
                """
                INSERT INTO approval_decisions
                (approval_id, decided_by, role, decision)
                VALUES (:approval_id, :decided_by, :role, 'APPROVED')
                """
            ),
            {"approval_id": id, "decided_by": approved_by, "role": req_role},
        )
        db.commit()

        log_audit(
            "approval_decision",
            actor=approved_by,
            entity_type="approval",
            entity_id=str(id),
            detail=f"role={req_role}",
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )

        pending_left = db.execute(
            text(
                """
                SELECT COUNT(*) FROM approval_requirements
                WHERE approval_id=:id AND current_count < required_count
                """
            ),
            {"id": id},
        ).scalar() or 0
        if pending_left > 0:
            db.execute(
                text("UPDATE approvals SET status='IN_REVIEW' WHERE id=:id"),
                {"id": id},
            )
            db.commit()
            return {"status": "pending", "remaining": pending_left}

        group = None
        if isinstance(agent_id, str) and agent_id.startswith("group:"):
            group = agent_id.split(":", 1)[1]
        agent_ids = resolve_agent_ids(client, target=agent_id, group=group)

        start = utc_now_naive()

        result = db.execute(
            text(
                """
                INSERT INTO executions
                (approval_id, agent, playbook, action, args, status, approved_by, started_at, alert_id, org_id)
                VALUES (:approval_id, :agent, :playbook, :action, :args, :status, :approved_by, :started_at, :alert_id, :org_id)
                RETURNING id
                """
            ),
            {
                "approval_id": id,
                "agent": agent_id,
                "playbook": action_id,
                "action": action_id,
                "args": json.dumps(arguments),
                "status": "RUNNING",
                "approved_by": approved_by,
                "started_at": start,
                "alert_id": alert_id,
                "org_id": org_id,
            },
        )
        execution_id = result.scalar()
        db.commit()

        # Persist justification on the execution record for operator visibility.
        try:
            just_row = db.execute(
                text(
                    """
                    SELECT justification FROM approval_metadata
                    WHERE approval_id=:approval_id
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                ),
                {"approval_id": id},
            ).fetchone()
            if just_row and just_row[0]:
                db.execute(
                    text(
                        """
                        INSERT INTO execution_metadata (execution_id, justification)
                        VALUES (:execution_id, :justification)
                        """
                    ),
                    {"execution_id": execution_id, "justification": str(just_row[0])},
                )
                db.commit()
        except Exception:
            # Never block action execution on metadata writes.
            pass

        from core.case_timeline import case_ids_for_alert, log_case_event
        target_cases = case_ids_for_alert(alert_id, conn=db) if alert_id else []
        for cid in target_cases:
            msg = f"Execution started for action {action_id}"
            if group:
                msg += f" on group {group}"
            log_case_event(
                cid,
                "execution_started",
                message=msg,
                actor=approved_by,
                alert_id=alert_id,
                approval_id=id,
                execution_id=execution_id,
                action=action_id,
                conn=db,
            )

        status = "SUCCESS"
        step_status = "SUCCESS"
        stdout = ""
        stderr = ""
        step_name = "orchestration"
        target_rows = None

        try:
            execution = execute_action(client, action_id, dispatch, agent_ids, execution_id=int(execution_id))
            stdout = json.dumps(execution.get("result"))
            step_name = execution.get("channel") or "orchestration"
            step_detail = f"channel={execution.get('channel')}; command={execution.get('command_used')}"
            if execution.get("attempts"):
                step_detail += f"; attempts={','.join(execution.get('attempts'))}"
            stdout = f"{step_detail}\n{stdout}"
            result_payload = execution.get("result")
            if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                target_rows = result_payload.get("results")
        except HTTPException as exc:
            status = "FAILED"
            step_status = "FAILED"
            if isinstance(exc.detail, dict):
                step_name = "endpoint"
                stderr = _to_text(exc.detail.get("message") or exc.detail)
            else:
                stderr = _to_text(exc.detail)
            if isinstance(exc.detail, dict):
                result_payload = exc.detail.get("result")
                if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                    target_rows = result_payload.get("results")
        except Exception as exc:
            status = "FAILED"
            step_status = "FAILED"
            stderr = _to_text(exc)

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
                "stdout": stdout,
                "stderr": stderr,
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
            {"status": status, "finished_at": utc_now_naive(), "id": execution_id},
        )
        # If an operator killed/cancelled this execution mid-flight, do not overwrite their decision.
        try:
            current_status = (
                db.execute(
                    text("SELECT status FROM executions WHERE id=:id"),
                    {"id": execution_id},
                ).scalar()
                or ""
            )
        except Exception:
            current_status = ""
        if str(current_status).upper() in {"KILLED", "CANCELLED"}:
            # Keep operator-set status/finished_at; still persist steps/targets for auditability.
            pass
        else:
            db.execute(
                text(
                    """
                    UPDATE executions
                    SET status=:status, finished_at=:finished_at
                    WHERE id=:id
                    """
                ),
                {"status": status, "finished_at": utc_now_naive(), "id": execution_id},
            )
        if target_rows:
            _store_execution_targets(db, int(execution_id), target_rows)

        db.execute(
            text(
                """
                UPDATE approvals
                SET status='APPROVED', decided_at=:decided_at
                WHERE id=:id
                """
            ),
            {"decided_at": utc_now_naive(), "id": id},
        )

        for cid in target_cases:
            approve_msg = f"Approval approved for action {action_id}"
            finish_msg = f"Execution finished with status {status}"
            if group:
                approve_msg += f" on group {group}"
                finish_msg += f" on group {group}"
            log_case_event(
                cid,
                "approval_approved",
                message=approve_msg,
                actor=approved_by,
                alert_id=alert_id,
                approval_id=id,
                execution_id=execution_id,
                action=action_id,
                conn=db,
            )
            log_case_event(
                cid,
                "execution_finished",
                message=finish_msg,
                actor=approved_by,
                alert_id=alert_id,
                approval_id=id,
                execution_id=execution_id,
                action=action_id,
                conn=db,
            )

        db.commit()
        log_audit(
            "execution_finished",
            actor=approved_by,
            entity_type="execution",
            entity_id=str(execution_id),
            detail=f"status={status}",
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "executed", "execution_id": execution_id}
    finally:
        db.close()


@router.post("/{id}/reject")
def reject(id: int, request: Request, user=Depends(require_role("admin"))):
    db = connect()
    try:
        db.execute(
            text("UPDATE approvals SET status='REJECTED', decided_at=:decided_at WHERE id=:id"),
            {"decided_at": utc_now_naive(), "id": id},
        )
        actor = user.get("sub") if isinstance(user, dict) else str(user)
        role = user.get("role") if isinstance(user, dict) else None
        db.execute(
            text(
                """
                INSERT INTO approval_decisions
                (approval_id, decided_by, role, decision)
                VALUES (:approval_id, :decided_by, :role, 'REJECTED')
                """
            ),
            {"approval_id": id, "decided_by": actor, "role": role},
        )
        from core.case_timeline import case_ids_for_alert, log_case_event
        row = db.execute(
            text("SELECT alert_id, COALESCE(action, playbook) AS action FROM approvals WHERE id=:id"),
            {"id": id},
        ).fetchone()
        alert_id = row[0] if row else None
        action_id = row[1] if row else None
        agent_row = db.execute(
            text("SELECT agent FROM approvals WHERE id=:id"),
            {"id": id},
        ).fetchone()
        group = None
        if agent_row and isinstance(agent_row[0], str) and agent_row[0].startswith("group:"):
            group = agent_row[0].split(":", 1)[1]
        target_cases = case_ids_for_alert(alert_id, conn=db) if alert_id else []
        for cid in target_cases:
            msg = f"Approval rejected for action {action_id}"
            if group:
                msg += f" on group {group}"
            log_case_event(
                cid,
                "approval_rejected",
                message=msg,
                actor=actor,
                alert_id=alert_id,
                approval_id=id,
                action=action_id,
                conn=db,
            )

        db.commit()
        log_audit(
            "approval_rejected",
            actor=actor,
            entity_type="approval",
            entity_id=str(id),
            detail=f"action={action_id}",
            org_id=user.get("org_id") if isinstance(user, dict) else None,
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "rejected"}
    finally:
        db.close()


@router.get("/executions")
def executions(user=Depends(current_user)):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    id,
                    agent,
                    COALESCE(action, playbook) AS action,
                    status,
                    approved_by,
                    started_at,
                    finished_at
                FROM executions
                ORDER BY started_at DESC
                """
            )
        ).fetchall()
        return [_serialize_row(row) for row in rows]
    finally:
        db.close()


@router.get("/executions/{id}")
def execution_detail(id: int, user=Depends(current_user)):
    db = connect()
    try:
        steps = db.execute(
            text("SELECT step, stdout, stderr, status FROM execution_steps WHERE execution_id=:id"),
            {"id": id},
        ).fetchall()
        return [_serialize_row(row) for row in steps]
    finally:
        db.close()
