from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request

from core.audit import log_audit
from core.scheduler import (
    create_job,
    list_jobs,
    run_scheduled_job,
    scheduler as core_scheduler,
    set_job_enabled,
    sync_policy_jobs,
    update_job,
    upsert_healthcheck_policy,
    upsert_integrity_sweep_policy,
)
from core.security import recent_auth_window_seconds, require_recent_auth, require_role

router = APIRouter(prefix="/scheduler")


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _require_scheduler_recent_auth(
    user,
    request: Request | None,
    *,
    action_label: str,
) -> None:
    require_recent_auth(
        user,
        request,
        max_age_seconds=recent_auth_window_seconds("scheduler_write", 7200),
        action_label=action_label,
    )


@router.get("")
def get_scheduled_jobs(user: dict = Depends(require_role("admin"))):
    org_id = user.get("org_id") if isinstance(user, dict) else None
    rows = list_jobs(org_id=org_id)
    return {
        "running": bool(core_scheduler.running),
        "jobs": rows,
    }


@router.get("/jobs")
def get_scheduled_jobs_alias(user: dict = Depends(require_role("admin"))):
    return get_scheduled_jobs(user=user)


@router.post("")
async def create_scheduled_job(request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    name = str(body.get("name") or "Scheduled Policy").strip()
    job_kind = str(body.get("job_kind") or body.get("kind") or "action").strip().lower() or "action"
    payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
    if job_kind == "shell":
        playbook = "global-shell"
        payload = {
            **payload,
            "command": str(
                payload.get("command")
                or body.get("command")
                or body.get("shell_command")
                or body.get("script")
                or ""
            ).strip(),
            "shell": str(payload.get("shell") or body.get("shell") or "powershell").strip().lower(),
            "run_as_system": _to_bool(payload.get("run_as_system") if "run_as_system" in payload else body.get("run_as_system"), False),
            "verify_kb": str(payload.get("verify_kb") or body.get("verify_kb") or "").strip(),
            "verify_min_build": str(payload.get("verify_min_build") or body.get("verify_min_build") or "").strip(),
            "verify_stdout_contains": str(payload.get("verify_stdout_contains") or body.get("verify_stdout_contains") or "").strip(),
        }
    elif job_kind == "playbook":
        playbook = str(body.get("playbook") or body.get("name") or "scheduled-playbook").strip() or "scheduled-playbook"
        if isinstance(body.get("playbook_payload"), dict) and "steps" in body.get("playbook_payload", {}):
            payload = {**payload, **body["playbook_payload"]}
        if isinstance(body.get("steps"), list):
            payload = {**payload, "steps": body.get("steps")}
    else:
        playbook = str(body.get("playbook") or body.get("action_id") or "endpoint-healthcheck").strip()
        if "args" in body and "args" not in payload:
            payload = {**payload, "args": body.get("args")}
    target = str(body.get("target") or body.get("agent_id") or "all").strip() or "all"
    cron = str(body.get("cron") or "").strip()
    interval_hours = body.get("interval_hours")
    if not cron:
        if interval_hours is not None:
            try:
                hours = max(1, int(interval_hours))
            except Exception as exc:
                raise HTTPException(status_code=400, detail="interval_hours must be an integer") from exc
        else:
            hours = 6
        cron = f"0 */{hours} * * *"
    enabled = _to_bool(body.get("enabled"), True)
    require_approval = _to_bool(body.get("require_approval"), False)
    org_id = user.get("org_id") if isinstance(user, dict) else None

    try:
        created = create_job(
            name=name,
            playbook=playbook,
            job_kind=job_kind,
            payload=payload if isinstance(payload, dict) else {},
            target=target,
            cron=cron,
            enabled=enabled,
            require_approval=require_approval,
            org_id=org_id,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to create scheduler job: {exc}") from exc
    actor = user.get("sub") if isinstance(user, dict) else "system"
    org_id = user.get("org_id") if isinstance(user, dict) else None
    log_audit(
        "scheduler_job_created",
        actor=actor,
        entity_type="scheduler_job",
        entity_id=str(created.get("id")) if isinstance(created, dict) else None,
        detail=f"name={created.get('name') if isinstance(created, dict) else name}",
        org_id=org_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "created", "job": created}


@router.post("/jobs")
async def create_scheduled_job_alias(request: Request, user: dict = Depends(require_role("admin"))):
    return await create_scheduled_job(request=request, user=user)


@router.post("/{job_id}/toggle")
async def toggle_job(job_id: int, request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    enabled = body.get("enabled")
    enabled_value = _to_bool(enabled) if enabled is not None else None
    try:
        job = set_job_enabled(job_id, enabled=enabled_value)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to toggle scheduler job: {exc}") from exc
    actor = user.get("sub") if isinstance(user, dict) else "system"
    org_id = user.get("org_id") if isinstance(user, dict) else None
    log_audit(
        "scheduler_job_toggled",
        actor=actor,
        entity_type="scheduler_job",
        entity_id=str(job_id),
        detail=f"enabled={job.get('enabled') if isinstance(job, dict) else enabled_value}",
        org_id=org_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "toggled", "job": job}


@router.patch("/jobs/{job_id}")
async def update_scheduler_job(job_id: int, request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    updates: Dict[str, Any] = {}
    if "name" in body:
        updates["name"] = str(body.get("name") or "").strip() or "Scheduled Policy"
    if "playbook" in body or "action_id" in body:
        updates["playbook"] = str(body.get("playbook") or body.get("action_id") or "").strip()
    if "job_kind" in body or "kind" in body:
        updates["job_kind"] = str(body.get("job_kind") or body.get("kind") or "").strip().lower() or "action"
    payload_from_body = body.get("payload") if isinstance(body.get("payload"), dict) else None
    if payload_from_body is not None:
        updates["payload"] = payload_from_body
    if "args" in body:
        updates["payload"] = {
            **(updates.get("payload") if isinstance(updates.get("payload"), dict) else {}),
            "args": body.get("args"),
        }
    if any(field in body for field in ("command", "shell_command", "script", "shell", "run_as_system", "verify_kb", "verify_min_build", "verify_stdout_contains")):
        updates["job_kind"] = str(updates.get("job_kind") or "shell").lower()
        updates["payload"] = {
            **(updates.get("payload") if isinstance(updates.get("payload"), dict) else {}),
            "command": str(
                body.get("command")
                or body.get("shell_command")
                or body.get("script")
                or ""
            ).strip(),
            "shell": str(body.get("shell") or "powershell").strip().lower(),
            "run_as_system": _to_bool(body.get("run_as_system"), False),
            "verify_kb": str(body.get("verify_kb") or "").strip(),
            "verify_min_build": str(body.get("verify_min_build") or "").strip(),
            "verify_stdout_contains": str(body.get("verify_stdout_contains") or "").strip(),
        }
        updates["playbook"] = "global-shell"
    if isinstance(body.get("playbook_payload"), dict):
        updates["job_kind"] = str(updates.get("job_kind") or "playbook").lower()
        updates["payload"] = {**body["playbook_payload"]}
        if "playbook" not in updates:
            updates["playbook"] = str(body.get("playbook") or "scheduled-playbook").strip() or "scheduled-playbook"
    if isinstance(body.get("steps"), list):
        updates["job_kind"] = str(updates.get("job_kind") or "playbook").lower()
        updates["payload"] = {
            **(updates.get("payload") if isinstance(updates.get("payload"), dict) else {}),
            "steps": body.get("steps"),
        }
        if "playbook" not in updates:
            updates["playbook"] = str(body.get("playbook") or "scheduled-playbook").strip() or "scheduled-playbook"
    if "target" in body or "agent_id" in body:
        updates["target"] = str(body.get("target") or body.get("agent_id") or "all").strip() or "all"

    interval_hours = body.get("interval_hours")
    if "cron" in body or interval_hours is not None:
        cron = str(body.get("cron") or "").strip()
        if not cron and interval_hours is not None:
            try:
                hours = max(1, int(interval_hours))
            except Exception as exc:
                raise HTTPException(status_code=400, detail="interval_hours must be an integer") from exc
            cron = f"0 */{hours} * * *"
        if cron:
            updates["cron"] = cron

    if "enabled" in body:
        updates["enabled"] = _to_bool(body.get("enabled"))
    if "require_approval" in body:
        updates["require_approval"] = _to_bool(body.get("require_approval"))

    if not updates:
        raise HTTPException(status_code=400, detail="No updatable fields provided")

    try:
        job = update_job(job_id, **updates)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to update scheduler job: {exc}") from exc
    actor = user.get("sub") if isinstance(user, dict) else "system"
    org_id = user.get("org_id") if isinstance(user, dict) else None
    log_audit(
        "scheduler_job_updated",
        actor=actor,
        entity_type="scheduler_job",
        entity_id=str(job_id),
        detail=f"fields={','.join(sorted(updates.keys()))}",
        org_id=org_id,
        ip_address=request.client.host if request.client else None,
    )
    return {"status": "updated", "job": job}


@router.post("/{job_id}/run")
def run_job_now(job_id: int, request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler execution")
    result = run_scheduled_job(job_id)
    actor = user.get("sub") if isinstance(user, dict) else "system"
    org_id = user.get("org_id") if isinstance(user, dict) else None
    log_audit(
        "scheduler_job_run_now_triggered",
        actor=actor,
        entity_type="scheduler_job",
        entity_id=str(job_id),
        detail=f"ok={bool(result.get('ok')) if isinstance(result, dict) else False}",
        org_id=org_id,
        ip_address=None,
    )
    return {"status": "triggered", "result": result}


@router.post("/jobs/{job_id}/run-now")
def run_job_now_alias(job_id: int, request: Request, user: dict = Depends(require_role("admin"))):
    return run_job_now(job_id=job_id, request=request, user=user)


@router.post("/policies/healthcheck")
async def upsert_healthcheck(request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    interval_hours = body.get("interval_hours", 6)
    enabled = _to_bool(body.get("enabled"), True)
    org_id = user.get("org_id") if isinstance(user, dict) else None
    try:
        policy = upsert_healthcheck_policy(
            interval_hours=int(interval_hours),
            org_id=org_id,
            enabled=enabled,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to upsert health-check policy: {exc}") from exc
    return {"status": "ok", "policy": policy}


@router.post("/policies/integrity-sweep")
async def upsert_integrity_sweep(request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    cron_value = body.get("cron")
    cron = str(cron_value).strip() if cron_value is not None else None
    enabled = _to_bool(body.get("enabled"), True)
    org_id = user.get("org_id") if isinstance(user, dict) else None
    try:
        policy = upsert_integrity_sweep_policy(
            cron=cron,
            org_id=org_id,
            enabled=enabled,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Failed to upsert integrity sweep policy: {exc}") from exc
    return {"status": "ok", "policy": policy}


@router.post("/sync")
def sync_jobs(request: Request, user: dict = Depends(require_role("admin"))):
    _require_scheduler_recent_auth(user, request, action_label="scheduler changes")
    sync_policy_jobs()
    org_id = user.get("org_id") if isinstance(user, dict) else None
    return {
        "status": "synced",
        "running": bool(core_scheduler.running),
        "jobs": list_jobs(org_id=org_id),
    }
