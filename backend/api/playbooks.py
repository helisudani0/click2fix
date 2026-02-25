import json
import os
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text

from core.actions import get_action, normalize_args, resolve_action_dispatch
from core.action_execution import execute_action, resolve_agent_ids
from core.audit import log_audit
from core.playbook_generator import (
    build_playbook_path,
    generate_playbook,
    save_playbook,
)
from core.security import require_role
from core.settings import SETTINGS
from core.time_utils import utc_now_naive
from core.ws_bus import publish_event
from core.wazuh_client import WazuhClient
from core.wazuh_verification import run_post_action_verification
from db.database import connect


router = APIRouter()
PLAYBOOK_DIR = (
    SETTINGS.get("playbooks_path")
    if isinstance(SETTINGS, dict) and SETTINGS.get("playbooks_path")
    else "./playbooks"
)

DEFAULT_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "soc_windows_malware_containment.json": {
        "name": "SOC Windows Malware Containment",
        "description": "Contain suspicious malware behavior on a Windows endpoint.",
        "steps": [
            {
                "id": "kill_suspicious_process",
                "action": "kill-process",
                "args": {"pid": "1234"},
                "reason": "Stop suspicious process execution quickly.",
            },
            {
                "id": "quarantine_payload",
                "action": "quarantine-file",
                "args": {"path": "C:\\\\Temp\\\\suspect.exe"},
                "reason": "Prevent re-execution of malicious file.",
            },
            {
                "id": "block_hash",
                "action": "hash-blocklist",
                "args": {
                    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                },
                "reason": "Block known-bad artifact across endpoint checks.",
            },
            {
                "id": "collect_triage",
                "action": "collect-forensics",
                "args": {},
                "reason": "Capture evidence for investigation.",
            },
            {
                "id": "collect_memory",
                "action": "collect-memory",
                "args": {},
                "reason": "Capture volatile indicators before reboot/cleanup.",
            },
        ],
    },
    "soc_network_ioc_containment.json": {
        "name": "SOC Network IOC Containment",
        "description": "Contain known-bad network indicators tied to an alert.",
        "steps": [
            {
                "id": "block_ip_firewall",
                "action": "firewall-drop",
                "args": {"ip": "1.2.3.4"},
                "reason": "Immediate network containment.",
            },
            {
                "id": "host_deny",
                "action": "host-deny",
                "args": {"ip": "1.2.3.4"},
                "reason": "Add defense-in-depth deny rule.",
            },
            {
                "id": "hunt_ioc_set",
                "action": "ioc-scan",
                "args": {"ioc_set": "campaign-2026-02"},
                "reason": "Hunt for campaign indicators.",
            },
        ],
    },
    "soc_windows_vulnerability_remediation.json": {
        "name": "SOC Windows Vulnerability Remediation",
        "description": "Patch and validate a vulnerable Windows endpoint.",
        "steps": [
            {
                "id": "patch_windows",
                "action": "patch-windows",
                "args": {},
                "reason": "Apply endpoint security updates.",
            },
            {
                "id": "sca_rescan",
                "action": "sca-rescan",
                "args": {},
                "reason": "Re-validate compliance posture post patching.",
            },
            {
                "id": "restart_wazuh",
                "action": "restart-wazuh",
                "args": {},
                "reason": "Ensure telemetry and policy checks recover cleanly.",
            },
        ],
    },
    "soc_linux_vulnerability_remediation.json": {
        "name": "SOC Linux Vulnerability Remediation",
        "description": "Patch and validate a vulnerable Linux endpoint.",
        "steps": [
            {
                "id": "patch_linux",
                "action": "patch-linux",
                "args": {},
                "reason": "Apply Linux package updates.",
            },
            {
                "id": "sca_rescan",
                "action": "sca-rescan",
                "args": {},
                "reason": "Re-run compliance checks.",
            },
            {
                "id": "persistence_hunt",
                "action": "threat-hunt-persistence",
                "args": {},
                "reason": "Check startup/persistence artifacts after patching.",
            },
        ],
    },
    "soc_suspicious_login_response.json": {
        "name": "SOC Suspicious Login Response",
        "description": "Respond to suspicious account activity and capture evidence.",
        "steps": [
            {
                "id": "disable_account",
                "action": "disable-account",
                "args": {"user": "suspicious_user"},
                "reason": "Contain potentially compromised identity.",
            },
            {
                "id": "collect_forensics",
                "action": "collect-forensics",
                "args": {},
                "reason": "Capture host context for triage.",
            },
            {
                "id": "ioc_hunt",
                "action": "ioc-scan",
                "args": {"ioc_set": "identity-compromise-baseline"},
                "reason": "Validate compromise spread.",
            },
        ],
    },
    "soc_ransomware_emergency.json": {
        "name": "SOC Ransomware Emergency",
        "description": "Emergency containment for probable ransomware execution.",
        "steps": [
            {
                "id": "kill_encryptor",
                "action": "kill-process",
                "args": {"pid": "1234"},
                "reason": "Stop active encryption quickly.",
            },
            {
                "id": "block_c2_ip",
                "action": "firewall-drop",
                "args": {"ip": "1.2.3.4"},
                "reason": "Cut command-and-control traffic.",
            },
            {
                "id": "quarantine_dropper",
                "action": "quarantine-file",
                "args": {"path": "C:\\\\Users\\\\Public\\\\payload.exe"},
                "reason": "Prevent relaunch after process kill.",
            },
            {
                "id": "collect_memory",
                "action": "collect-memory",
                "args": {},
                "reason": "Preserve volatile artifacts.",
            },
            {
                "id": "collect_forensics",
                "action": "collect-forensics",
                "args": {},
                "reason": "Capture triage package for incident timeline.",
            },
        ],
    },
    "soc_threat_hunt_endpoint_sweep.json": {
        "name": "SOC Threat Hunt Endpoint Sweep",
        "description": "Run baseline hunting checks for endpoint compromise.",
        "steps": [
            {
                "id": "ioc_scan",
                "action": "ioc-scan",
                "args": {"ioc_set": "baseline-global"},
                "reason": "Search for known malicious indicators.",
            },
            {
                "id": "yara_scan",
                "action": "yara-scan",
                "args": {"path": "C:\\\\Users"},
                "reason": "Inspect user space for malware patterns.",
            },
            {
                "id": "persistence_hunt",
                "action": "threat-hunt-persistence",
                "args": {},
                "reason": "Validate persistence mechanisms.",
            },
        ],
    },
    "soc_post_incident_hardening.json": {
        "name": "SOC Post-Incident Hardening",
        "description": "Post-remediation hardening and telemetry reset.",
        "steps": [
            {
                "id": "sca_rescan",
                "action": "sca-rescan",
                "args": {},
                "reason": "Measure policy compliance after cleanup.",
            },
            {
                "id": "service_restart",
                "action": "service-restart",
                "args": {"service": "wuauserv"},
                "reason": "Stabilize affected service after remediation.",
            },
            {
                "id": "restart_wazuh",
                "action": "restart-wazuh",
                "args": {},
                "reason": "Refresh endpoint telemetry channel.",
            },
        ],
    },
}

client = WazuhClient()


def _list_playbooks() -> list[str]:
    if not os.path.isdir(PLAYBOOK_DIR):
        return []
    return sorted([f for f in os.listdir(PLAYBOOK_DIR) if f.endswith(".json")])


def _seed_default_playbooks(force: bool = False) -> list[str]:
    os.makedirs(PLAYBOOK_DIR, exist_ok=True)
    written: list[str] = []
    for filename, payload in DEFAULT_PLAYBOOKS.items():
        path = os.path.join(PLAYBOOK_DIR, filename)
        if force or not os.path.exists(path):
            save_playbook(path, payload)
            written.append(filename)
    return written


def _normalize_steps(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    steps = payload.get("steps")
    if isinstance(steps, list):
        return [s for s in steps if isinstance(s, dict)]
    tasks = payload.get("tasks")
    if isinstance(tasks, list):
        # Legacy format: treat tasks as steps
        return [t for t in tasks if isinstance(t, dict)]
    return []


def _to_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except Exception:
        return str(value)


def _to_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


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


@router.get("")
def list_playbooks(user=Depends(require_role("analyst"))):
    playbooks = _list_playbooks()
    if not playbooks:
        _seed_default_playbooks(force=False)
        playbooks = _list_playbooks()
    return playbooks


@router.get("/{name}")
def get_playbook(name: str, user=Depends(require_role("analyst"))):
    path = build_playbook_path(PLAYBOOK_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Playbook not found")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


@router.post("")
async def create_playbook(request: Request, user=Depends(require_role("admin"))):
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    name = body.get("name") or body.get("filename") or "generated-playbook"
    payload = body.get("payload") or body.get("playbook") or body

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid playbook payload")

    path = build_playbook_path(PLAYBOOK_DIR, name)
    save_playbook(path, payload)
    return {"status": "saved", "name": os.path.basename(path)}


@router.post("/seed-defaults")
async def seed_defaults(request: Request, user=Depends(require_role("admin"))):
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}
    force = bool(body.get("force", False))
    written = _seed_default_playbooks(force=force)
    return {"status": "ok", "seeded": written, "count": len(written)}


@router.post("/generate")
async def generate(request: Request, user=Depends(require_role("analyst"))):
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    alert_id = body.get("alert_id")
    case_id = body.get("case_id")
    playbook = generate_playbook(alert_id=alert_id, case_id=case_id)
    return playbook


@router.post("/execute")
async def execute_playbook(request: Request, user=Depends(require_role("admin"))):
    """
    Execute a stored playbook (multi-step action plan) against an agent/group/fleet/multi target.
    Creates a single execution record with per-step execution_steps output.
    """
    body: Dict[str, Any] = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    name = body.get("name") or body.get("playbook") or body.get("playbook_name")
    payload = body.get("payload") or body.get("playbook_payload")

    agent_id = body.get("agent_id")
    agent_ids = body.get("agent_ids") or body.get("agents")
    group = body.get("group")
    alert_id = body.get("alert_id")
    case_id = body.get("case_id")
    justification = body.get("justification") or body.get("reason")
    exclude_agent_ids = body.get("exclude_agent_ids") or body.get("exclude_agents") or []
    dry_run = _to_bool(body.get("dry_run"), False)

    if not payload:
        if not name:
            raise HTTPException(status_code=400, detail="playbook name or payload is required")
        path = build_playbook_path(PLAYBOOK_DIR, str(name))
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="Playbook not found")
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle) or {}

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid playbook payload")

    steps = _normalize_steps(payload)
    if not steps:
        raise HTTPException(status_code=400, detail="Playbook has no steps to execute")

    if not agent_id and not group and not agent_ids:
        raise HTTPException(status_code=400, detail="agent_id, agent_ids or group is required")

    target = agent_id if agent_id else f"group:{group}"
    if agent_ids:
        norm_ids = [str(a).strip() for a in agent_ids if str(a).strip()]
        if not norm_ids:
            raise HTTPException(status_code=400, detail="agent_ids must not be empty")
        target = "multi:" + ",".join(norm_ids)
        resolved_agent_ids = norm_ids
    else:
        resolved_agent_ids = resolve_agent_ids(client, target=target, group=group)
    if exclude_agent_ids:
        exclude_norm = {str(a).strip() for a in exclude_agent_ids if str(a).strip()}
        resolved_agent_ids = [a for a in resolved_agent_ids if str(a).strip() not in exclude_norm]
    if not resolved_agent_ids:
        raise HTTPException(status_code=404, detail="No agents resolved for target")

    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None

    playbook_label = payload.get("name") or (str(name) if name else "Playbook")
    playbook_file = str(name) if name else playbook_label

    if dry_run:
        resolved_plan: List[Dict[str, Any]] = []
        for idx, step in enumerate(steps):
            step_id = str(step.get("id") or step.get("action") or f"step_{idx+1}")
            step_action = step.get("action") or step.get("command") or step.get("id")
            if not step_action:
                raise HTTPException(status_code=400, detail=f"Step '{step_id}' has no action")
            action = get_action(str(step_action))
            arguments = normalize_args(action, step.get("args"))
            dispatch = resolve_action_dispatch(action, arguments)
            resolved_plan.append(
                {
                    "step_id": step_id,
                    "action_id": str(step_action),
                    "args": arguments,
                    "command": dispatch.get("command"),
                    "arguments": dispatch.get("arguments") or [],
                    "attempts": dispatch.get("attempts") or [],
                }
            )

        simulation_detail = json.dumps(
            {
                "playbook": playbook_label,
                "target": target,
                "resolved_agents": resolved_agent_ids,
                "resolved_plan": resolved_plan,
            },
            default=str,
        )
        log_audit(
            "playbook_simulated",
            actor=actor,
            entity_type="playbook",
            entity_id=playbook_file,
            detail=simulation_detail,
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
        )
        return {
            "status": "SIMULATED",
            "dry_run": True,
            "playbook": playbook_file,
            "target": target,
            "resolved_agents": resolved_agent_ids,
            "resolved_plan": resolved_plan,
        }

    db = connect()
    execution_id = None
    overall_status = "SUCCESS"
    target_rows: Dict[str, Dict[str, Any]] = {}
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
                "playbook": playbook_file,
                "action": None,
                "args": json.dumps({"steps": steps}, default=str),
                "status": "RUNNING",
                "approved_by": actor,
                "started_at": started_at,
                "alert_id": alert_id,
                "org_id": org_id,
            },
        )
        execution_id = int(inserted.scalar())
        db.commit()

        if justification:
            db.execute(
                text(
                    """
                    INSERT INTO execution_metadata (execution_id, justification)
                    VALUES (:execution_id, :justification)
                    """
                ),
                {"execution_id": execution_id, "justification": str(justification)},
            )
            db.commit()

        publish_event(
            execution_id,
            {
                "type": "execution_started",
                "step": "playbook",
                "status": "RUNNING",
                "stdout": f"playbook={playbook_label}; steps={len(steps)}; target={target}",
                "stderr": "",
            },
        )

        for idx, step in enumerate(steps):
            step_id = str(step.get("id") or step.get("action") or f"step_{idx+1}")
            step_action = step.get("action") or step.get("command") or step.get("id")
            if not step_action:
                overall_status = "FAILED"
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
                        "step": step_id,
                        "stdout": "",
                        "stderr": "Step action is missing",
                        "status": "FAILED",
                    },
                )
                break

            publish_event(
                execution_id,
                {
                    "type": "step_start",
                    "step": step_id,
                    "status": "RUNNING",
                    "stdout": f"action={step_action}",
                    "stderr": "",
                },
            )

            try:
                action = get_action(str(step_action))
                arguments = normalize_args(action, step.get("args"))
                dispatch = resolve_action_dispatch(action, arguments)
                execution = execute_action(
                    client,
                    str(step_action),
                    dispatch,
                    resolved_agent_ids,
                    execution_id=execution_id,
                )
                result_payload = execution.get("result")
                if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                    for row in result_payload.get("results") or []:
                        if not isinstance(row, dict):
                            continue
                        aid = str(row.get("agent_id") or "").strip()
                        if aid:
                            target_rows[aid] = row
                detail = f"channel={execution.get('channel')}; command={execution.get('command_used')}"
                if execution.get("attempts"):
                    detail += f"; attempts={','.join(execution.get('attempts'))}"
                stdout = f"{detail}\n{json.dumps(execution.get('result'), default=str)}"
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
                        "step": step_id,
                        "stdout": stdout,
                        "stderr": "",
                        "status": "SUCCESS",
                    },
                )
                db.commit()
                publish_event(
                    execution_id,
                    {
                        "type": "step_done",
                        "step": step_id,
                        "status": "SUCCESS",
                        "stdout": f"action={step_action}",
                        "stderr": "",
                    },
                )
                if (
                    isinstance(result_payload, dict)
                    and isinstance(result_payload.get("results"), list)
                ):
                    verification_result = run_post_action_verification(
                        client,
                        str(step_action),
                        execution_id,
                        result_payload.get("results") or [],
                    )
                    if not verification_result.get("skipped"):
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
                                "step": f"{step_id}:post_verify",
                                "stdout": json.dumps(verification_result, default=str),
                                "stderr": "" if verification_ok else "Post-action verification did not fully complete",
                                "status": "SUCCESS" if verification_ok else "FAILED",
                            },
                        )
                        db.commit()
                        publish_event(
                            execution_id,
                            {
                                "type": "step_done" if verification_ok else "step_failed",
                                "step": f"{step_id}:post_verify",
                                "status": "SUCCESS" if verification_ok else "FAILED",
                                "stdout": json.dumps(verification_result.get("summary", {}), default=str),
                                "stderr": "" if verification_ok else "verification_timeout_or_trigger_failure",
                            },
                        )
            except HTTPException as exc:
                overall_status = "FAILED"
                err_text = exc.detail.get("message") if isinstance(exc.detail, dict) else exc.detail
                if isinstance(exc.detail, dict):
                    result_payload = exc.detail.get("result")
                    if isinstance(result_payload, dict) and isinstance(result_payload.get("results"), list):
                        for row in result_payload.get("results") or []:
                            if not isinstance(row, dict):
                                continue
                            aid = str(row.get("agent_id") or "").strip()
                            if aid:
                                target_rows[aid] = row
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
                        "step": step_id,
                        "stdout": "",
                        "stderr": json.dumps(err_text, default=str) if not isinstance(err_text, str) else str(err_text),
                        "status": "FAILED",
                    },
                )
                db.commit()
                publish_event(
                    execution_id,
                    {
                        "type": "step_failed",
                        "step": step_id,
                        "status": "FAILED",
                        "stdout": "",
                        "stderr": str(err_text),
                    },
                )
                break
            except Exception as exc:
                overall_status = "FAILED"
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
                        "step": step_id,
                        "stdout": "",
                        "stderr": str(exc),
                        "status": "FAILED",
                    },
                )
                db.commit()
                publish_event(
                    execution_id,
                    {
                        "type": "step_failed",
                        "step": step_id,
                        "status": "FAILED",
                        "stdout": "",
                        "stderr": str(exc),
                    },
                )
                break

        db.execute(
            text(
                """
                UPDATE executions
                SET status=:status, finished_at=:finished_at
                WHERE id=:id
                """
            ),
            {"status": overall_status, "finished_at": utc_now_naive(), "id": execution_id},
        )
        if target_rows:
            _store_execution_targets(db, execution_id, list(target_rows.values()))
        db.commit()
    finally:
        db.close()

    log_audit(
        "playbook_executed",
        actor=actor,
        entity_type="execution",
        entity_id=str(execution_id) if execution_id is not None else playbook_file,
        detail=f"playbook={playbook_label}; target={target}; status={overall_status}",
        org_id=org_id,
        ip_address=request.client.host if request.client else None,
    )

    return {
        "execution_id": execution_id,
        "status": overall_status,
        "playbook": playbook_file,
        "target": target,
    }
