import json
import os
from typing import Any, Dict, Iterable, List

from fastapi import HTTPException

try:
    from core.active_defense import action_requires_approval_handshake, partition_adaptive_window_targets
except ImportError:  # Backward-compatible fallback for v1.1.x deployments.
    def action_requires_approval_handshake(*_args, **_kwargs):
        return False

    def partition_adaptive_window_targets(agent_ids, tenant_id=None):
        ready = [str(agent_id).strip() for agent_id in (agent_ids or []) if str(agent_id).strip()]
        return {
            "ready": ready,
            "deferred": [],
            "states": [
                {
                    "agent_id": agent_id,
                    "status": "ready",
                    "reason": "active_defense_unavailable",
                    "tenant_id": tenant_id,
                }
                for agent_id in ready
            ],
        }
from core.endpoint_executor import EndpointExecutor
from core.settings import SETTINGS
from core.ws_bus import publish_event


def is_command_undefined(detail: str) -> bool:
    text = (detail or "").lower()
    return (
        "command used is not defined in the configuration" in text
        or "code': 1652" in text
        or '"code": 1652' in text
    )


def _active_response_enabled() -> bool:
    raw = os.getenv("C2F_DISABLE_ACTIVE_RESPONSE")
    if isinstance(raw, str) and raw.strip().lower() in {"1", "true", "yes", "on"}:
        return False
    cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
    return bool(cfg.get("enabled", False))


def orchestration_mode() -> str:
    env_mode = os.getenv("C2F_ORCHESTRATION_MODE", "").strip().lower()
    cfg_mode = ""
    if isinstance(SETTINGS, dict):
        cfg_mode = str((SETTINGS.get("orchestration", {}) or {}).get("mode", "")).strip().lower()
    mode = env_mode or cfg_mode or "endpoint"
    aliases = {
        "endpoint": "endpoint",
        "direct": "endpoint",
        "direct_endpoint": "endpoint",
        "active_response": "active_response",
        "active-response": "active_response",
        "ar": "active_response",
        "hybrid": "hybrid",
    }
    resolved = aliases.get(mode, "endpoint")
    if resolved in {"active_response", "hybrid"} and not _active_response_enabled():
        return "endpoint"
    return resolved


def _active_response_endpoint_fallback_enabled() -> bool:
    if not _active_response_enabled():
        return False
    if not isinstance(SETTINGS, dict):
        return False
    cfg = SETTINGS.get("orchestration", {}) or {}
    value = cfg.get("active_response_fallback_to_endpoint", False)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _requires_endpoint_transport(action_id: str, dispatch: Dict[str, Any]) -> bool:
    requested = str(action_id or "").strip().lower()
    resolved = str((dispatch or {}).get("action_command") or "").strip().lower()
    return requested == "global-shell" or resolved == "custom-os-command"


def _resolve_manager_api_action(action_id: str, dispatch: Dict[str, Any]) -> str:
    candidates = [
        str(action_id or "").strip().lower(),
        str((dispatch or {}).get("action_command") or "").strip().lower(),
        str((dispatch or {}).get("command") or "").strip().lower(),
    ]
    for candidate in candidates:
        if candidate in {"restart-wazuh", "restart-agent", "agent-restart"}:
            return "restart-agent"
        # Best-effort: Wazuh doesn't expose a dedicated "run SCA now" API in all deployments.
        # Restarting the agent is a reliable way to trigger a fresh module cycle, including SCA.
        if candidate in {"sca-rescan", "sca_rescan", "sca"}:
            return "restart-agent"
    return ""


def _manager_api_supported(action_id: str, dispatch: Dict[str, Any]) -> bool:
    return bool(_resolve_manager_api_action(action_id, dispatch))


def _execution_batch_size() -> int:
    cfg_value = ""
    if isinstance(SETTINGS, dict):
        cfg_value = str((SETTINGS.get("orchestration", {}) or {}).get("batch_size", "")).strip()
    raw = os.getenv("C2F_EXECUTION_BATCH_SIZE", cfg_value)
    try:
        return max(1, min(int(raw), 100))
    except Exception:
        return 20


def _execution_batch_threshold() -> int:
    cfg_value = ""
    if isinstance(SETTINGS, dict):
        cfg_value = str((SETTINGS.get("orchestration", {}) or {}).get("batch_threshold", "")).strip()
    raw = os.getenv("C2F_EXECUTION_BATCH_THRESHOLD", cfg_value)
    try:
        return max(2, int(raw))
    except Exception:
        return max(21, _execution_batch_size() + 1)


def _result_status(result: Dict[str, Any]) -> str:
    payload = result if isinstance(result, dict) else {}
    total = int(payload.get("total") or 0)
    success = int(payload.get("success") or 0)
    failed = int(payload.get("failed") or 0)
    if total <= 0 and "ok" in payload:
        return "SUCCESS" if bool(payload.get("ok")) else "FAILED"
    if total > 0 and success > 0 and failed > 0:
        return "PARTIAL"
    if total > 0 and success > 0 and failed == 0:
        return "SUCCESS"
    return "FAILED"


def _progress_state(*, total: int, success: int, failed: int, completed: int | None = None) -> Dict[str, Any]:
    total_targets = max(0, int(total or 0))
    done = max(0, int(completed if completed is not None else success + failed))
    succeeded = max(0, int(success or 0))
    failed_targets = max(0, int(failed or 0))
    remaining = max(0, total_targets - done)
    status = "PARTIAL" if done < total_targets else _result_status(
        {
            "total": total_targets,
            "success": succeeded,
            "failed": failed_targets,
        }
    )
    percent_complete = int(round((done / total_targets) * 100)) if total_targets > 0 else 0
    return {
        "total": total_targets,
        "completed": done,
        "success": succeeded,
        "failed": failed_targets,
        "remaining": remaining,
        "percent_complete": percent_complete,
        "status": status,
    }


def _should_batch_endpoint_execution(
    *,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    mode: str,
    manager_api_action: str,
) -> bool:
    target_count = len([str(a).strip() for a in (agent_ids or []) if str(a).strip()])
    if target_count < _execution_batch_threshold():
        return False
    if manager_api_action:
        return False
    return mode in {"endpoint", "hybrid"} or _requires_endpoint_transport(action_id, dispatch)


def _resolve_target_rows(executor: EndpointExecutor, agent_ids: Iterable[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    agent_list = [str(aid or "").strip() for aid in (agent_ids or []) if str(aid or "").strip()]
    agent_lookup = executor._build_agent_lookup(agent_list)  # noqa: SLF001 - internal lookup optimization
    for raw in agent_list:
        if not raw:
            continue
        try:
            target = executor._resolve_agent_target(raw, agent_lookup=agent_lookup)  # noqa: SLF001 - internal cache-aware resolver
            rows.append(
                {
                    "agent_id": str(target.get("agent_id") or raw),
                    "agent_name": str(target.get("agent_name") or ""),
                    "target_ip": str(target.get("ip") or ""),
                    "platform": str(target.get("platform") or ""),
                }
            )
        except Exception:
            rows.append(
                {
                    "agent_id": raw,
                    "agent_name": "",
                    "target_ip": "",
                    "platform": "",
                }
            )
    return rows


def _as_bulk_result(
    client,
    *,
    channel: str,
    action: str,
    agent_ids: Iterable[str],
    ok: bool,
    stdout: str = "",
    stderr: str = "",
    raw: Any = None,
    status_code: int | None = None,
) -> Dict[str, Any]:
    # Provide a consistent "result" shape regardless of channel so we can
    # persist per-target outcomes and render evidence in the UI.
    executor = EndpointExecutor(client)
    base_rows = _resolve_target_rows(executor, agent_ids)
    code = int(status_code or (200 if ok else 400))
    results = [
        {
            **row,
            "ok": bool(ok),
            "status_code": code,
            "stdout": stdout,
            "stderr": stderr,
        }
        for row in base_rows
    ]
    success = sum(1 for r in results if r.get("ok"))
    failed = len(results) - success
    payload: Dict[str, Any] = {
        "channel": channel,
        "action": action,
        "ok": bool(ok),
        "total": len(results),
        "success": success,
        "failed": failed,
        "results": results,
    }
    if raw is not None:
        payload["raw"] = raw
    return payload


def resolve_agent_ids(client, target: str | None = None, group: str | None = None) -> List[str]:
    def _normalize(ids: Iterable[Any]) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in ids or []:
            value = str(item or "").strip()
            if not value:
                continue
            # Ignore manager pseudo-agent to avoid accidental self-targeting.
            if value in {"000", "0"}:
                continue
            if value in seen:
                continue
            seen.add(value)
            out.append(value)
        return out

    if group:
        ids = _normalize(client.get_agent_ids(group=group))
        if not ids:
            raise HTTPException(status_code=404, detail=f"No agents found in group: {group}")
        return ids

    value = str(target or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="agent_id or group is required")

    if value.lower() in {"all", "*", "fleet", "all-active"}:
        ids = _normalize(client.get_agent_ids())
        if not ids:
            raise HTTPException(status_code=404, detail="No agents found in fleet")
        return ids

    if value.startswith("multi:"):
        raw = value.split(":", 1)[1]
        parts = [p.strip() for p in raw.split(",")]
        ids = _normalize(parts)
        if not ids:
            raise HTTPException(status_code=404, detail="No agents found in multi target")
        return ids

    if "," in value:
        parts = [p.strip() for p in value.split(",")]
        ids = _normalize(parts)
        if not ids:
            raise HTTPException(status_code=404, detail="No agents found in target list")
        return ids

    if value.startswith("group:"):
        group_name = value.split(":", 1)[1]
        ids = _normalize(client.get_agent_ids(group=group_name))
        if not ids:
            raise HTTPException(status_code=404, detail=f"No agents found in group: {group_name}")
        return ids

    return _normalize([value])


def _run_active_response(
    client,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
) -> Dict[str, Any]:
    if not _active_response_enabled():
        raise HTTPException(status_code=400, detail="Active response is disabled")
    attempts = dispatch.get("attempts") or [
        {
            "command": dispatch.get("command"),
            "arguments": dispatch.get("arguments", []),
            "custom": dispatch.get("custom", False),
        }
    ]

    attempted_commands: List[str] = []
    last_error = None
    for attempt in attempts:
        command = str(attempt.get("command") or "").strip()
        if not command:
            continue
        attempted_commands.append(command)
        publish_event(
            execution_id,
            {
                "type": "step_start",
                "step": "active_response",
                "status": "RUNNING",
                "stdout": f"command={command}",
                "stderr": "",
            },
        )
        try:
            result = client.run_active_response(
                command=command,
                agents=list(agent_ids),
                arguments=attempt.get("arguments") or [],
                custom=bool(attempt.get("custom")),
            )
            publish_event(
                execution_id,
                {
                    "type": "step_done",
                    "step": "active_response",
                    "status": "SUCCESS",
                    "stdout": json.dumps(result, default=str),
                    "stderr": "",
                },
            )
            return {
                "channel": "active_response",
                "mode": "active_response",
                "command_used": command,
                "attempts": attempted_commands,
                "result": _as_bulk_result(
                    client,
                    channel="active_response",
                    action=command,
                    agent_ids=agent_ids,
                    ok=True,
                    stdout=f"ACTIVE_RESPONSE_OK command={command}",
                    raw=result,
                ),
            }
        except HTTPException as exc:
            detail = str(exc.detail)
            if is_command_undefined(detail):
                last_error = exc
                continue
            publish_event(
                execution_id,
                {
                    "type": "step_failed",
                    "step": "active_response",
                    "status": "FAILED",
                    "stdout": "",
                    "stderr": detail,
                },
            )
            raise

    if last_error:
        detail = str(last_error.detail)
        raise HTTPException(
            status_code=last_error.status_code,
            detail=f"{detail} | attempts={','.join(attempted_commands)}",
        )
    raise HTTPException(status_code=400, detail="No active response command could be executed")


def _run_endpoint(
    client,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    executor = EndpointExecutor(client)
    agent_list = list(agent_ids)
    requested_action = str(action_id or "").strip()
    resolved_action = str((dispatch or {}).get("action_command") or requested_action).strip()
    if not resolved_action:
        resolved_action = requested_action
    base_context = context if isinstance(context, dict) else {}

    publish_event(
        execution_id,
        {
            "type": "step_start",
            "step": "endpoint",
            "status": "RUNNING",
            "stdout": (
                f"action={requested_action}; resolved_action={resolved_action}; targets={len(agent_list)}"
            ),
            "stderr": "",
        },
    )

    def on_progress(row: Dict[str, Any]) -> None:
        agent = row.get("agent_id") or row.get("agent_name") or "agent"
        status = "SUCCESS" if row.get("ok") else "FAILED"
        publish_event(
            execution_id,
            {
                "type": "target_done",
                "step": f"endpoint:{agent}",
                "status": status,
                "stdout": str(row.get("stdout") or ""),
                "stderr": str(row.get("stderr") or ""),
            },
        )

    def event_sink(message: Dict[str, Any]) -> None:
        publish_event(execution_id, message)

    run_context = {
        **base_context,
        "execution_id": execution_id,
        "action_id": requested_action,
        "resolved_action_id": resolved_action,
        "_event_sink": event_sink,
    }
    result = executor.execute(
        action_id=resolved_action,
        action_args=dispatch.get("arguments") or [],
        agent_ids=agent_list,
        context=run_context,
        on_progress=on_progress,
    )
    overall_status = _result_status(result)
    result["overall_status"] = overall_status
    if overall_status == "FAILED":
        failed = [row for row in (result.get("results") or []) if not row.get("ok")]
        summary = []
        for row in failed[:3]:
            agent = row.get("agent_id") or row.get("agent_name") or "agent"
            err = row.get("stderr") or row.get("stdout") or "execution failed"
            summary.append(f"{agent}: {err}")
        msg = "; ".join(summary) if summary else "endpoint execution failed"
        publish_event(
            execution_id,
            {
                "type": "step_failed",
                "step": "endpoint",
                "status": "FAILED",
                "stdout": json.dumps(result, default=str),
                "stderr": msg,
            },
        )
        raise HTTPException(
            status_code=400,
            detail={"message": f"Endpoint execution failed: {msg}", "result": result},
        )

    publish_event(
        execution_id,
        {
            "type": "step_done",
            "step": "endpoint",
            "status": overall_status,
            "stdout": json.dumps({"success": result.get("success"), "failed": result.get("failed")}, default=str),
            "stderr": "",
        },
    )
    return {
        "channel": "endpoint",
        "mode": "endpoint",
        "command_used": resolved_action,
        "attempts": [resolved_action],
        "result": result,
    }


def _run_endpoint_batched(
    client,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    agent_list = [str(agent_id or "").strip() for agent_id in (agent_ids or []) if str(agent_id or "").strip()]
    if not agent_list:
        raise HTTPException(status_code=400, detail="No agents provided for endpoint execution")

    batch_size = _execution_batch_size()
    if len(agent_list) <= batch_size:
        return _run_endpoint(
            client,
            action_id,
            dispatch,
            agent_list,
            execution_id=execution_id,
            context=context,
        )

    requested_action = str(action_id or "").strip()
    resolved_action = str((dispatch or {}).get("action_command") or requested_action).strip() or requested_action
    progress_callback = None
    if isinstance(context, dict) and callable(context.get("_batch_progress_callback")):
        progress_callback = context.get("_batch_progress_callback")

    batches = [
        agent_list[index : index + batch_size]
        for index in range(0, len(agent_list), batch_size)
    ]
    aggregate_rows: List[Dict[str, Any]] = []

    publish_event(
        execution_id,
        {
            "type": "batch_start",
            "step": "fleet_batching",
            "status": "RUNNING",
            "stdout": json.dumps(
                {
                    "action": requested_action,
                    "resolved_action": resolved_action,
                    "batch_size": batch_size,
                    "batch_count": len(batches),
                    "target_total": len(agent_list),
                },
                default=str,
            ),
            "stderr": "",
        },
    )

    for batch_index, batch_agent_ids in enumerate(batches, start=1):
        batch_result: Dict[str, Any] = {}
        batch_message = ""
        try:
            batch_execution = _run_endpoint(
                client,
                action_id,
                dispatch,
                batch_agent_ids,
                execution_id=execution_id,
                context=context,
            )
            batch_result = batch_execution.get("result") if isinstance(batch_execution.get("result"), dict) else {}
        except HTTPException as exc:
            detail_text = str(exc.detail)
            if isinstance(exc.detail, dict):
                batch_result = exc.detail.get("result") if isinstance(exc.detail.get("result"), dict) else {}
                batch_message = str(exc.detail.get("message") or detail_text)
            else:
                if (
                    "credentials are missing" in detail_text.lower()
                    or "connector is disabled" in detail_text.lower()
                ):
                    raise
                batch_result = _as_bulk_result(
                    client,
                    channel="endpoint",
                    action=resolved_action,
                    agent_ids=batch_agent_ids,
                    ok=False,
                    stderr=detail_text,
                    status_code=400,
                )
                batch_message = detail_text

        rows = [row for row in (batch_result.get("results") or []) if isinstance(row, dict)]
        aggregate_rows.extend(rows)
        progress = _progress_state(
            total=len(agent_list),
            success=sum(1 for row in aggregate_rows if row.get("ok")),
            failed=sum(1 for row in aggregate_rows if not row.get("ok")),
            completed=len(aggregate_rows),
        )
        progress.update(
            {
                "batch_index": batch_index,
                "batch_count": len(batches),
                "batch_size": batch_size,
                "batch_agent_ids": list(batch_agent_ids),
                "rows": rows,
                "message": batch_message,
            }
        )
        if callable(progress_callback):
            try:
                progress_callback(progress)
            except Exception:
                pass
        publish_event(
            execution_id,
            {
                "type": "execution_progress",
                "step": "fleet_progress",
                "status": progress.get("status") or "PARTIAL",
                "stdout": json.dumps(progress, default=str),
                "stderr": batch_message,
            },
        )

    success = sum(1 for row in aggregate_rows if row.get("ok"))
    failed = len(aggregate_rows) - success
    result = {
        "channel": "endpoint",
        "mode": "direct_endpoint",
        "action": resolved_action,
        "total": len(agent_list),
        "success": success,
        "failed": failed,
        "ok": failed == 0 and len(agent_list) > 0,
        "results": aggregate_rows,
        "overall_status": _result_status({"total": len(agent_list), "success": success, "failed": failed}),
        "batch_size": batch_size,
        "batch_count": len(batches),
        "batched": True,
    }
    final_status = str(result.get("overall_status") or "FAILED")
    publish_event(
        execution_id,
        {
            "type": "step_done" if final_status != "FAILED" else "step_failed",
            "step": "fleet_batching",
            "status": final_status,
            "stdout": json.dumps(
                {
                    "success": success,
                    "failed": failed,
                    "total": len(agent_list),
                    "batch_count": len(batches),
                },
                default=str,
            ),
            "stderr": "",
        },
    )
    return {
        "channel": "endpoint",
        "mode": "endpoint_batched",
        "command_used": resolved_action,
        "attempts": [resolved_action],
        "result": result,
    }
    

def _run_manager_api(
    client,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
) -> Dict[str, Any]:
    manager_action = _resolve_manager_api_action(action_id, dispatch)
    agent_list = [str(a).strip() for a in (agent_ids or []) if str(a).strip()]
    if not agent_list:
        raise HTTPException(status_code=400, detail="No agents provided for manager API execution")
    if manager_action == "restart-agent":
        publish_event(
            execution_id,
            {
                "type": "step_start",
                "step": "manager_api",
                "status": "RUNNING",
                "stdout": "command=agents/restart",
                "stderr": "",
            },
        )
        result = client.restart_agents(agent_list)
        publish_event(
            execution_id,
            {
                "type": "step_done",
                "step": "manager_api",
                "status": "SUCCESS",
                "stdout": json.dumps(result, default=str),
                "stderr": "",
            },
        )
        return {
            "channel": "manager_api",
            "mode": "manager_api",
            "command_used": "agents/restart",
            "attempts": ["agents/restart"],
            "result": _as_bulk_result(
                client,
                channel="manager_api",
                action="agents/restart",
                agent_ids=agent_list,
                ok=True,
                stdout="MANAGER_API_OK command=agents/restart",
                raw=result,
            ),
        }
    if manager_action == "agent-query":
        publish_event(
            execution_id,
            {
                "type": "step_start",
                "step": "manager_api",
                "status": "RUNNING",
                "stdout": "command=agents/{id}",
                "stderr": "",
            },
        )
        for aid in agent_list:
            client.get_agent(str(aid))
        publish_event(
            execution_id,
            {
                "type": "step_done",
                "step": "manager_api",
                "status": "SUCCESS",
                "stdout": json.dumps({"ok": True, "checked": len(agent_list)}, default=str),
                "stderr": "",
            },
        )
        return {
            "channel": "manager_api",
            "mode": "manager_api",
            "command_used": "agents/{id}",
            "attempts": ["agents/{id}"],
            "result": _as_bulk_result(
                client,
                channel="manager_api",
                action="agents/{id}",
                agent_ids=agent_list,
                ok=True,
                stdout="MANAGER_API_OK command=agents/{id}",
                raw={"ok": True, "checked": len(agent_list)},
            ),
        }
    raise HTTPException(status_code=400, detail=f"Unsupported manager API action: {action_id}")


def _supports_adaptive_windowing(action_id: str) -> bool:
    lowered = str(action_id or "").strip().lower()
    return lowered in {"sca", "sca-rescan", "sca_rescan"}


def _deferred_target_rows(client, *, agent_ids: Iterable[str], deferred_states: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = _resolve_target_rows(EndpointExecutor(client), agent_ids)
    for row in rows:
        agent_id = str(row.get("agent_id") or "").strip()
        state = deferred_states.get(agent_id) or {}
        reasons = ",".join(state.get("reasons") or []) or "resource_pressure"
        row.update(
            {
                "ok": False,
                "status_code": 425,
                "stdout": "",
                "stderr": f"Deferred by adaptive windowing: {reasons}",
                "deferred": True,
                "resource_state": state,
            }
        )
    return rows


def _merge_deferred_results(payload: Dict[str, Any], deferred_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not deferred_rows:
        return payload
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    existing_rows = [row for row in (result.get("results") or []) if isinstance(row, dict)]
    merged_rows = existing_rows + deferred_rows
    success = sum(1 for row in merged_rows if row.get("ok"))
    hard_failed = sum(1 for row in merged_rows if not row.get("ok") and not row.get("deferred"))
    deferred_count = sum(1 for row in merged_rows if row.get("deferred"))
    status = "PARTIAL" if success > 0 or deferred_count > 0 else "FAILED"
    result.update(
        {
            "results": merged_rows,
            "total": len(merged_rows),
            "success": success,
            "failed": hard_failed,
            "deferred_count": deferred_count,
            "overall_status": status,
            "adaptive_windowing": deferred_count > 0,
        }
    )
    payload["result"] = result
    payload["adaptive_windowing"] = {
        "deferred": deferred_count,
        "ready": max(0, len(merged_rows) - deferred_count),
    }
    return payload


def execute_action(
    client,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
    context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    context_data = context if isinstance(context, dict) else {}
    agent_list = [str(a).strip() for a in (agent_ids or []) if str(a).strip()]
    if action_requires_approval_handshake(
        action_id,
        target_count=len(agent_list),
        context=context_data,
    ):
        raise HTTPException(
            status_code=409,
            detail="Approval handshake required before executing this action",
        )

    requested_mode = orchestration_mode()
    mode = requested_mode
    if _requires_endpoint_transport(action_id, dispatch):
        mode = "endpoint"
    endpoint_error = None
    manager_error = None
    ar_fallback_enabled = _active_response_endpoint_fallback_enabled()
    manager_api_action = _resolve_manager_api_action(action_id, dispatch)
    deferred_rows: List[Dict[str, Any]] = []
    effective_agent_ids = list(agent_list)

    if _supports_adaptive_windowing(action_id) and len(agent_list) >= _execution_batch_threshold():
        adaptive_plan = partition_adaptive_window_targets(
            agent_list,
            tenant_id=context_data.get("tenant_id"),
        )
        ready_agent_ids = [str(a).strip() for a in (adaptive_plan.get("ready") or []) if str(a).strip()]
        deferred_state_map = {
            str(item.get("agent_id") or "").strip(): item
            for item in (adaptive_plan.get("states") or [])
            if str(item.get("agent_id") or "").strip()
        }
        deferred_ids = [str(a).strip() for a in (adaptive_plan.get("deferred") or []) if str(a).strip()]
        deferred_rows = _deferred_target_rows(
            client,
            agent_ids=deferred_ids,
            deferred_states=deferred_state_map,
        )
        if ready_agent_ids:
            effective_agent_ids = ready_agent_ids
        elif deferred_rows:
            return _merge_deferred_results(
                {
                    "channel": "adaptive_windowing",
                    "mode": "adaptive_windowing",
                    "command_used": str(action_id or "").strip(),
                    "attempts": [str(action_id or "").strip()],
                    "result": {
                        "ok": False,
                        "total": 0,
                        "success": 0,
                        "failed": 0,
                        "results": [],
                    },
                },
                deferred_rows,
            )

    if manager_api_action:
        try:
            payload = _run_manager_api(client, action_id, dispatch, effective_agent_ids, execution_id=execution_id)
            payload["requested_mode"] = mode
            payload = _merge_deferred_results(payload, deferred_rows)
            return payload
        except HTTPException as exc:
            manager_error = str(exc.detail)
            # Manager API is the fastest path, but endpoint/active-response
            # channels should still be attempted when available.

    if mode in {"endpoint", "hybrid"}:
        try:
            if _should_batch_endpoint_execution(
                action_id=action_id,
                dispatch=dispatch,
                agent_ids=agent_ids,
                mode=mode,
                manager_api_action=manager_api_action,
            ):
                payload = _run_endpoint_batched(
                    client,
                    action_id,
                    dispatch,
                    effective_agent_ids,
                    execution_id=execution_id,
                    context=context,
                )
            else:
                payload = _run_endpoint(
                    client,
                    action_id,
                    dispatch,
                    effective_agent_ids,
                    execution_id=execution_id,
                    context=context,
                )
            payload["mode"] = mode
            if mode != requested_mode:
                payload["requested_mode"] = requested_mode
            if manager_error:
                payload["manager_api_error"] = manager_error
            payload = _merge_deferred_results(payload, deferred_rows)
            return payload
        except HTTPException as exc:
            if mode == "endpoint":
                detail_text = str(exc.detail)
                if (
                    ar_fallback_enabled
                    and (
                        "credentials are missing" in detail_text.lower()
                        or "connector is disabled" in detail_text.lower()
                    )
                ):
                    try:
                        payload = _run_active_response(client, dispatch, effective_agent_ids, execution_id=execution_id)
                        payload["mode"] = "endpoint_with_active_response_fallback"
                        if requested_mode != "endpoint":
                            payload["requested_mode"] = requested_mode
                        payload["endpoint_error"] = detail_text
                        if manager_error:
                            payload["manager_api_error"] = manager_error
                        payload = _merge_deferred_results(payload, deferred_rows)
                        return payload
                    except HTTPException as ar_exc:
                        raise HTTPException(
                            status_code=ar_exc.status_code,
                            detail=f"{ar_exc.detail} | endpoint_error={detail_text}",
                        ) from ar_exc
                if manager_error:
                    raise HTTPException(
                        status_code=exc.status_code,
                        detail=f"{exc.detail} | manager_api_error={manager_error}",
                    ) from exc
                raise
            endpoint_error = str(exc.detail)

    if mode in {"active_response", "hybrid"}:
        try:
            payload = _run_active_response(client, dispatch, effective_agent_ids, execution_id=execution_id)
            payload["mode"] = mode
            if mode != requested_mode:
                payload["requested_mode"] = requested_mode
            if endpoint_error:
                payload["endpoint_error"] = endpoint_error
            if manager_error:
                payload["manager_api_error"] = manager_error
            payload = _merge_deferred_results(payload, deferred_rows)
            return payload
        except HTTPException as exc:
            if (
                mode == "active_response"
                and ar_fallback_enabled
                and is_command_undefined(str(exc.detail))
            ):
                try:
                    endpoint_payload = _run_endpoint(
                        client,
                        action_id,
                        dispatch,
                        effective_agent_ids,
                        execution_id=execution_id,
                        context=context,
                    )
                    endpoint_payload["mode"] = "active_response_with_endpoint_fallback"
                    if requested_mode != "active_response":
                        endpoint_payload["requested_mode"] = requested_mode
                    endpoint_payload["active_response_error"] = str(exc.detail)
                    if manager_error:
                        endpoint_payload["manager_api_error"] = manager_error
                    endpoint_payload = _merge_deferred_results(endpoint_payload, deferred_rows)
                    return endpoint_payload
                except HTTPException as endpoint_exc:
                    raise HTTPException(
                        status_code=endpoint_exc.status_code,
                        detail=f"{endpoint_exc.detail} | active_response_error={exc.detail}",
                    ) from endpoint_exc
            if manager_error:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=f"{exc.detail} | manager_api_error={manager_error}",
                ) from exc
            if endpoint_error:
                raise HTTPException(
                    status_code=exc.status_code,
                    detail=f"{exc.detail} | endpoint_error={endpoint_error}",
                ) from exc
            raise

    raise HTTPException(status_code=500, detail=f"Unsupported orchestration mode: {json.dumps(mode)}")
