import json
import os
from typing import Any, Dict, Iterable, List

from fastapi import HTTPException

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
    return aliases.get(mode, "endpoint")


def _active_response_endpoint_fallback_enabled() -> bool:
    if not isinstance(SETTINGS, dict):
        return True
    cfg = SETTINGS.get("orchestration", {}) or {}
    value = cfg.get("active_response_fallback_to_endpoint", True)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


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
) -> Dict[str, Any]:
    executor = EndpointExecutor(client)
    agent_list = list(agent_ids)
    requested_action = str(action_id or "").strip()
    resolved_action = str((dispatch or {}).get("action_command") or requested_action).strip()
    if not resolved_action:
        resolved_action = requested_action

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

    result = executor.execute(
        action_id=resolved_action,
        action_args=dispatch.get("arguments") or [],
        agent_ids=agent_list,
        context={
            "execution_id": execution_id,
            "action_id": requested_action,
            "resolved_action_id": resolved_action,
            "_event_sink": event_sink,
        },
        on_progress=on_progress,
    )
    if not result.get("ok"):
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
            "status": "SUCCESS",
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


def execute_action(
    client,
    action_id: str,
    dispatch: Dict[str, Any],
    agent_ids: Iterable[str],
    execution_id: int | None = None,
) -> Dict[str, Any]:
    mode = orchestration_mode()
    endpoint_error = None
    manager_error = None
    ar_fallback_enabled = _active_response_endpoint_fallback_enabled()
    manager_api_action = _resolve_manager_api_action(action_id, dispatch)

    if manager_api_action:
        try:
            payload = _run_manager_api(client, action_id, dispatch, agent_ids, execution_id=execution_id)
            payload["requested_mode"] = mode
            return payload
        except HTTPException as exc:
            manager_error = str(exc.detail)
            # Manager API is the fastest path, but endpoint/active-response
            # channels should still be attempted when available.

    if mode in {"endpoint", "hybrid"}:
        try:
            payload = _run_endpoint(client, action_id, dispatch, agent_ids, execution_id=execution_id)
            payload["mode"] = mode
            if manager_error:
                payload["manager_api_error"] = manager_error
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
                        payload = _run_active_response(client, dispatch, agent_ids, execution_id=execution_id)
                        payload["mode"] = "endpoint_with_active_response_fallback"
                        payload["endpoint_error"] = detail_text
                        if manager_error:
                            payload["manager_api_error"] = manager_error
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
            payload = _run_active_response(client, dispatch, agent_ids, execution_id=execution_id)
            payload["mode"] = mode
            if endpoint_error:
                payload["endpoint_error"] = endpoint_error
            if manager_error:
                payload["manager_api_error"] = manager_error
            return payload
        except HTTPException as exc:
            if (
                mode == "active_response"
                and ar_fallback_enabled
                and is_command_undefined(str(exc.detail))
            ):
                try:
                    endpoint_payload = _run_endpoint(client, action_id, dispatch, agent_ids, execution_id=execution_id)
                    endpoint_payload["mode"] = "active_response_with_endpoint_fallback"
                    endpoint_payload["active_response_error"] = str(exc.detail)
                    if manager_error:
                        endpoint_payload["manager_api_error"] = manager_error
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
