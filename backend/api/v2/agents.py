from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from core.active_defense import action_requires_approval_handshake, normalize_network_path_state
from core.action_execution import execute_action
from core.agent_runtime_state import (
    STATE_ENROLLMENT,
    STATE_HEALTH,
    STATE_ISOLATION,
    STATE_NETWORK_PATH,
    STATE_POLICY,
    clear_agent_runtime_state,
    find_any_agent_state,
    get_agent_state,
    upsert_agent_state,
)
from core.actions import get_action, list_actions, normalize_args, resolve_action_dispatch
from core.agent_manager_client import AgentManagerClient
from core.secrets import resolve_secret_env
from core.security import current_user, require_role
from core.time_utils import utc_iso_now, utc_now_naive
from core.wazuh_client import WazuhClient
from db.database import connect
from .audit import log_v2_write_audit
from .common import ok
from .policy import enforce_abac
from .tenant_contract import normalize_contract_response, org_id_to_tenant_id, resolve_tenant_scope


router = APIRouter(prefix="/agents")
client = WazuhClient()
manager_client = AgentManagerClient()


class _StateHandle(str):
    def clear(self) -> None:
        clear_agent_runtime_state(state_kind=str(self))


_ENROLLMENT_STATE = _StateHandle(STATE_ENROLLMENT)
_POLICY_STATE = _StateHandle(STATE_POLICY)
_HEALTH_STATE = _StateHandle(STATE_HEALTH)
_ISOLATION_STATE = _StateHandle(STATE_ISOLATION)

_ISOLATION_GROUP = str(os.getenv("C2F_AGENT_ISOLATION_GROUP", "isolated")).strip() or "isolated"
_DEFAULT_MANAGER_BOOTSTRAP_TOKEN = (
    resolve_secret_env("C2F_AGENT_MANAGER_BOOTSTRAP_TOKEN")
    or resolve_secret_env("C2F_ENROLLMENT_BOOTSTRAP_TOKEN")
    or ""
)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


_AUTO_CREATE_ISOLATION_GROUP = _env_bool("C2F_AGENT_ISOLATION_AUTO_CREATE_GROUP", True)


def _normalize_agent_id(agent_id: Any) -> str:
    raw = str(agent_id or "").strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_provider(value: Any, *, default: str = "wazuh") -> str:
    token = str(value or "").strip().lower()
    if not token:
        return str(default or "").strip().lower()
    if token in {"native", "c2f", "agent-manager"}:
        return "native"
    if token in {"wazuh", "ossec"}:
        return "wazuh"
    if default:
        return str(default).strip().lower()
    return "wazuh"


def _is_native_agent_id(agent_id: str) -> bool:
    return str(agent_id or "").strip().lower().startswith("agt_")


def _normalize_tokens(value: Any) -> list[str]:
    source: list[Any]
    if value is None:
        source = []
    elif isinstance(value, list):
        source = value
    elif isinstance(value, str):
        source = [part for part in value.split(",")]
    else:
        source = [value]

    out: list[str] = []
    seen = set()
    for item in source:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _normalize_command_args(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    if isinstance(value, dict):
        out: list[str] = []
        for key, item in value.items():
            token = str(key or "").strip()
            if not token:
                continue
            if isinstance(item, bool):
                out.append(f"--{token}={'true' if item else 'false'}")
            elif item is None:
                out.append(f"--{token}")
            else:
                out.append(f"--{token}={item}")
        return out
    return [str(value)]


def _extract_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        rows = (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
    elif isinstance(data, list):
        rows = data
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def _extract_agent(data: Any) -> dict[str, Any]:
    items = _extract_items(data)
    if items:
        return dict(items[0])
    if isinstance(data, dict):
        return dict(data)
    return {}


def _agent_groups(agent: Mapping[str, Any] | None) -> list[str]:
    out: list[str] = []
    seen = set()
    node = dict(agent or {})
    for key in ("groups", "group", "group_name", "group_id"):
        raw = node.get(key)
        values: list[str]
        if isinstance(raw, list):
            values = [str(v or "").strip() for v in raw]
        elif isinstance(raw, str):
            values = [raw.strip()]
        else:
            values = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
    return out


def _agent_status(agent: Mapping[str, Any] | None) -> str:
    status = str((agent or {}).get("status") or "").strip().lower()
    if status:
        return status
    nested = (agent or {}).get("agent")
    if isinstance(nested, dict):
        return str(nested.get("status") or "").strip().lower()
    return ""


def _agent_keepalive(agent: Mapping[str, Any] | None) -> str:
    node = dict(agent or {})
    return str(
        node.get("last_keepalive")
        or node.get("lastKeepAlive")
        or node.get("last_keep_alive")
        or node.get("last_seen")
        or node.get("status_time")
        or ""
    ).strip()


def _state_get(store: str, *, agent_id: str, tenant_id: int | None) -> dict[str, Any] | None:
    return get_agent_state(
        state_kind=str(store),
        agent_id=_normalize_agent_id(agent_id),
        tenant_id=org_id_to_tenant_id(tenant_id),
    )


def _state_find_any(store: str, *, agent_id: str) -> dict[str, Any] | None:
    return find_any_agent_state(
        state_kind=str(store),
        agent_id=_normalize_agent_id(agent_id),
    )


def _state_set(
    store: str,
    *,
    agent_id: str,
    tenant_id: int | None,
    value: Mapping[str, Any],
) -> None:
    upsert_agent_state(
        state_kind=str(store),
        agent_id=_normalize_agent_id(agent_id),
        tenant_id=org_id_to_tenant_id(tenant_id),
        value=dict(value),
        updated_by=str(dict(value).get("updated_by") or dict(value).get("enrolled_by") or dict(value).get("reported_by") or "").strip() or None,
    )


def _native_agent_for_tenant(*, agent_id: str, tenant_id: int | None) -> dict[str, Any] | None:
    scoped_tenant = org_id_to_tenant_id(tenant_id)
    if scoped_tenant is None:
        return None
    try:
        response = manager_client.get_agent(tenant_id=scoped_tenant, agent_id=agent_id)
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise
    if not isinstance(response, dict):
        return None
    payload = response.get("data")
    if not isinstance(payload, dict):
        return None
    agent = payload.get("agent")
    if isinstance(agent, Mapping):
        return dict(agent)
    return None


def _resolve_agent_scope(
    *,
    agent_id: str,
    user: Mapping[str, Any] | None,
    tenant_id: int | None = None,
) -> tuple[str, int | None]:
    normalized_agent = _normalize_agent_id(agent_id)
    if not normalized_agent:
        raise HTTPException(status_code=400, detail="agent_id is required")

    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=tenant_id,
        allow_superadmin_override=True,
    )
    enrollment = _state_get(_ENROLLMENT_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant)
    if enrollment is None:
        enrollment = _state_find_any(_ENROLLMENT_STATE, agent_id=normalized_agent)
    if enrollment is not None:
        enrolled_tenant = org_id_to_tenant_id(enrollment.get("tenant_id"))
        if enrolled_tenant is not None:
            if scoped_tenant is None:
                scoped_tenant = enrolled_tenant
            elif scoped_tenant != enrolled_tenant:
                raise HTTPException(status_code=404, detail="Agent not found")
    if enrollment is None and _is_native_agent_id(normalized_agent):
        if scoped_tenant is None:
            raise HTTPException(status_code=400, detail="tenant_id is required for native agent operations")
        manager_agent = _native_agent_for_tenant(agent_id=normalized_agent, tenant_id=scoped_tenant)
        if manager_agent is None:
            raise HTTPException(status_code=404, detail="Agent not found")
    return normalized_agent, scoped_tenant


def _require_scoped_tenant(value: int | None) -> int:
    scoped = org_id_to_tenant_id(value)
    if scoped is None:
        raise HTTPException(status_code=400, detail="tenant_id is required for this operation")
    return scoped


def _enrolled_provider(*, agent_id: str, tenant_id: int | None) -> str:
    record = _state_get(_ENROLLMENT_STATE, agent_id=agent_id, tenant_id=tenant_id) or {}
    provider = _normalize_provider(record.get("provider"), default="")
    if provider:
        return provider
    if _is_native_agent_id(agent_id):
        return "native"
    return "wazuh"


def _native_policy_merge(*, current: Mapping[str, Any], request_payload: "AgentPolicyApplyRequest") -> dict[str, Any]:
    base = dict(current or {})
    command_policy = _normalize_command_policy(request_payload.command_policy)
    if command_policy.get("allow_list") is not None:
        base["command_allow_list"] = [str(item).strip().lower() for item in command_policy.get("allow_list") or [] if str(item).strip()]
    if command_policy.get("block_list") is not None:
        base["command_block_list"] = [str(item).strip().lower() for item in command_policy.get("block_list") or [] if str(item).strip()]
    if isinstance(request_payload.metadata, dict):
        manager_policy = request_payload.metadata.get("manager_policy")
        if isinstance(manager_policy, dict):
            for key, value in manager_policy.items():
                base[key] = value
        base["metadata"] = dict(request_payload.metadata)
    return base


def _manager_agent(agent_id: str) -> dict[str, Any]:
    try:
        return _extract_agent(client.get_agent(agent_id))
    except HTTPException:
        return {}


def _default_command_policy() -> dict[str, Any]:
    allow_list = sorted(
        {
            str(action.get("id") or "").strip().lower()
            for action in list_actions()
            if str(action.get("id") or "").strip()
        }
    )
    return {
        "enforce_allow_list": True,
        "allow_list": allow_list,
        "block_list": [],
    }


def _normalize_command_policy(raw: Any) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="command_policy must be an object")
    out = dict(raw)
    if "allow_list" in out:
        out["allow_list"] = [token.lower() for token in _normalize_tokens(out.get("allow_list"))]
    if "block_list" in out:
        out["block_list"] = [token.lower() for token in _normalize_tokens(out.get("block_list"))]
    if "enforce_allow_list" in out:
        out["enforce_allow_list"] = bool(out.get("enforce_allow_list"))
    return out


def _effective_command_policy(*, agent_id: str, tenant_id: int | None) -> dict[str, Any]:
    effective = _default_command_policy()
    override = _state_get(_POLICY_STATE, agent_id=agent_id, tenant_id=tenant_id) or {}
    command_policy = _normalize_command_policy(override.get("command_policy") if isinstance(override, dict) else None)
    if "allow_list" in command_policy:
        effective["allow_list"] = command_policy.get("allow_list") or []
    if "block_list" in command_policy:
        effective["block_list"] = command_policy.get("block_list") or []
    if "enforce_allow_list" in command_policy:
        effective["enforce_allow_list"] = bool(command_policy.get("enforce_allow_list"))
    for key, value in command_policy.items():
        if key in {"allow_list", "block_list", "enforce_allow_list"}:
            continue
        effective[key] = value
    return effective


def _resolve_isolation_payload(payload: Mapping[str, Any]) -> bool:
    if payload.get("isolate") is not None:
        return bool(payload.get("isolate"))
    state = str(payload.get("state") or "").strip().lower()
    if state in {"isolated", "isolate", "enable", "enabled", "on", "true"}:
        return True
    if state in {"released", "release", "disable", "disabled", "off", "false"}:
        return False
    return True


def _current_isolation_state(*, agent_id: str, tenant_id: int | None, manager_agent: Mapping[str, Any] | None) -> dict[str, Any]:
    local_state = _state_get(_ISOLATION_STATE, agent_id=agent_id, tenant_id=tenant_id) or {}
    groups = [g.lower() for g in _agent_groups(manager_agent)]
    manager_isolated = _ISOLATION_GROUP.lower() in groups
    local_isolated = bool(local_state.get("isolated"))
    isolated = manager_isolated or local_isolated
    source = "manager" if manager_isolated else ("local" if local_state else "inferred")
    return {
        "isolated": isolated,
        "source": source,
        "group": _ISOLATION_GROUP,
        "updated_at_utc": local_state.get("updated_at_utc"),
        "updated_by": local_state.get("updated_by"),
        "reason": local_state.get("reason"),
    }


class AgentEnrollmentRequest(BaseModel):
    provider: str = Field(default="wazuh", max_length=32)
    name: str = Field(min_length=1, max_length=255)
    ip: str = Field(default="any", max_length=64)
    force: int = Field(default=-1, ge=-1, le=1)
    groups: list[str] = Field(default_factory=list)
    os: str | None = Field(default=None, max_length=64)
    fingerprint: str | None = Field(default=None, max_length=512)
    bootstrap_token: str | None = Field(default=None, max_length=512)
    tenant_id: int | None = Field(default=None, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str):
        token = _normalize_provider(value)
        if token not in {"wazuh", "native"}:
            raise ValueError("provider must be one of: wazuh, native")
        return token

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str):
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("name is required")
        return cleaned

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str):
        cleaned = str(value or "").strip()
        return cleaned or "any"

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, value: list[str]):
        return _normalize_tokens(value)


class AgentPolicyApplyRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    assign_groups: list[str] = Field(default_factory=list)
    remove_groups: list[str] = Field(default_factory=list)
    replace_groups: bool = False
    command_policy: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("assign_groups", "remove_groups")
    @classmethod
    def validate_group_lists(cls, value: list[str]):
        return _normalize_tokens(value)


class AgentCommandDispatchRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    action_id: str = Field(min_length=1, max_length=128)
    args: Any = None
    dry_run: bool = False
    reason: str | None = Field(default=None, max_length=1000)

    @field_validator("action_id")
    @classmethod
    def validate_action_id(cls, value: str):
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("action_id is required")
        return cleaned


class AgentHealthReportRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    status: str = Field(default="ok", max_length=32)
    version: str | None = Field(default=None, max_length=128)
    message: str | None = Field(default=None, max_length=1000)
    tamper_alert: bool = False
    metrics: dict[str, Any] = Field(default_factory=dict)
    checks: list[dict[str, Any]] = Field(default_factory=list)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str):
        normalized = str(value or "").strip().lower() or "ok"
        allowed = {"ok", "healthy", "degraded", "warning", "error", "offline", "unknown"}
        if normalized not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return normalized


class AgentIsolationRequest(BaseModel):
    tenant_id: int | None = Field(default=None, ge=1)
    isolate: bool | None = None
    state: str | None = Field(default=None, max_length=32)
    group: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=1000)

    @field_validator("group")
    @classmethod
    def validate_group(cls, value: str | None):
        if value is None:
            return None
        cleaned = str(value or "").strip()
        return cleaned or None


@router.post("/enroll")
def enroll_agent(
    payload: AgentEnrollmentRequest,
    request: Request,
    user=Depends(require_role("admin")),
):
    scoped_tenant = resolve_tenant_scope(
        user=user,
        tenant_id=payload.tenant_id,
        allow_superadmin_override=True,
    )
    decision = enforce_abac(
        action="v2.agents.enroll",
        user=user,
        request=request,
        resource={
            "type": "agent_enrollment",
            "tenant_id": scoped_tenant,
            "agent_name": payload.name,
        },
    )
    provider = _normalize_provider(payload.provider)
    groups_assigned: list[str] = []
    enrollment_key = ""
    agent_token = ""
    agent_id = ""

    if provider == "native":
        tenant_for_native = _require_scoped_tenant(scoped_tenant)
        bootstrap_token = str(payload.bootstrap_token or _DEFAULT_MANAGER_BOOTSTRAP_TOKEN).strip()
        if not bootstrap_token:
            raise HTTPException(status_code=400, detail="bootstrap_token is required for native agent enrollment")
        os_name = str(payload.os or payload.metadata.get("os") or "unknown").strip() or "unknown"
        fingerprint = str(payload.fingerprint or payload.metadata.get("fingerprint") or payload.name).strip()
        if len(fingerprint) < 8:
            raise HTTPException(status_code=400, detail="fingerprint must be at least 8 characters")
        manager_response = manager_client.enroll(
            payload={
                "tenant_id": tenant_for_native,
                "hostname": payload.name,
                "os": os_name,
                "fingerprint": fingerprint,
                "bootstrap_token": bootstrap_token,
                "metadata": dict(payload.metadata or {}),
            }
        )
        agent_id = _normalize_agent_id(manager_response.get("agent_id"))
        agent_token = str(manager_response.get("agent_token") or "").strip()
        if not agent_id:
            raise HTTPException(status_code=502, detail="Native enrollment did not return agent_id")
        scoped_tenant = tenant_for_native
    else:
        manager_response = client.enroll_agent(
            name=payload.name,
            ip=payload.ip,
            force=payload.force,
        )
        enrolled_row = _extract_agent(manager_response)
        agent_id = _normalize_agent_id(
            enrolled_row.get("id")
            or enrolled_row.get("agent_id")
            or enrolled_row.get("agent")
        )
        enrollment_key = str(enrolled_row.get("key") or "").strip()
        if not agent_id:
            raise HTTPException(status_code=502, detail="Wazuh enrollment did not return agent_id")
        for group in payload.groups:
            client.assign_agent_group(agent_id, group)
            groups_assigned.append(group)

    enrollment_state = {
        "tenant_id": scoped_tenant,
        "agent_id": agent_id,
        "provider": provider,
        "name": payload.name,
        "groups": groups_assigned,
        "metadata": dict(payload.metadata or {}),
        "enrolled_at_utc": utc_iso_now(),
        "enrolled_by": (user or {}).get("sub"),
    }
    _state_set(_ENROLLMENT_STATE, agent_id=agent_id, tenant_id=scoped_tenant, value=enrollment_state)
    response_payload = {
        "tenant_id": scoped_tenant,
        "agent_id": agent_id,
        "provider": provider,
        "name": payload.name,
        "groups_assigned": groups_assigned,
        "enrolled_at_utc": enrollment_state["enrolled_at_utc"],
        "metadata": payload.metadata,
    }
    if enrollment_key:
        response_payload["enrollment_key"] = enrollment_key
    if agent_token:
        response_payload["agent_token"] = agent_token
    response = normalize_contract_response(response_payload)
    log_v2_write_audit(
        action="v2.agents.enroll",
        entity_type="agent",
        entity_id=agent_id,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "name": payload.name,
            "groups": groups_assigned,
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        response,
        message="Agent enrolled",
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.get("/{agent_id}/policy")
def get_agent_policy(
    agent_id: str,
    include_group_configuration: bool = Query(default=False),
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        manager_policy = manager_client.get_policy(tenant_id=native_tenant, agent_id=normalized_agent)
        payload = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "policy": manager_policy.get("data", {}).get("policy", {}),
                "command_policy": {
                    "enforce_allow_list": True,
                    "allow_list": manager_policy.get("data", {}).get("policy", {}).get("command_allow_list") or [],
                    "block_list": manager_policy.get("data", {}).get("policy", {}).get("command_block_list") or [],
                },
                "source": "agent-manager",
            }
        )
        return ok(payload, tenant_id=native_tenant, contract="tenant_id_primary")

    manager_agent = _manager_agent(normalized_agent)
    groups = _agent_groups(manager_agent)
    group_configurations: dict[str, Any] = {}
    if include_group_configuration:
        for group in groups:
            try:
                group_configurations[group] = client.get_group_configuration(group)
            except HTTPException as exc:
                group_configurations[group] = {"error": str(exc.detail)}

    policy_state = _state_get(_POLICY_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant) or {}
    command_policy = _effective_command_policy(agent_id=normalized_agent, tenant_id=scoped_tenant)
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "wazuh",
            "manager_groups": groups,
            "group_count": len(groups),
            "command_policy": command_policy,
            "policy_version": int(policy_state.get("version") or 0),
            "updated_at_utc": policy_state.get("updated_at_utc"),
            "updated_by": policy_state.get("updated_by"),
            "metadata": policy_state.get("metadata") if isinstance(policy_state.get("metadata"), dict) else {},
        }
    )
    if include_group_configuration:
        payload["group_configurations"] = group_configurations
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.put("/{agent_id}/policy")
def apply_agent_policy(
    agent_id: str,
    request: Request,
    payload: AgentPolicyApplyRequest = Body(default=AgentPolicyApplyRequest()),
    user=Depends(require_role("admin")),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=payload.tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    if (
        not payload.assign_groups
        and not payload.remove_groups
        and not payload.replace_groups
        and payload.command_policy is None
        and payload.metadata is None
    ):
        raise HTTPException(status_code=400, detail="No policy changes requested")

    decision = enforce_abac(
        action="v2.agents.policy.apply",
        user=user,
        request=request,
        resource={
            "type": "agent_policy",
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
        },
    )

    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        current_policy = manager_client.get_policy(tenant_id=native_tenant, agent_id=normalized_agent).get("data", {}).get("policy") or {}
        merged_policy = _native_policy_merge(current=current_policy, request_payload=payload)
        applied = manager_client.apply_policy(
            tenant_id=native_tenant,
            agent_id=normalized_agent,
            payload=merged_policy,
        )
        response = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "operations": ["policy_updated:manager"],
                "policy": applied.get("data", {}).get("policy", {}),
                "command_policy": {
                    "enforce_allow_list": True,
                    "allow_list": applied.get("data", {}).get("policy", {}).get("command_allow_list") or [],
                    "block_list": applied.get("data", {}).get("policy", {}).get("command_block_list") or [],
                },
                "updated_at_utc": utc_iso_now(),
                "updated_by": (user or {}).get("sub"),
                "metadata": payload.metadata if isinstance(payload.metadata, dict) else {},
            }
        )
        log_v2_write_audit(
            action="v2.agents.policy.apply",
            entity_type="agent_policy",
            entity_id=normalized_agent,
            user=user,
            request=request,
            tenant_id=native_tenant,
            changes={
                "provider": "native",
                "policy_keys": sorted(list((applied.get("data", {}).get("policy") or {}).keys())),
            },
            metadata={
                "abac_policy_source": decision.policy_source,
                "abac_reason": decision.reason,
            },
        )
        return ok(
            response,
            message="Policy applied",
            tenant_id=native_tenant,
            contract="tenant_id_primary",
        )

    operations: list[str] = []
    if payload.replace_groups:
        client.clear_agent_groups(normalized_agent)
        operations.append("groups_cleared")

    for group in payload.remove_groups:
        client.remove_agent_group(normalized_agent, group)
        operations.append(f"group_removed:{group}")

    for group in payload.assign_groups:
        client.assign_agent_group(normalized_agent, group)
        operations.append(f"group_assigned:{group}")

    existing = _state_get(_POLICY_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant) or {}
    updated_state = dict(existing)
    if payload.command_policy is not None:
        updated_state["command_policy"] = _normalize_command_policy(payload.command_policy)
    if payload.metadata is not None:
        updated_state["metadata"] = dict(payload.metadata)
    updated_state["updated_at_utc"] = utc_iso_now()
    updated_state["updated_by"] = (user or {}).get("sub")
    updated_state["version"] = int(existing.get("version") or 0) + 1
    _state_set(_POLICY_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant, value=updated_state)

    manager_groups = _agent_groups(_manager_agent(normalized_agent))
    response = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "wazuh",
            "manager_groups": manager_groups,
            "group_count": len(manager_groups),
            "operations": operations,
            "command_policy": _effective_command_policy(agent_id=normalized_agent, tenant_id=scoped_tenant),
            "policy_version": updated_state["version"],
            "updated_at_utc": updated_state["updated_at_utc"],
            "updated_by": updated_state["updated_by"],
            "metadata": updated_state.get("metadata") if isinstance(updated_state.get("metadata"), dict) else {},
        }
    )
    log_v2_write_audit(
        action="v2.agents.policy.apply",
        entity_type="agent_policy",
        entity_id=normalized_agent,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "assign_groups": payload.assign_groups,
            "remove_groups": payload.remove_groups,
            "replace_groups": payload.replace_groups,
            "policy_version": updated_state["version"],
        },
        metadata={
            "operations": operations,
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        response,
        message="Policy applied",
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.post("/{agent_id}/commands")
def dispatch_agent_command(
    agent_id: str,
    request: Request,
    payload: AgentCommandDispatchRequest,
    user=Depends(require_role("admin")),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=payload.tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    decision = enforce_abac(
        action="v2.agents.command.dispatch",
        user=user,
        request=request,
        resource={
            "type": "agent_command",
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
        },
    )

    action_id = str(payload.action_id or "").strip()
    normalized_args = _normalize_command_args(payload.args)
    dispatch = {"command": action_id, "arguments": list(normalized_args), "custom": True, "attempts": []}
    try:
        action = get_action(payload.action_id)
        action_id = str(action.get("id") or payload.action_id).strip()
        normalized_args = normalize_args(action, payload.args)
        dispatch = resolve_action_dispatch(action, normalized_args)
    except HTTPException as exc:
        if provider != "native" or exc.status_code != 404:
            raise

    def _pending_approval_response():
        from api.approvals import create_approval_request_record

        approval = create_approval_request_record(
            request=request,
            user=user,
            agent_id=normalized_agent,
            action_id=action_id,
            args=payload.args,
            justification=payload.reason,
            resolved_target_ids=[normalized_agent],
        )
        response = normalize_contract_response(
            {
                "tenant_id": scoped_tenant,
                "agent_id": normalized_agent,
                "provider": provider,
                "action_id": action_id,
                "dry_run": False,
                "dispatch": dispatch,
                "channel": None,
                "mode": "approval_required",
                "attempts": dispatch.get("attempts"),
                "result": None,
                "approval_id": approval.get("approval_id") or approval.get("id"),
                "approval": approval,
            }
        )
        log_v2_write_audit(
            action="v2.agents.command.dispatch",
            entity_type="agent_command",
            entity_id=normalized_agent,
            user=user,
            request=request,
            tenant_id=scoped_tenant,
            changes={
                "action_id": action_id,
                "dry_run": False,
                "reason": payload.reason,
                "approval_required": True,
            },
            metadata={
                "abac_policy_source": decision.policy_source,
                "abac_reason": decision.reason,
                "approval_id": response.get("approval_id"),
            },
        )
        return ok(
            response,
            message="Approval required before dispatch",
            tenant_id=scoped_tenant,
            contract="tenant_id_primary",
        )

    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        policy = manager_client.get_policy(tenant_id=native_tenant, agent_id=normalized_agent).get("data", {}).get("policy") or {}
        allow_list = {str(token or "").strip().lower() for token in policy.get("command_allow_list") or [] if str(token or "").strip()}
        block_list = {str(token or "").strip().lower() for token in policy.get("command_block_list") or [] if str(token or "").strip()}
        if action_id.lower() in block_list:
            raise HTTPException(status_code=403, detail=f"Action '{action_id}' is blocked by agent policy")
        if allow_list and action_id.lower() not in allow_list:
            raise HTTPException(status_code=403, detail=f"Action '{action_id}' is not allowed by agent policy")
        if not payload.dry_run and action_requires_approval_handshake(
            action_id,
            target_count=1,
            context={"tenant_id": scoped_tenant},
        ):
            return _pending_approval_response()
        command = None
        if not payload.dry_run:
            dispatch_response = manager_client.dispatch_command(
                tenant_id=native_tenant,
                agent_id=normalized_agent,
                payload={
                    "action": action_id,
                    "args": list(normalized_args),
                    "reason": payload.reason,
                    "requested_by": (user or {}).get("sub"),
                    "metadata": {
                        "source": "api.v2",
                        "dispatch": dispatch,
                    },
                },
            )
            command = dispatch_response.get("data", {}).get("command")
        response = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "action_id": action_id,
                "dry_run": bool(payload.dry_run),
                "dispatch": dispatch,
                "channel": "agent-manager-queue",
                "mode": "native_agent",
                "attempts": dispatch.get("attempts"),
                "result": command,
            }
        )
    else:
        command_policy = _effective_command_policy(agent_id=normalized_agent, tenant_id=scoped_tenant)
        enforce_allow = bool(command_policy.get("enforce_allow_list", True))
        allowed = {token.lower() for token in _normalize_tokens(command_policy.get("allow_list"))}
        blocked = {token.lower() for token in _normalize_tokens(command_policy.get("block_list"))}
        if action_id.lower() in blocked:
            raise HTTPException(
                status_code=403,
                detail=f"Action '{action_id}' is blocked by agent policy",
            )
        if enforce_allow and allowed and action_id.lower() not in allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Action '{action_id}' is not allowed by agent policy",
            )
        if not payload.dry_run and action_requires_approval_handshake(
            action_id,
            target_count=1,
            context={"tenant_id": scoped_tenant},
        ):
            return _pending_approval_response()

        execution = None
        if not payload.dry_run:
            execution = execute_action(client, action_id, dispatch, [normalized_agent])
        response = normalize_contract_response(
            {
                "tenant_id": scoped_tenant,
                "agent_id": normalized_agent,
                "provider": "wazuh",
                "action_id": action_id,
                "dry_run": bool(payload.dry_run),
                "dispatch": dispatch,
                "channel": execution.get("channel") if isinstance(execution, dict) else None,
                "mode": execution.get("mode") if isinstance(execution, dict) else None,
                "command_used": execution.get("command_used") if isinstance(execution, dict) else None,
                "attempts": execution.get("attempts") if isinstance(execution, dict) else dispatch.get("attempts"),
                "result": execution.get("result") if isinstance(execution, dict) else None,
            }
        )
    log_v2_write_audit(
        action="v2.agents.command.dispatch",
        entity_type="agent_command",
        entity_id=normalized_agent,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "action_id": action_id,
            "dry_run": bool(payload.dry_run),
            "reason": payload.reason,
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
            "dispatch_mode": response.get("mode"),
            "dispatch_channel": response.get("channel"),
        },
    )
    message = "Dispatch dry-run complete" if payload.dry_run else "Command dispatched"
    return ok(
        response,
        message=message,
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.get("/{agent_id}/health")
def get_agent_health(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        health_response = manager_client.get_health(tenant_id=native_tenant, agent_id=normalized_agent)
        isolation_response = manager_client.get_isolation(tenant_id=native_tenant, agent_id=normalized_agent)
        health = health_response.get("data", {}).get("health", {}) if isinstance(health_response, dict) else {}
        isolation = isolation_response.get("data", {}).get("isolation", {}) if isinstance(isolation_response, dict) else {}
        payload = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "status": str(health.get("status") or "unknown").strip().lower(),
                "manager_health": health,
                "agent_report": health or None,
                "isolation": isolation,
            }
        )
        return ok(payload, tenant_id=native_tenant, contract="tenant_id_primary")

    manager_agent = _manager_agent(normalized_agent)
    manager_status = _agent_status(manager_agent) or "unknown"
    manager_keepalive = _agent_keepalive(manager_agent)
    manager_health = {
        "status": manager_status,
        "connected": manager_status in {"active", "connected"},
        "last_keepalive": manager_keepalive or None,
    }

    local_health = _state_get(_HEALTH_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant) or {}
    isolation = _current_isolation_state(
        agent_id=normalized_agent,
        tenant_id=scoped_tenant,
        manager_agent=manager_agent,
    )
    effective_status = str(local_health.get("status") or manager_health.get("status") or "unknown").strip().lower()
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "wazuh",
            "status": effective_status,
            "manager_health": manager_health,
            "agent_report": local_health or None,
            "isolation": isolation,
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.post("/{agent_id}/health")
def report_agent_health(
    agent_id: str,
    request: Request,
    payload: AgentHealthReportRequest,
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=payload.tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    decision = enforce_abac(
        action="v2.agents.health.report",
        user=user,
        request=request,
        resource={
            "type": "agent_health",
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
        },
    )

    report = {
        "status": payload.status,
        "version": payload.version,
        "message": payload.message,
        "tamper_alert": bool(payload.tamper_alert),
        "metrics": dict(payload.metrics or {}),
        "checks": list(payload.checks or []),
        "reported_at_utc": utc_iso_now(),
        "reported_by": (user or {}).get("sub"),
    }
    _state_set(_HEALTH_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant, value=report)
    network_path_state = normalize_network_path_state(payload.metrics)
    _state_set(
        STATE_NETWORK_PATH,
        agent_id=normalized_agent,
        tenant_id=scoped_tenant,
        value=network_path_state,
    )

    free_memory_mb = 0
    try:
        free_memory_mb = int(
            report["metrics"].get("available_memory_mb")
            or report["metrics"].get("free_memory_mb")
            or 0
        )
    except Exception:
        free_memory_mb = 0
    now = utc_now_naive()
    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO agent_state (agent_id, online_status, last_heartbeat, free_memory_mb, updated_at)
                VALUES (:agent_id, :online_status, :last_heartbeat, :free_memory_mb, :updated_at)
                ON CONFLICT (agent_id)
                DO UPDATE SET
                    online_status=excluded.online_status,
                    last_heartbeat=excluded.last_heartbeat,
                    free_memory_mb=excluded.free_memory_mb,
                    updated_at=excluded.updated_at
                """
            ),
            {
                "agent_id": normalized_agent,
                "online_status": str(report["status"] or "").strip().lower(),
                "last_heartbeat": now,
                "free_memory_mb": free_memory_mb,
                "updated_at": now,
            },
        )
        db.commit()
    finally:
        db.close()

    response = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": provider,
            "status": report["status"],
            "tamper_alert": report["tamper_alert"],
            "reported_at_utc": report["reported_at_utc"],
            "reported_by": report["reported_by"],
        }
    )
    log_v2_write_audit(
        action="v2.agents.health.report",
        entity_type="agent_health",
        entity_id=normalized_agent,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "status": report["status"],
            "tamper_alert": report["tamper_alert"],
        },
        metadata={
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    return ok(
        response,
        message="Health report received",
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


@router.get("/{agent_id}/isolation")
def get_agent_isolation(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        isolation_response = manager_client.get_isolation(tenant_id=native_tenant, agent_id=normalized_agent)
        isolation = isolation_response.get("data", {}).get("isolation", {}) if isinstance(isolation_response, dict) else {}
        response = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "isolated": bool(isolation.get("enabled")),
                "group": _ISOLATION_GROUP,
                "source": "agent-manager",
                "reason": isolation.get("reason"),
                "updated_at_utc": isolation.get("updated_at_utc"),
                "updated_by": isolation.get("updated_by"),
                "manager_groups": [],
            }
        )
        return ok(response, tenant_id=native_tenant, contract="tenant_id_primary")

    manager_agent = _manager_agent(normalized_agent)
    state = _current_isolation_state(
        agent_id=normalized_agent,
        tenant_id=scoped_tenant,
        manager_agent=manager_agent,
    )
    response = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "wazuh",
            "isolated": bool(state.get("isolated")),
            "group": state.get("group"),
            "source": state.get("source"),
            "reason": state.get("reason"),
            "updated_at_utc": state.get("updated_at_utc"),
            "updated_by": state.get("updated_by"),
            "manager_groups": _agent_groups(manager_agent),
        }
    )
    return ok(response, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.post("/{agent_id}/isolation")
def set_agent_isolation(
    agent_id: str,
    request: Request,
    payload: AgentIsolationRequest,
    user=Depends(require_role("admin")),
):
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=payload.tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    decision = enforce_abac(
        action="v2.agents.isolation.apply",
        user=user,
        request=request,
        resource={
            "type": "agent_isolation",
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
        },
    )

    isolate_now = _resolve_isolation_payload(payload.model_dump())
    group = str(payload.group or _ISOLATION_GROUP).strip() or _ISOLATION_GROUP
    if provider == "native":
        native_tenant = _require_scoped_tenant(scoped_tenant)
        manager_response = manager_client.apply_isolation(
            tenant_id=native_tenant,
            agent_id=normalized_agent,
            payload={
                "enabled": isolate_now,
                "reason": payload.reason,
                "requested_by": (user or {}).get("sub"),
                "metadata": {"group": group},
            },
        )
        isolation = manager_response.get("data", {}).get("isolation", {}) if isinstance(manager_response, dict) else {}
        isolation_state = {
            "isolated": bool(isolation.get("enabled")),
            "group": group,
            "reason": payload.reason,
            "updated_at_utc": isolation.get("updated_at_utc") or utc_iso_now(),
            "updated_by": isolation.get("updated_by") or (user or {}).get("sub"),
        }
        _state_set(_ISOLATION_STATE, agent_id=normalized_agent, tenant_id=native_tenant, value=isolation_state)
        response = normalize_contract_response(
            {
                "tenant_id": native_tenant,
                "agent_id": normalized_agent,
                "provider": "native",
                "isolated": bool(isolation.get("enabled")),
                "group": group,
                "reason": payload.reason,
                "operations": [f"manager_isolation:{'enabled' if isolate_now else 'released'}"],
                "updated_at_utc": isolation_state["updated_at_utc"],
                "updated_by": isolation_state["updated_by"],
                "manager_groups": [],
            }
        )
        log_v2_write_audit(
            action="v2.agents.isolation.apply",
            entity_type="agent_isolation",
            entity_id=normalized_agent,
            user=user,
            request=request,
            tenant_id=native_tenant,
            changes={
                "provider": "native",
                "isolated": isolate_now,
                "group": group,
                "reason": payload.reason,
            },
            metadata={
                "operations": response.get("operations"),
                "abac_policy_source": decision.policy_source,
                "abac_reason": decision.reason,
            },
        )
        message = "Isolation enabled" if isolate_now else "Isolation released"
        return ok(
            response,
            message=message,
            tenant_id=native_tenant,
            contract="tenant_id_primary",
        )

    operations: list[str] = []
    if isolate_now:
        try:
            client.assign_agent_group(normalized_agent, group)
            operations.append(f"group_assigned:{group}")
        except HTTPException as exc:
            if not _AUTO_CREATE_ISOLATION_GROUP or exc.status_code not in {400, 404}:
                raise
            client.create_group(group)
            operations.append(f"group_created:{group}")
            client.assign_agent_group(normalized_agent, group)
            operations.append(f"group_assigned:{group}")
    else:
        try:
            client.remove_agent_group(normalized_agent, group)
            operations.append(f"group_removed:{group}")
        except HTTPException as exc:
            if exc.status_code not in {400, 404}:
                raise
            operations.append(f"group_remove_noop:{group}")

    isolation_state = {
        "isolated": isolate_now,
        "group": group,
        "reason": payload.reason,
        "updated_at_utc": utc_iso_now(),
        "updated_by": (user or {}).get("sub"),
    }
    _state_set(_ISOLATION_STATE, agent_id=normalized_agent, tenant_id=scoped_tenant, value=isolation_state)

    manager_agent = _manager_agent(normalized_agent)
    current = _current_isolation_state(
        agent_id=normalized_agent,
        tenant_id=scoped_tenant,
        manager_agent=manager_agent,
    )
    response = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "wazuh",
            "isolated": bool(current.get("isolated")),
            "group": group,
            "reason": payload.reason,
            "operations": operations,
            "updated_at_utc": isolation_state["updated_at_utc"],
            "updated_by": isolation_state["updated_by"],
            "manager_groups": _agent_groups(manager_agent),
        }
    )
    log_v2_write_audit(
        action="v2.agents.isolation.apply",
        entity_type="agent_isolation",
        entity_id=normalized_agent,
        user=user,
        request=request,
        tenant_id=scoped_tenant,
        changes={
            "isolated": isolate_now,
            "group": group,
            "reason": payload.reason,
        },
        metadata={
            "operations": operations,
            "abac_policy_source": decision.policy_source,
            "abac_reason": decision.reason,
        },
    )
    message = "Isolation enabled" if isolate_now else "Isolation released"
    return ok(
        response,
        message=message,
        tenant_id=scoped_tenant,
        contract="tenant_id_primary",
    )


def _require_native_agent_scope(
    *,
    agent_id: str,
    user: Mapping[str, Any] | None,
    tenant_id: int | None,
) -> tuple[str, int]:
    normalized_agent, scoped_tenant = _resolve_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    provider = _enrolled_provider(agent_id=normalized_agent, tenant_id=scoped_tenant)
    if provider != "native":
        raise HTTPException(
            status_code=400,
            detail="This endpoint is available for native C2F agents only",
        )
    return normalized_agent, _require_scoped_tenant(scoped_tenant)


@router.get("/{agent_id}/events")
def get_agent_events(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.get_events(
        tenant_id=scoped_tenant,
        agent_id=normalized_agent,
        limit=limit,
    )
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "items": manager_response.get("data", {}).get("items", []),
            "total": manager_response.get("data", {}).get("total", 0),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/alerts")
def get_agent_alerts(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.get_alerts(
        tenant_id=scoped_tenant,
        agent_id=normalized_agent,
        limit=limit,
    )
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "items": manager_response.get("data", {}).get("items", []),
            "total": manager_response.get("data", {}).get("total", 0),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/storyline")
def get_agent_storyline(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=10, le=1000),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.get_storyline(
        tenant_id=scoped_tenant,
        agent_id=normalized_agent,
        limit=limit,
    )
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "storyline": manager_response.get("data", {}).get("storyline", {}),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/posture")
def get_agent_posture(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.get_posture(tenant_id=scoped_tenant, agent_id=normalized_agent)
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "posture": manager_response.get("data", {}).get("posture", {}),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/mapping")
def get_agent_mapping(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.get_mapping(tenant_id=scoped_tenant, agent_id=normalized_agent)
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "mapping": manager_response.get("data", {}).get("mapping", {}),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/hunt")
def hunt_agent_telemetry(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    query: str = Query(min_length=2, max_length=200),
    limit: int = Query(default=100, ge=1, le=1000),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.hunt(
        tenant_id=scoped_tenant,
        agent_id=normalized_agent,
        query=query,
        limit=limit,
    )
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "query": query,
            "tokens": manager_response.get("data", {}).get("tokens", []),
            "events": manager_response.get("data", {}).get("events", []),
            "alerts": manager_response.get("data", {}).get("alerts", []),
            "event_matches": manager_response.get("data", {}).get("event_matches", 0),
            "alert_matches": manager_response.get("data", {}).get("alert_matches", 0),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")


@router.get("/{agent_id}/commands/history")
def list_agent_command_history(
    agent_id: str,
    tenant_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=200, ge=1, le=2000),
    user=Depends(current_user),
):
    normalized_agent, scoped_tenant = _require_native_agent_scope(
        agent_id=agent_id,
        user=user,
        tenant_id=tenant_id,
    )
    manager_response = manager_client.list_commands(
        tenant_id=scoped_tenant,
        agent_id=normalized_agent,
        limit=limit,
    )
    payload = normalize_contract_response(
        {
            "tenant_id": scoped_tenant,
            "agent_id": normalized_agent,
            "provider": "native",
            "items": manager_response.get("data", {}).get("items", []),
            "total": manager_response.get("data", {}).get("total", 0),
        }
    )
    return ok(payload, tenant_id=scoped_tenant, contract="tenant_id_primary")
