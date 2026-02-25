import json
from typing import Any, Dict, List

from fastapi import HTTPException

from core.settings import SETTINGS


_ACTION_ALIASES: Dict[str, Dict[str, str]] = {
    "toc-scan": {
        "base_id": "ioc-scan",
        "label": "TOC Hunt Scan",
        "description": "Threat hunting: scan endpoint for TOC indicators using IOC scan engine.",
    },
}

_INTERNAL_ONLY_ACTION_IDS = {
    "custom-os-command",
}


def _actions_config() -> List[Dict[str, Any]]:
    cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
    if not cfg.get("enabled", True):
        return []
    return cfg.get("commands", []) or []


def _runner_config() -> Dict[str, Any]:
    cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
    runner = cfg.get("runner", {}) if isinstance(cfg, dict) else {}
    if not isinstance(runner, dict):
        runner = {}
    command = str(runner.get("command") or "c2f-runner").strip()
    if not command:
        command = "c2f-runner"
    return {
        "enabled": bool(runner.get("enabled", False)),
        "command": command,
        "custom": bool(runner.get("custom", False)),
        "prepend_action": bool(runner.get("prepend_action", True)),
    }


def _fallback_commands() -> List[str]:
    cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
    values = cfg.get("fallback_commands", []) if isinstance(cfg, dict) else []
    if not isinstance(values, list):
        values = []
    result: List[str] = []
    for value in values:
        cmd = str(value or "").strip()
        if cmd and cmd not in result:
            result.append(cmd)
    return result


def _normalize_docs(action: Dict[str, Any]) -> Dict[str, str]:
    raw = action.get("docs") or action.get("runbook") or {}
    if isinstance(raw, str):
        docs: Dict[str, str] = {"what_it_does": raw}
    elif isinstance(raw, dict):
        docs = {str(k): str(v) for k, v in raw.items() if v is not None}
    else:
        docs = {}

    description = str(action.get("description") or "").strip()
    category = str(action.get("category") or "response").strip()
    risk = str(action.get("risk") or "medium").strip()

    if not docs.get("what_it_does"):
        docs["what_it_does"] = description or "Executes an automated response step on one or more endpoints."
    if not docs.get("when_to_use"):
        docs["when_to_use"] = f"Use during triage/response for {category} scenarios when the alert context supports it."
    if not docs.get("impact"):
        docs["impact"] = f"Risk: {risk}. This action may change endpoint state or collect data."
    if not docs.get("rollback"):
        docs["rollback"] = "Rollback is action-specific. Review the execution output and apply the reverse change if needed."
    if not docs.get("evidence"):
        docs["evidence"] = "Execution output includes connector stdout/stderr plus C2F_LOG evidence lines from the endpoint."

    return docs


def list_actions() -> List[Dict[str, Any]]:
    actions = []
    seen_ids = set()
    seen_signatures = set()
    for action in _actions_config():
        action_id = str(action.get("id") or "").strip()
        action_id_key = action_id.lower()
        if action_id_key in _INTERNAL_ONLY_ACTION_IDS:
            # Keep internal-only actions available through get_action() for backend
            # orchestration paths, but do not expose them in analyst action catalogs.
            continue
        if action_id_key:
            if action_id_key in seen_ids:
                continue
            seen_ids.add(action_id_key)

        command_key = str(action.get("command") or "").strip().lower()
        signature = (
            command_key,
            json.dumps(action.get("inputs", []), sort_keys=True, default=str),
            str(action.get("category", "response")).strip().lower(),
        )
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)

        actions.append(
            {
                "id": action_id,
                "label": action.get("label"),
                "description": action.get("description"),
                "inputs": action.get("inputs", []),
                "category": action.get("category", "response"),
                "risk": action.get("risk", "medium"),
                "custom": bool(action.get("custom")),
                "command": action.get("command"),
                "docs": _normalize_docs(action),
                "capabilities": action.get("capabilities") or {},
            }
        )
    by_id = {str(item.get("id") or "").strip().lower(): item for item in actions if item.get("id")}
    for alias_id, spec in _ACTION_ALIASES.items():
        if alias_id in by_id:
            # Real action already exists in settings; don't duplicate alias rows.
            continue
        base_id = str(spec.get("base_id") or "").strip().lower()
        if not base_id:
            continue
        base = by_id.get(base_id)
        if not base:
            continue
        clone = dict(base)
        clone["id"] = alias_id
        if spec.get("label"):
            clone["label"] = spec["label"]
        if spec.get("description"):
            clone["description"] = spec["description"]
        actions.append(clone)
    return actions


def get_action(action_id: str) -> Dict[str, Any]:
    requested = str(action_id or "").strip()
    requested_l = requested.lower()
    for action in _actions_config():
        if str(action.get("id") or "").strip().lower() == requested_l:
            return action
    alias = _ACTION_ALIASES.get(requested_l)
    if alias:
        base_id = str(alias.get("base_id") or "").strip().lower()
        if base_id:
            for action in _actions_config():
                if str(action.get("id") or "").strip().lower() != base_id:
                    continue
                merged = dict(action)
                merged["id"] = requested_l
                if alias.get("label"):
                    merged["label"] = alias["label"]
                if alias.get("description"):
                    merged["description"] = alias["description"]
                return merged
    raise HTTPException(status_code=404, detail="Action not found")


def normalize_args(action: Dict[str, Any], args: Any) -> List[str]:
    if args is None:
        return []

    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = [args]

    if isinstance(args, dict):
        inputs = action.get("inputs") or []
        if inputs:
            capabilities = action.get("capabilities") if isinstance(action, dict) else {}
            validation_rules = []
            if isinstance(capabilities, dict):
                validation_rules = capabilities.get("validation", []) or []
            rule_by_field: Dict[str, Dict[str, Any]] = {}
            for rule in validation_rules:
                if not isinstance(rule, dict):
                    continue
                field_name = str(rule.get("field") or "").strip()
                if field_name:
                    rule_by_field[field_name] = rule

            # Build positional arg list in the same order as inputs.
            # Inputs may include optional fields; missing optional values are omitted only
            # when they are trailing inputs to preserve positional mapping.
            values: List[Any] = []
            for field in inputs:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name") or "").strip()
                if not name:
                    continue

                rule = rule_by_field.get(name, {})
                required = field.get("required")
                if required is None:
                    required = rule.get("required", False)
                required = bool(required)
                default = field.get("default")
                if default is None:
                    default = rule.get("default")

                provided = name in args
                raw = args.get(name) if provided else None
                missing = raw is None or (isinstance(raw, str) and raw.strip() == "")
                if missing:
                    if required:
                        raise HTTPException(status_code=400, detail=f"Missing argument: {name}")
                    if default is not None and (not isinstance(default, str) or default.strip() != ""):
                        values.append(default)
                    else:
                        values.append(None)
                    continue

                values.append(raw)

            # Trim trailing optional Nones (missing optional inputs at the end).
            while values and values[-1] is None:
                values.pop()
            if any(v is None for v in values):
                # Preserve positional mapping while allowing optional middle fields to be
                # omitted by filling explicit empty placeholders.
                values = ["" if v is None else v for v in values]

            return [str(v) for v in values]
        return [str(v) for v in args.values()]

    if isinstance(args, list):
        return [str(v) for v in args]

    return [str(args)]


def resolve_action_dispatch(action: Dict[str, Any], arguments: List[str]) -> Dict[str, Any]:
    action_id = str(action.get("id") or "").strip()
    action_command = str(action.get("command") or action_id).strip()
    if not action_command:
        raise HTTPException(status_code=400, detail="Action command is not configured")

    attempts: List[Dict[str, Any]] = []

    # Attempt 1: direct command mode (legacy/default)
    attempts.append(
        {
            "command": action_command,
            "arguments": arguments or [],
            "custom": bool(action.get("custom")),
        }
    )

    # Attempt 2: explicit runner mode (if enabled in settings)
    runner = _runner_config()
    if runner["enabled"]:
        dispatch_args: List[str] = []
        if runner["prepend_action"]:
            dispatch_args.append(action_command)
        dispatch_args.extend(arguments or [])
        attempts.append(
            {
                "command": runner["command"],
                "arguments": dispatch_args,
                "custom": runner["custom"],
            }
        )

    # Attempt 3+: configured fallback aliases that can behave as runners.
    for fallback_cmd in _fallback_commands():
        fallback_args = [action_command] + (arguments or [])
        attempts.append(
            {
                "command": fallback_cmd,
                "arguments": fallback_args,
                "custom": False,
            }
        )

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for attempt in attempts:
        key = (
            attempt["command"],
            tuple(attempt["arguments"]),
            bool(attempt["custom"]),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(attempt)

    # Keep legacy top-level fields for compatibility.
    first = deduped[0]
    return {
        "command": first["command"],
        "arguments": first["arguments"],
        "custom": first["custom"],
        "action_command": action_command,
        "attempts": deduped,
    }
