from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any, Iterable, Mapping

from sqlalchemy import text

from core.actions import get_action
from core.agent_runtime_state import STATE_HEALTH, find_any_agent_state, get_agent_state, upsert_agent_state
from core.approval_policy import get_policy
from core.time_utils import parse_utc_datetime, utc_iso_now, utc_now_naive
from db.database import connect


STATE_NETWORK_PATH = "network_path"
STATE_SCA_BASELINE = "sca_baseline"

_APPROVAL_REQUIRED_ACTION_IDS = {
    "collect-memory",
    "collect-forensics",
    "custom-os-command",
    "disable-account",
    "enable-account",
    "firewall-drop",
    "fleet-software-update",
    "global-shell",
    "hash-blocklist",
    "host-deny",
    "kill-process",
    "netsh",
    "package-update",
    "patch-linux",
    "patch-windows",
    "quarantine-file",
    "rollback-kb",
    "route-null",
    "service-restart",
    "software-install-upgrade",
    "unblock-ip",
    "win-route-null",
    "windows-os-update",
}
_APPROVAL_REQUIRED_CATEGORIES = {"containment", "patching", "recovery", "response"}
_LOW_RISK_BYPASS_ACTION_IDS = {"endpoint-healthcheck", "ioc-scan", "sca-rescan", "threat-hunt-persistence", "toc-scan", "yara-scan"}
_DUAL_AUTH_ACTION_IDS = {
    "custom-os-command",
    "disable-account",
    "firewall-drop",
    "global-shell",
    "hash-blocklist",
    "host-deny",
    "kill-process",
    "netsh",
    "quarantine-file",
    "route-null",
    "win-route-null",
}
_HEAVY_LOAD_CPU_THRESHOLD = 85.0
_HEAVY_LOAD_MEMORY_MB = 512
_STALE_HEARTBEAT_SECONDS = 120
_PROCESS_HINT_KEYS = {
    "commandline",
    "command_line",
    "cmdline",
    "process_name",
    "image",
    "exe",
    "path",
    "pid",
    "processid",
    "parentcommandline",
    "parent_command_line",
}
_SEMANTIC_TIME_HINTS = (
    (re.compile(r"\blast hour\b"), timedelta(hours=1)),
    (re.compile(r"\blast 2 hours\b"), timedelta(hours=2)),
    (re.compile(r"\blast 6 hours\b"), timedelta(hours=6)),
    (re.compile(r"\blast 12 hours\b"), timedelta(hours=12)),
    (re.compile(r"\blast 24 hours\b|\blast day\b"), timedelta(hours=24)),
)
_SEMANTIC_AGENT_HINT = re.compile(r"\b(?:agent|host|endpoint)\s+([A-Za-z0-9._-]+)\b", re.IGNORECASE)
_SEMANTIC_PATH_HINT = re.compile(r"\bfrom\s+([A-Za-z]:\\[^\s,;]+|/[^\s,;]+)", re.IGNORECASE)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _dedupe(items: Iterable[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items or []:
        value = _as_text(item)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _action_metadata(action_id: str) -> dict[str, Any]:
    lowered = _as_text(action_id).lower()
    if not lowered:
        return {"id": "", "category": "", "risk": "medium"}
    try:
        action = get_action(lowered)
    except Exception:
        action = {
            "id": lowered,
            "category": "response" if lowered in _APPROVAL_REQUIRED_ACTION_IDS else "validation",
            "risk": "critical" if lowered in {"custom-os-command", "global-shell"} else "high",
        }
    return {
        "id": _as_text(action.get("id") or lowered).lower(),
        "category": _as_text(action.get("category")).lower(),
        "risk": _as_text(action.get("risk")).lower() or "medium",
    }


def action_requires_approval_handshake(
    action_id: str,
    *,
    target_count: int = 1,
    context: Mapping[str, Any] | None = None,
) -> bool:
    ctx = dict(context or {})
    if ctx.get("approval_id") or ctx.get("approval_status") == "APPROVED":
        return False
    if ctx.get("system_forensics_capture"):
        return False

    meta = _action_metadata(action_id)
    lowered = meta["id"]
    if lowered in _LOW_RISK_BYPASS_ACTION_IDS:
        return False
    if lowered in _APPROVAL_REQUIRED_ACTION_IDS:
        return True
    if meta["category"] in _APPROVAL_REQUIRED_CATEGORIES:
        return True
    if meta["risk"] in {"high", "critical"}:
        return True
    if target_count > 25 and meta["category"] not in {"validation", "compliance"}:
        return True
    return False


def build_contextual_approval_policy(
    action_id: str,
    *,
    target_count: int = 1,
    incident_priority: str | None = None,
    incident_score: int | None = None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    base = get_policy(action_id)
    handshake_required = action_requires_approval_handshake(
        action_id,
        target_count=target_count,
        context=context,
    )
    fleet_wide = bool((context or {}).get("fleet_wide")) or int(target_count or 0) >= 25
    critical_incident = _as_text(incident_priority).lower() == "critical" or _safe_int(incident_score, 0) >= 80
    dual_authorization = handshake_required and (
        critical_incident or (fleet_wide and _action_metadata(action_id)["id"] in _DUAL_AUTH_ACTION_IDS)
    )

    policy = {
        "requirements": [dict(item) for item in (base.get("requirements") or [])],
        "justification_required": bool(base.get("justification_required")),
        "prevent_self_approval": bool(base.get("prevent_self_approval", True)),
        "handshake_required": handshake_required,
        "dual_authorization_required": dual_authorization,
    }
    if not handshake_required:
        return policy

    if dual_authorization:
        policy["requirements"] = [{"role": "admin", "count": 2}]
        policy["justification_required"] = True
        return policy

    if not policy["requirements"]:
        policy["requirements"] = [{"role": "admin", "count": 1}]
    return policy


def build_incident_score(
    *,
    agents: Iterable[str],
    tactics: Iterable[str],
    alert_count: int,
    identities: Iterable[str] | None = None,
    iocs: Iterable[str] | None = None,
    tamper_suspected: bool = False,
) -> dict[str, Any]:
    distinct_agents = _dedupe(agents)
    distinct_tactics = _dedupe([_as_text(item).lower() for item in tactics or []])
    distinct_identities = _dedupe([_as_text(item).lower() for item in identities or []])
    distinct_iocs = _dedupe([_as_text(item).lower() for item in iocs or []])

    blast_radius_points = min(20, max(0, len(distinct_agents) - 1) * 10)
    tactical_depth_points = 30 if len(distinct_tactics) >= 3 else min(20, len(distinct_tactics) * 10)
    alert_volume_points = min(20, max(0, _safe_int(alert_count, 0)) * 2)
    identity_points = min(10, len(distinct_identities) * 5)
    ioc_points = min(10, len(distinct_iocs) * 5)
    tamper_points = 10 if tamper_suspected else 0

    score = min(
        100,
        blast_radius_points + tactical_depth_points + alert_volume_points + identity_points + ioc_points + tamper_points,
    )
    if score >= 80:
        priority = "critical"
    elif score >= 60:
        priority = "high"
    elif score >= 35:
        priority = "medium"
    else:
        priority = "low"

    attack_narrative = (
        f"Attack activity spans {len(distinct_tactics)} tactic stage(s) across "
        f"{max(1, len(distinct_agents))} agent(s) with {max(1, _safe_int(alert_count, 0))} correlated alert(s)."
    )
    if tamper_suspected:
        attack_narrative += " Telemetry silence suggests possible anti-tamper interference."

    return {
        "score": score,
        "priority": priority,
        "attack_narrative": attack_narrative,
        "requires_dual_authorization": priority == "critical",
        "breakdown": {
            "blast_radius_points": blast_radius_points,
            "tactical_depth_points": tactical_depth_points,
            "alert_volume_points": alert_volume_points,
            "identity_points": identity_points,
            "ioc_points": ioc_points,
            "tamper_points": tamper_points,
            "distinct_agents": len(distinct_agents),
            "mitre_stage_count": len(distinct_tactics),
        },
    }


def extract_forensic_snapshot_hint(raw_json: Mapping[str, Any] | None) -> dict[str, Any]:
    source = dict(raw_json or {})
    flattened: dict[str, Any] = {}

    def walk(prefix: str, value: Any, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                walk(f"{prefix}.{key}" if prefix else str(key), child, depth + 1)
            return
        if isinstance(value, list):
            for idx, child in enumerate(value[:8]):
                walk(f"{prefix}[{idx}]", child, depth + 1)
            return
        key = prefix.split(".")[-1].lower()
        if key in _PROCESS_HINT_KEYS:
            flattened[key] = value

    walk("", source)
    command_line = _as_text(
        flattened.get("commandline")
        or flattened.get("command_line")
        or flattened.get("cmdline")
        or flattened.get("parentcommandline")
        or flattened.get("parent_command_line")
    )
    image = _as_text(flattened.get("image") or flattened.get("exe") or flattened.get("path"))
    process_name = _as_text(flattened.get("process_name") or image.rsplit("\\", 1)[-1] or image.rsplit("/", 1)[-1])
    pid = _safe_int(flattened.get("pid") or flattened.get("processid"), 0)
    strings = [token for token in re.split(r"[\s\"']+", command_line) if len(token) >= 5][:12]
    return {
        "process_name": process_name or None,
        "image": image or None,
        "pid": pid or None,
        "command_line": command_line or None,
        "memory_strings": strings,
        "captured_at_utc": utc_iso_now(),
    }


def build_forensic_snapshot_plan(*, alerts: Iterable[Mapping[str, Any]], incident_id: int) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for alert in alerts or []:
        agent_id = _as_text(alert.get("agent_id"))
        raw_json = alert.get("raw_json") if isinstance(alert, Mapping) else {}
        hint = extract_forensic_snapshot_hint(raw_json if isinstance(raw_json, Mapping) else {})
        key = (agent_id, _as_text(hint.get("process_name") or hint.get("image")))
        if not agent_id or key in seen:
            continue
        seen.add(key)
        plans.append(
            {
                "incident_id": int(incident_id),
                "agent_id": agent_id,
                "action_id": "collect-memory",
                "reason": "Automatic evidence preservation for correlated incident",
                "hint": hint,
            }
        )
        if len(plans) >= 3:
            break
    return plans


def build_virtual_patch_suggestions(
    *,
    telemetry_context: Mapping[str, Any] | None,
    recommendations: Iterable[Mapping[str, Any] | str] | None,
) -> list[dict[str, Any]]:
    context = dict(telemetry_context or {})
    critical_vulns = _safe_int(context.get("vulnerabilities_critical"), 0)
    high_vulns = _safe_int(context.get("vulnerabilities_high"), 0)
    alert_pressure = _safe_int(context.get("alerts_high"), 0) + _safe_int(context.get("alerts_critical"), 0)
    if critical_vulns <= 0 and high_vulns <= 0:
        return []

    candidate_actions: Counter[str] = Counter()
    for item in recommendations or []:
        if isinstance(item, Mapping):
            action_id = _as_text(item.get("recommended_action") or item.get("action_id"))
        else:
            action_id = _as_text(item)
        if action_id:
            candidate_actions[action_id.lower()] += 1

    shield_actions = ["host-deny", "firewall-drop", "hash-blocklist"]
    if alert_pressure <= 0:
        shield_actions = ["hash-blocklist", "host-deny", "firewall-drop"]

    out: list[dict[str, Any]] = []
    for action_id in shield_actions:
        confidence = 65
        if candidate_actions[action_id] > 0:
            confidence += 10
        if critical_vulns > 0:
            confidence += 10
        out.append(
            {
                "action_id": action_id,
                "confidence": min(95, confidence),
                "reason": "Temporary shield recommendation derived from fleet vulnerability pressure and analytics telemetry.",
            }
        )
    return out


def compute_sca_group_baselines(
    agent_rows: Iterable[Mapping[str, Any]],
    *,
    consensus_ratio: float = 0.8,
) -> dict[str, dict[str, Any]]:
    grouped_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in agent_rows or []:
        groups = row.get("groups") if isinstance(row.get("groups"), list) else []
        group_name = _as_text(row.get("group"))
        keys = groups or ([group_name] if group_name else ["ungrouped"])
        for key in keys:
            grouped_rows[_as_text(key) or "ungrouped"].append(row)

    baselines: dict[str, dict[str, Any]] = {}
    for group_name, rows in grouped_rows.items():
        required_pass: Counter[str] = Counter()
        observed: Counter[str] = Counter()
        titles: dict[str, str] = {}
        for row in rows:
            for policy in row.get("policies") or []:
                for check in policy.get("checks") or []:
                    check_id = _as_text(check.get("id"))
                    if not check_id:
                        continue
                    observed[check_id] += 1
                    titles[check_id] = _as_text(check.get("title")) or check_id
                    if _as_text(check.get("result")).lower() == "passed":
                        required_pass[check_id] += 1

        required_checks: list[dict[str, Any]] = []
        for check_id, seen in observed.items():
            if seen <= 0:
                continue
            pass_ratio = required_pass[check_id] / max(1, seen)
            if pass_ratio >= consensus_ratio:
                required_checks.append(
                    {
                        "check_id": check_id,
                        "title": titles.get(check_id) or check_id,
                        "pass_ratio": round(pass_ratio, 3),
                    }
                )
        required_checks.sort(key=lambda item: (-float(item.get("pass_ratio") or 0.0), _as_text(item.get("check_id"))))
        baselines[group_name] = {
            "group": group_name,
            "consensus_ratio": float(consensus_ratio),
            "required_checks": required_checks,
            "agents_observed": len(rows),
            "captured_at_utc": utc_iso_now(),
        }
    return baselines


def compute_sca_drift(
    agent_row: Mapping[str, Any],
    baseline: Mapping[str, Any] | None,
) -> dict[str, Any]:
    required = {
        _as_text(item.get("check_id")): item
        for item in (baseline or {}).get("required_checks", [])
        if _as_text(item.get("check_id"))
    }
    if not required:
        return {"drifted": False, "drift_count": 0, "violations": []}

    failed: dict[str, dict[str, Any]] = {}
    for policy in agent_row.get("policies") or []:
        for check in policy.get("checks") or []:
            check_id = _as_text(check.get("id"))
            if check_id and _as_text(check.get("result")).lower() == "failed":
                failed[check_id] = dict(check)

    violations: list[dict[str, Any]] = []
    for check_id, baseline_item in required.items():
        if check_id not in failed:
            continue
        check = failed[check_id]
        violations.append(
            {
                "check_id": check_id,
                "title": _as_text(check.get("title") or baseline_item.get("title")) or check_id,
                "remediation": _as_text(check.get("remediation")),
                "reason": _as_text(check.get("reason")),
            }
        )
    violations.sort(key=lambda item: _as_text(item.get("check_id")))
    return {
        "drifted": bool(violations),
        "drift_count": len(violations),
        "violations": violations,
    }


def persist_group_baseline(*, group_name: str, tenant_id: int | None, baseline: Mapping[str, Any], actor: str | None = None) -> dict[str, Any]:
    payload = dict(baseline or {})
    payload["group"] = _as_text(group_name) or "ungrouped"
    return upsert_agent_state(
        state_kind=STATE_SCA_BASELINE,
        agent_id=f"group:{payload['group']}",
        tenant_id=tenant_id,
        value=payload,
        updated_by=actor,
    )


def load_group_baseline(*, group_name: str, tenant_id: int | None) -> dict[str, Any] | None:
    return get_agent_state(
        state_kind=STATE_SCA_BASELINE,
        agent_id=f"group:{_as_text(group_name) or 'ungrouped'}",
        tenant_id=tenant_id,
    )


def infer_resource_pressure(agent_id: str, *, tenant_id: int | None = None) -> dict[str, Any]:
    normalized_agent = _as_text(agent_id)
    health_state = get_agent_state(state_kind=STATE_HEALTH, agent_id=normalized_agent, tenant_id=tenant_id)
    if health_state is None:
        health_state = find_any_agent_state(state_kind=STATE_HEALTH, agent_id=normalized_agent) or {}
    network_state = get_agent_state(state_kind=STATE_NETWORK_PATH, agent_id=normalized_agent, tenant_id=tenant_id)
    if network_state is None:
        network_state = find_any_agent_state(state_kind=STATE_NETWORK_PATH, agent_id=normalized_agent) or {}

    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT online_status, last_heartbeat, free_memory_mb
                FROM agent_state
                WHERE agent_id=:agent_id
                LIMIT 1
                """
            ),
            {"agent_id": normalized_agent},
        ).fetchone()
    finally:
        db.close()

    metrics = health_state.get("metrics") if isinstance(health_state.get("metrics"), dict) else {}
    cpu_percent = _safe_float(metrics.get("cpu_percent") or metrics.get("cpu") or metrics.get("cpu_usage"))
    free_memory_mb = _safe_int(
        metrics.get("available_memory_mb") or metrics.get("free_memory_mb") or (row[2] if row else 0),
        0,
    )
    reported_at = parse_utc_datetime(health_state.get("reported_at_utc")) if isinstance(health_state, dict) else None
    last_heartbeat = row[1] if row else None
    now = utc_now_naive()
    stale_heartbeat = False
    if last_heartbeat is not None:
        stale_heartbeat = last_heartbeat < (now - timedelta(seconds=_STALE_HEARTBEAT_SECONDS))
    elif reported_at is not None:
        stale_heartbeat = reported_at.replace(tzinfo=None) < (now - timedelta(seconds=_STALE_HEARTBEAT_SECONDS))

    reasons: list[str] = []
    if cpu_percent >= _HEAVY_LOAD_CPU_THRESHOLD:
        reasons.append("high_cpu")
    if free_memory_mb and free_memory_mb <= _HEAVY_LOAD_MEMORY_MB:
        reasons.append("low_memory")
    if bool(health_state.get("tamper_alert")):
        reasons.append("tamper_alert")
    if stale_heartbeat:
        reasons.append("stale_heartbeat")

    return {
        "agent_id": normalized_agent,
        "constrained": bool(reasons),
        "reasons": reasons,
        "cpu_percent": cpu_percent,
        "free_memory_mb": free_memory_mb,
        "online_status": _as_text(row[0] if row else ""),
        "network_ok": bool(network_state.get("network_ok", True)),
        "network_path": _as_text(network_state.get("path") or network_state.get("network_path")),
        "reported_at_utc": health_state.get("reported_at_utc") if isinstance(health_state, dict) else None,
    }


def partition_adaptive_window_targets(
    agent_ids: Iterable[str],
    *,
    tenant_id: int | None = None,
) -> dict[str, Any]:
    ready: list[str] = []
    deferred: list[str] = []
    states: list[dict[str, Any]] = []
    for agent_id in _dedupe(agent_ids):
        state = infer_resource_pressure(agent_id, tenant_id=tenant_id)
        states.append(state)
        if state.get("constrained"):
            deferred.append(agent_id)
        else:
            ready.append(agent_id)
    return {
        "ready": ready,
        "deferred": deferred,
        "states": states,
        "adaptive_windowing": bool(deferred),
    }


def evaluate_agent_silence_tamper(
    agent_id: str,
    *,
    tenant_id: int | None = None,
    manager_online: bool | None = None,
) -> dict[str, Any]:
    state = infer_resource_pressure(agent_id, tenant_id=tenant_id)
    path_ok = bool(state.get("network_ok", True))
    stale = "stale_heartbeat" in (state.get("reasons") or [])
    inferred_manager_online = str(state.get("online_status") or "").strip().lower() in {"active", "connected", "online"}
    effective_manager_online = inferred_manager_online if manager_online is None else bool(manager_online)
    suspected = bool(effective_manager_online and path_ok and stale)
    return {
        "agent_id": _as_text(agent_id),
        "suspected": suspected,
        "severity": "critical" if suspected else "warning",
        "reason": "Potential Anti-Virus/EDR Tampering" if suspected else "No tamper condition met",
        "network_path": state.get("network_path"),
        "manager_online": effective_manager_online,
        "state": state,
    }


def normalize_network_path_state(metrics: Mapping[str, Any] | None) -> dict[str, Any]:
    data = dict(metrics or {})
    path = _as_text(
        data.get("network_path")
        or data.get("last_known_network_path")
        or data.get("egress_path")
        or data.get("path")
    )
    status = _as_text(data.get("network_status") or data.get("path_status")).lower()
    if not status:
        status = "ok" if _as_text(data.get("network_ok")).lower() not in {"0", "false", "no"} else "degraded"
    return {
        "path": path or None,
        "network_ok": status in {"ok", "healthy", "reachable", "up"},
        "status": status,
        "latency_ms": _safe_int(data.get("latency_ms"), 0) or None,
        "captured_at_utc": utc_iso_now(),
    }


def interpret_semantic_search(query: str) -> dict[str, Any]:
    raw_query = _as_text(query)
    if not raw_query:
        return {"enabled": False, "query": ""}
    lowered = raw_query.lower()
    parsed_query = raw_query
    start = None
    now = utc_now_naive()

    for pattern, delta in _SEMANTIC_TIME_HINTS:
        if pattern.search(lowered):
            start = now - delta
            break
    if "today" in lowered and start is None:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    agent_match = _SEMANTIC_AGENT_HINT.search(raw_query)
    agent_id = agent_match.group(1) if agent_match else None

    query_terms: list[str] = []
    if "powershell" in lowered:
        query_terms.append('"powershell" OR "powershell.exe"')
    if "unauthorized" in lowered or "suspicious" in lowered:
        query_terms.append('"unauthorized" OR "suspicious" OR "policy"')
    if "process created" in lowered or "process creation" in lowered or "running" in lowered:
        query_terms.append('"process"')
    path_match = _SEMANTIC_PATH_HINT.search(raw_query)
    if path_match:
        query_terms.append(f'"{path_match.group(1)}"')
    if "last hour" not in lowered and "hour" in lowered and start is None:
        start = now - timedelta(hours=1)

    final_query = " AND ".join(query_terms) if query_terms else raw_query
    return {
        "enabled": bool(query_terms or start or agent_id),
        "query": final_query,
        "agent_id": agent_id,
        "start": start.isoformat() if start else None,
        "interpretation": {
            "raw_query": raw_query,
            "parsed_terms": query_terms,
            "agent_id": agent_id,
            "time_window": "semantic" if start else None,
        },
    }


def predict_alert_storm(series: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    counts = [_safe_int(item.get("count"), 0) for item in series or [] if isinstance(item, Mapping)]
    if len(counts) < 3:
        return {
            "storm_predicted": False,
            "recommend_suppression": False,
            "reason": "Insufficient hourly history",
        }

    recent = counts[-3:]
    growth = recent[2] / max(1, recent[1])
    accelerating = recent[1] > recent[0] and recent[2] > recent[1]
    baseline = sum(counts[:-1]) / max(1, len(counts) - 1)
    storm_predicted = accelerating and growth >= 1.35 and recent[2] > baseline * 1.4
    return {
        "storm_predicted": storm_predicted,
        "recommend_suppression": storm_predicted,
        "recommended_scope": "tenant",
        "recommended_rule_level": 3 if storm_predicted else None,
        "reason": (
            "Hourly alert volume is accelerating quickly; temporarily suppress level 3 noise to preserve storage bandwidth."
            if storm_predicted
            else "Hourly alert volume is within expected bounds."
        ),
        "latest_count": recent[2],
        "baseline_count": round(baseline, 2),
        "growth_ratio": round(growth, 3),
    }


def summarize_baseline_ghosting(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    noisy_rules: list[dict[str, Any]] = []
    ghosted_estimate = 0
    for row in rows or []:
        rule = _as_text((row or {}).get("rule"))
        count = _safe_int((row or {}).get("count"), 0)
        rule_l = rule.lower()
        if count < 100:
            continue
        if "process" not in rule_l and "created" not in rule_l:
            continue
        ghosted_estimate += count
        noisy_rules.append({"rule": rule, "count": count})
    noisy_rules.sort(key=lambda item: (-_safe_int(item.get("count"), 0), _as_text(item.get("rule"))))
    return {
        "ghosted_alert_estimate": ghosted_estimate,
        "ghosted_rules": noisy_rules[:5],
        "structural_focus": "Highlight path, parent, and command-line anomalies instead of repetitive baseline process creation noise.",
    }
