from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from core.wazuh_client import WazuhClient
from core.indexer_client import IndexerClient
from core.security import current_user

router = APIRouter()
client = WazuhClient()
indexer = IndexerClient()

def _extract_items(data):
    if isinstance(data, dict):
        return (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
    if isinstance(data, list):
        return data
    return []


def _normalize_agent_id(agent_id: str) -> str:
    raw = str(agent_id).strip()
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _normalize_agent_payload(agent):
    if not isinstance(agent, dict):
        return agent
    normalized = dict(agent)
    keepalive = (
        normalized.get("last_keepalive")
        or normalized.get("lastKeepAlive")
        or normalized.get("last_keep_alive")
        or normalized.get("last_seen")
        or normalized.get("lastSeen")
        or normalized.get("status_time")
    )
    if keepalive:
        normalized["last_keepalive"] = keepalive
    if normalized.get("id") and not normalized.get("agent_id"):
        normalized["agent_id"] = normalized.get("id")
    if normalized.get("agent_id") and not normalized.get("id"):
        normalized["id"] = normalized.get("agent_id")
    return normalized


def _agent_status_value(agent: dict) -> str:
    status = ""
    if isinstance(agent, dict):
        status = str(agent.get("status") or "").strip().lower()
        if not status and isinstance(agent.get("agent"), dict):
            status = str(agent.get("agent", {}).get("status") or "").strip().lower()
    return status


def _agent_platform_value(agent: dict) -> str:
    if not isinstance(agent, dict):
        return ""
    os_node = agent.get("os")
    if isinstance(os_node, dict):
        name = str(os_node.get("name") or os_node.get("platform") or os_node.get("full") or "")
    else:
        name = str(agent.get("os_name") or agent.get("os") or "")
    lowered = name.strip().lower()
    if "windows" in lowered:
        return "windows"
    if any(token in lowered for token in ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "suse", "alpine")):
        return "linux"
    return "unknown"


def _compact_agent_payload(agent: dict) -> dict:
    normalized = _normalize_agent_payload(agent)
    groups = normalized.get("groups")
    if not groups:
        group_value = normalized.get("group") or normalized.get("group_name")
        if isinstance(group_value, list):
            groups = group_value
        elif isinstance(group_value, str) and group_value.strip():
            groups = [group_value]
        else:
            groups = []
    elif isinstance(groups, str):
        groups = [groups]
    elif not isinstance(groups, list):
        groups = []

    return {
        "id": normalized.get("id") or normalized.get("agent_id") or "",
        "agent_id": normalized.get("agent_id") or normalized.get("id") or "",
        "name": normalized.get("name") or normalized.get("hostname") or "",
        "hostname": normalized.get("hostname") or normalized.get("name") or "",
        "ip": normalized.get("ip") or normalized.get("registerIP") or normalized.get("ip_address") or "",
        "status": normalized.get("status") or "",
        "platform": _agent_platform_value(normalized),
        "group": normalized.get("group") or normalized.get("group_name") or "",
        "groups": [str(g) for g in groups if str(g).strip()],
        "last_keepalive": normalized.get("last_keepalive") or "",
    }


SCA_CATEGORY_KEYWORDS = {
    "identity": (
        "password",
        "credential",
        "account",
        "authentication",
        "login",
        "logon",
        "mfa",
        "lockout",
        "kerberos",
        "ntlm",
        "anonymous",
        "guest",
    ),
    "patching": (
        "update",
        "patch",
        "hotfix",
        "vulnerability",
        "cve",
        "outdated",
        "upgrade",
    ),
    "network": (
        "firewall",
        "port",
        "rdp",
        "remote desktop",
        "winrm",
        "smb",
        "ssh",
        "tls",
        "ssl",
        "network",
    ),
    "malware": (
        "defender",
        "antivirus",
        "malware",
        "asr",
        "realtime",
        "real-time",
        "signature",
        "tamper",
        "exploit guard",
    ),
    "logging": (
        "audit",
        "event log",
        "logging",
        "monitor",
        "retention",
        "sysmon",
        "powershell logging",
    ),
    "privilege": (
        "privilege",
        "uac",
        "administrator",
        "admin",
        "elevation",
        "rights assignment",
        "sudo",
        "secedit",
    ),
    "hardening": (
        "disable",
        "harden",
        "autorun",
        "autoplay",
        "macro",
        "script",
        "powershell",
        "service",
        "registry",
    ),
    "encryption": (
        "bitlocker",
        "encrypt",
        "cipher",
        "secure boot",
        "credential guard",
        "tls",
        "ssl",
    ),
}


def _to_int(value: Any, fallback: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return fallback
    try:
        text = str(value).strip()
        if not text:
            return fallback
        return int(float(text))
    except Exception:
        return fallback


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return " ".join(_stringify(item) for item in value if _stringify(item).strip())
    if isinstance(value, dict):
        chunks = []
        for key, val in value.items():
            key_txt = str(key).strip()
            val_txt = _stringify(val).strip()
            if key_txt and val_txt:
                chunks.append(f"{key_txt} {val_txt}")
            elif val_txt:
                chunks.append(val_txt)
        return " ".join(chunks)
    return str(value)


def _parse_timestamp_rank(value: Any) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _normalize_sca_result(value: Any) -> str:
    token = str(value or "").strip().lower().replace("_", " ")
    if token in {"pass", "passed", "ok", "success"}:
        return "passed"
    if token in {"fail", "failed", "error"}:
        return "failed"
    if token in {"not applicable", "n/a", "na", "invalid"}:
        return "not applicable"
    if not token:
        return "unknown"
    return token


def _severity_bucket(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "unknown"
    token = str(value).strip().lower()
    if token.startswith("crit"):
        return "critical"
    if token.startswith("high"):
        return "high"
    if token.startswith("med"):
        return "medium"
    if token.startswith("low"):
        return "low"
    try:
        return _severity_bucket(float(token))
    except Exception:
        return "unknown"


def _normalize_sca_references(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if value is None:
        return []
    text = str(value).strip()
    return [text] if text else []


def _normalize_sca_policy_row(row: dict, idx: int) -> dict:
    policy_node = _as_dict(row.get("policy"))
    policy_id = str(
        row.get("policy_id")
        or policy_node.get("id")
        or row.get("id")
        or ""
    ).strip()
    policy_name = str(
        row.get("name")
        or policy_node.get("name")
        or row.get("policy_name")
        or policy_id
        or f"Policy {idx + 1}"
    ).strip()
    passed = _to_int(
        row.get("pass")
        or row.get("passed")
        or _as_dict(row.get("summary")).get("passed")
        or row.get("checks_passed"),
        0,
    )
    failed = _to_int(
        row.get("fail")
        or row.get("failed")
        or _as_dict(row.get("summary")).get("failed")
        or row.get("checks_failed"),
        0,
    )
    not_applicable = _to_int(
        row.get("invalid")
        or row.get("not_applicable")
        or _as_dict(row.get("summary")).get("invalid")
        or row.get("checks_not_applicable"),
        0,
    )
    total_checks = _to_int(row.get("total_checks"), 0)
    if total_checks <= 0:
        total_checks = max(passed + failed + not_applicable, 0)
    score = _to_int(
        row.get("score")
        or _as_dict(row.get("summary")).get("score")
        or row.get("compliance_score"),
        0,
    )
    if score <= 0 and total_checks > 0:
        score = int(round((passed / max(total_checks, 1)) * 100))
    end_scan = (
        row.get("end_scan")
        or _as_dict(row.get("scan")).get("end_scan")
        or row.get("scan_time")
        or row.get("@timestamp")
    )
    start_scan = row.get("start_scan") or _as_dict(row.get("scan")).get("start_scan")
    return {
        "id": policy_id or f"policy-{idx + 1}",
        "policy_id": policy_id,
        "policy_name": policy_name or f"Policy {idx + 1}",
        "description": row.get("description") or policy_node.get("description") or "",
        "references": _normalize_sca_references(row.get("references") or policy_node.get("references")),
        "hash_file": row.get("hash_file") or "",
        "start_scan": start_scan or "",
        "end_scan": end_scan or "",
        "passed": max(passed, 0),
        "failed": max(failed, 0),
        "not_applicable": max(not_applicable, 0),
        "total_checks": max(total_checks, 0),
        "score": max(score, 0),
        "checks": [],
        "checks_summary": {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0},
        "raw": row,
    }


def _latest_unique_sca_policies(rows: list[dict]) -> list[dict]:
    latest: dict[str, dict] = {}
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        normalized = _normalize_sca_policy_row(row, idx)
        identity = (normalized.get("policy_id") or normalized.get("policy_name") or normalized.get("id") or "").strip()
        if not identity:
            identity = f"policy-{idx + 1}"
        existing = latest.get(identity)
        if not existing:
            latest[identity] = normalized
            continue
        if _parse_timestamp_rank(normalized.get("end_scan")) >= _parse_timestamp_rank(existing.get("end_scan")):
            latest[identity] = normalized
    return sorted(
        latest.values(),
        key=lambda item: _parse_timestamp_rank(item.get("end_scan")),
        reverse=True,
    )


def _normalize_sca_check_row(row: dict, policy: dict, idx: int) -> dict:
    check_id = row.get("id") or row.get("check_id") or f"{policy.get('policy_id') or policy.get('policy_name')}-{idx + 1}"
    check_id_text = str(check_id).strip() or str(idx + 1)
    references = _normalize_sca_references(row.get("references"))
    rules = row.get("rules")
    if isinstance(rules, list):
        rules_out = [item for item in rules if item is not None and str(item).strip()]
    elif rules is None or str(rules).strip() == "":
        rules_out = []
    else:
        rules_out = [rules]
    compliance = row.get("compliance")
    if not isinstance(compliance, (dict, list)):
        compliance = _normalize_sca_references(compliance)
    result = _normalize_sca_result(row.get("result") or row.get("status"))
    return {
        "id": check_id_text,
        "policy_id": str(row.get("policy_id") or policy.get("policy_id") or "").strip(),
        "policy_name": policy.get("policy_name") or "",
        "title": str(row.get("title") or row.get("name") or f"Check {check_id_text}").strip(),
        "description": str(row.get("description") or "").strip(),
        "rationale": str(row.get("rationale") or "").strip(),
        "remediation": str(row.get("remediation") or "").strip(),
        "reason": str(row.get("reason") or "").strip(),
        "condition": str(row.get("condition") or "").strip(),
        "command": row.get("command") if row.get("command") is not None else "",
        "rules": rules_out,
        "references": references,
        "compliance": compliance,
        "result": result,
        "raw_result": row.get("result") or row.get("status") or "",
        "raw": row,
    }


def _summarize_checks(checks: list[dict]) -> dict:
    result_counts: Counter[str] = Counter()
    for check in checks:
        result_counts[_normalize_sca_result(check.get("result"))] += 1
    passed = int(result_counts.get("passed", 0))
    failed = int(result_counts.get("failed", 0))
    not_applicable = int(result_counts.get("not applicable", 0))
    unknown = sum(v for key, v in result_counts.items() if key not in {"passed", "failed", "not applicable"})
    total = passed + failed + not_applicable + unknown
    return {
        "passed": passed,
        "failed": failed,
        "not_applicable": not_applicable,
        "unknown": unknown,
        "total": total,
    }


def _extract_alert_level(alert: dict) -> int:
    rule = _as_dict(alert.get("rule"))
    return _to_int(rule.get("level") or rule.get("severity") or alert.get("level"), 0)


def _extract_vulnerability_severity(vuln: dict) -> Any:
    vuln_node = _as_dict(vuln.get("vulnerability"))
    score_node = _as_dict(vuln_node.get("score"))
    cvss_node = _as_dict(vuln_node.get("cvss"))
    root_cvss = _as_dict(vuln.get("cvss"))
    return (
        vuln_node.get("severity")
        or score_node.get("severity")
        or score_node.get("base")
        or score_node.get("base_score")
        or cvss_node.get("severity")
        or vuln.get("severity")
        or root_cvss.get("score")
    )


def _collect_hardening_context(agent_id: str) -> dict:
    alert_limit = 200
    vulnerability_limit = 500
    fim_limit = 200
    mitre_hours = 72

    alerts: list[dict] = []
    if indexer.enabled:
        try:
            alerts_data = indexer.search_alerts(limit=alert_limit, agent_id=agent_id, agent_only=True)
            alerts = indexer.extract_alerts(alerts_data)
        except HTTPException:
            alerts = []

    vulnerabilities: list[dict] = []
    if indexer.enabled:
        try:
            vuln_data = indexer.search_vulnerabilities(agent_id=agent_id, limit=vulnerability_limit)
            vulnerabilities = indexer.extract_vulnerabilities(vuln_data)
        except HTTPException:
            vulnerabilities = []
    if not vulnerabilities:
        try:
            vulnerabilities = _extract_items(client.get_agent_vulnerabilities(agent_id, limit=vulnerability_limit))
        except HTTPException:
            vulnerabilities = []

    fim_events: list[dict] = []
    if indexer.enabled:
        try:
            fim_data = indexer.search_fim_events(agent_id=agent_id, limit=fim_limit)
            fim_events = indexer.extract_alerts(fim_data)
        except HTTPException:
            fim_events = []

    mitre_tactics: list[str] = []
    if indexer.enabled:
        try:
            mitre_data = indexer.search_mitre(agent_id=agent_id, hours=mitre_hours)
            buckets = _as_dict(_as_dict(mitre_data.get("aggregations")).get("tactics")).get("buckets") or []
            if isinstance(buckets, list):
                mitre_tactics = [str(row.get("key") or "").strip() for row in buckets if isinstance(row, dict) and str(row.get("key") or "").strip()]
        except HTTPException:
            mitre_tactics = []

    high_alerts = 0
    critical_alerts = 0
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        level = _extract_alert_level(alert)
        if level >= 10:
            high_alerts += 1
        if level >= 12:
            critical_alerts += 1

    severity_counter: Counter[str] = Counter()
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        severity_counter[_severity_bucket(_extract_vulnerability_severity(vuln))] += 1

    return {
        "alerts_total": len(alerts),
        "alerts_high": high_alerts,
        "alerts_critical": critical_alerts,
        "vulnerabilities_total": len(vulnerabilities),
        "vulnerabilities_critical": int(severity_counter.get("critical", 0)),
        "vulnerabilities_high": int(severity_counter.get("high", 0)),
        "vulnerabilities_medium": int(severity_counter.get("medium", 0)),
        "vulnerabilities_low": int(severity_counter.get("low", 0)),
        "fim_events": len(fim_events),
        "mitre_tactics": mitre_tactics[:10],
    }


def _build_category_boosts(context: dict) -> dict[str, float]:
    boosts = {category: 0.0 for category in SCA_CATEGORY_KEYWORDS}

    if _to_int(context.get("vulnerabilities_critical"), 0) > 0:
        boosts["patching"] += 6.0
        boosts["network"] += 2.0
    if _to_int(context.get("vulnerabilities_high"), 0) >= 10:
        boosts["patching"] += 3.0
    if _to_int(context.get("alerts_high"), 0) > 0:
        boosts["logging"] += 2.0
        boosts["hardening"] += 2.0
    if _to_int(context.get("alerts_critical"), 0) > 0:
        boosts["malware"] += 4.0
        boosts["privilege"] += 3.0
        boosts["network"] += 2.0
    if _to_int(context.get("fim_events"), 0) >= 20:
        boosts["hardening"] += 3.0
        boosts["logging"] += 2.0

    for tactic in context.get("mitre_tactics") or []:
        text = str(tactic).strip().lower()
        if not text:
            continue
        if "credential access" in text:
            boosts["identity"] += 5.0
        if "privilege escalation" in text:
            boosts["privilege"] += 5.0
        if "defense evasion" in text:
            boosts["logging"] += 3.0
            boosts["malware"] += 2.0
        if "lateral movement" in text:
            boosts["network"] += 4.0
        if "persistence" in text:
            boosts["hardening"] += 3.0
        if "initial access" in text:
            boosts["network"] += 2.0
            boosts["identity"] += 2.0

    return boosts


def _priority_from_score(score: float) -> str:
    if score >= 12.0:
        return "critical"
    if score >= 8.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _check_text_blob(check: dict) -> str:
    pieces = [
        check.get("title"),
        check.get("description"),
        check.get("rationale"),
        check.get("remediation"),
        check.get("reason"),
        check.get("condition"),
        check.get("command"),
        check.get("rules"),
        check.get("references"),
        check.get("compliance"),
    ]
    return _stringify(pieces).lower()


def _recommend_failed_checks(policies: list[dict], context: dict, limit: int) -> list[dict]:
    boosts = _build_category_boosts(context)
    rows: list[dict] = []
    for policy in policies:
        checks = policy.get("checks")
        if not isinstance(checks, list):
            continue
        for check in checks:
            if not isinstance(check, dict):
                continue
            if _normalize_sca_result(check.get("result")) != "failed":
                continue

            text = _check_text_blob(check)
            matched_categories: list[str] = []
            score = 1.0
            for category, keywords in SCA_CATEGORY_KEYWORDS.items():
                hits = [kw for kw in keywords if kw in text]
                if not hits:
                    continue
                matched_categories.append(category)
                score += min(2.0, len(hits) * 0.5)
                score += boosts.get(category, 0.0)

            reasons: list[str] = []
            if matched_categories:
                reasons.append(f"Control area match: {', '.join(matched_categories[:3])}")
            if "patching" in matched_categories and _to_int(context.get("vulnerabilities_critical"), 0) > 0:
                reasons.append(
                    f"{_to_int(context.get('vulnerabilities_critical'), 0)} critical vulnerabilities detected on this agent."
                )
            if _to_int(context.get("alerts_high"), 0) > 0 and (
                "logging" in matched_categories
                or "hardening" in matched_categories
                or "malware" in matched_categories
                or "network" in matched_categories
            ):
                reasons.append(f"{_to_int(context.get('alerts_high'), 0)} high-severity alerts in recent history.")
            if _to_int(context.get("fim_events"), 0) >= 20 and (
                "hardening" in matched_categories or "logging" in matched_categories
            ):
                reasons.append(f"{_to_int(context.get('fim_events'), 0)} recent FIM changes observed.")
            if context.get("mitre_tactics"):
                reasons.append(f"Recent MITRE tactics: {', '.join((context.get('mitre_tactics') or [])[:2])}.")
            if not reasons:
                reasons.append("Failed check with hardening impact.")

            rows.append(
                {
                    "policy_id": policy.get("policy_id"),
                    "policy_name": policy.get("policy_name"),
                    "check_id": check.get("id"),
                    "title": check.get("title") or f"Check {check.get('id')}",
                    "priority_score": round(score, 2),
                    "priority": _priority_from_score(score),
                    "matched_categories": matched_categories,
                    "reason": " ".join(reasons[:3]),
                    "remediation": check.get("remediation") or "",
                    "description": check.get("description") or "",
                    "result": "failed",
                }
            )

    rows.sort(
        key=lambda item: (
            -float(item.get("priority_score") or 0.0),
            str(item.get("policy_name") or "").lower(),
            str(item.get("check_id") or ""),
        )
    )
    top_rows = rows[: max(1, limit)]
    for idx, row in enumerate(top_rows, start=1):
        row["rank"] = idx
    return top_rows


def _parse_csv_tokens(value: str | None, lowercase: bool = False) -> list[str]:
    if value is None:
        return []
    out: list[str] = []
    for part in str(value).split(","):
        token = part.strip()
        if not token:
            continue
        out.append(token.lower() if lowercase else token)
    return out


def _build_agent_sca_payload(
    agent_id: str,
    *,
    limit: int,
    include_checks: bool,
    checks_limit: int,
    recommendation_limit: int,
) -> dict:
    norm_agent = _normalize_agent_id(agent_id)
    items: list[dict] = []
    source = "indexer"
    error = None

    if indexer.enabled:
        try:
            data = indexer.search_sca(agent_id=norm_agent, limit=limit)
            items = indexer.extract_sca(data)
        except HTTPException as exc:
            error = str(exc.detail) if getattr(exc, "detail", None) else "Wazuh indexer unavailable"
            items = []

    if not items:
        try:
            data = client.get_agent_sca(norm_agent, limit=limit)
            items = _extract_items(data)
            source = "api"
            error = None
        except HTTPException:
            if error is None:
                error = "Wazuh manager unavailable"
            items = []

    if not isinstance(items, list):
        items = []

    policies = _latest_unique_sca_policies([row for row in items if isinstance(row, dict)])
    checks_summary = {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0}
    recommendations: list[dict] = []
    context = {}

    if include_checks and policies:
        for policy in policies:
            policy_id = str(policy.get("policy_id") or "").strip()
            checks: list[dict] = []
            policy_error = ""
            if policy_id:
                try:
                    check_data = client.get_agent_sca_checks(norm_agent, policy_id, limit=checks_limit)
                    raw_checks = _extract_items(check_data)
                    if isinstance(raw_checks, list):
                        checks = [
                            _normalize_sca_check_row(row, policy, idx)
                            for idx, row in enumerate(raw_checks)
                            if isinstance(row, dict)
                        ]
                except HTTPException as exc:
                    policy_error = str(exc.detail) if getattr(exc, "detail", None) else "Wazuh manager unavailable"
            else:
                policy_error = "Missing policy_id in SCA summary payload."

            check_rollup = _summarize_checks(checks)
            policy["checks"] = checks
            policy["checks_summary"] = check_rollup
            if policy_error:
                policy["checks_error"] = policy_error

            if check_rollup["total"] > 0:
                policy["passed"] = check_rollup["passed"]
                policy["failed"] = check_rollup["failed"]
                policy["not_applicable"] = check_rollup["not_applicable"]
                policy["total_checks"] = check_rollup["total"]
                policy["score"] = int(round((policy["passed"] / max(policy["total_checks"], 1)) * 100))

            checks_summary["passed"] += check_rollup["passed"]
            checks_summary["failed"] += check_rollup["failed"]
            checks_summary["not_applicable"] += check_rollup["not_applicable"]
            checks_summary["unknown"] += check_rollup["unknown"]
            checks_summary["total"] += check_rollup["total"]

        context = _collect_hardening_context(norm_agent)
        recommendations = _recommend_failed_checks(
            policies,
            context=context,
            limit=recommendation_limit,
        )
    else:
        for policy in policies:
            checks_summary["passed"] += _to_int(policy.get("passed"), 0)
            checks_summary["failed"] += _to_int(policy.get("failed"), 0)
            checks_summary["not_applicable"] += _to_int(policy.get("not_applicable"), 0)
            checks_summary["total"] += _to_int(policy.get("total_checks"), 0)

    return {
        "agent_id": norm_agent,
        "items": items,
        "source": source,
        "error": error,
        "policies": policies,
        "policy_count": len(policies),
        "checks_summary": checks_summary,
        "recommendations": recommendations,
        "telemetry_context": context,
    }


@router.get("")
def list_agents(
    group: str | None = None,
    compact: bool = Query(default=True),
    status: str | None = Query(default=None, description="Comma-separated status filter"),
    platform: str | None = Query(default=None, description="windows|linux"),
    limit: int = Query(default=2000, ge=1, le=100000),
    user=Depends(current_user),
):
    try:
        data = client.get_agents(group=group)
    except HTTPException:
        return []
    items = _extract_items(data)
    if isinstance(items, list):
        normalized_items = [_normalize_agent_payload(item) for item in items]

        if status:
            allowed = {s.strip().lower() for s in str(status).split(",") if s.strip()}
            if allowed:
                normalized_items = [item for item in normalized_items if _agent_status_value(item) in allowed]

        if platform:
            allowed_platform = {s.strip().lower() for s in str(platform).split(",") if s.strip()}
            if allowed_platform:
                normalized_items = [
                    item for item in normalized_items if _agent_platform_value(item) in allowed_platform
                ]

        if compact:
            normalized_items = [_compact_agent_payload(item) for item in normalized_items]

        return normalized_items[:limit]
    return []


@router.get("/groups")
def list_groups(user=Depends(current_user)):
    try:
        data = client.get_groups()
    except HTTPException:
        data = []

    if isinstance(data, dict):
        groups = (
            data.get("data", {}).get("affected_items")
            or data.get("affected_items")
            or data.get("items")
            or []
        )
        if isinstance(groups, list):
            return groups
        return []

    if isinstance(data, list):
        return data

    return []


@router.get("/sca/fleet")
def get_fleet_sca_hardening(
    group: str | None = Query(default=None),
    agent_ids: str | None = Query(default=None, description="Comma-separated agent IDs."),
    status: str | None = Query(default="active", description="Comma-separated status filter."),
    platform: str | None = Query(default=None, description="Comma-separated platform filter: windows|linux."),
    limit_agents: int = Query(default=200, ge=1, le=2000),
    sca_limit: int = Query(default=200, ge=1, le=1000),
    checks_limit: int = Query(default=10000, ge=1, le=20000),
    recommendation_limit: int = Query(default=25, ge=1, le=250),
    fleet_recommendation_limit: int = Query(default=500, ge=1, le=5000),
    include_checks: bool = Query(default=False, description="Include full policy/check documents per agent."),
    parallelism: int = Query(default=6, ge=1, le=32),
    user=Depends(current_user),
):
    requested_agent_ids = [_normalize_agent_id(token) for token in _parse_csv_tokens(agent_ids)]
    requested_agent_set = set(requested_agent_ids)
    allowed_status = set(_parse_csv_tokens(status, lowercase=True))
    allowed_platform = set(_parse_csv_tokens(platform, lowercase=True))

    try:
        data = client.get_agents(group=group)
        source_agents = _extract_items(data)
    except HTTPException:
        source_agents = []

    selected_by_id: dict[str, dict] = {}
    for row in source_agents:
        if not isinstance(row, dict):
            continue
        normalized = _normalize_agent_payload(row)
        aid = _normalize_agent_id(normalized.get("id") or normalized.get("agent_id") or "")
        if not aid or aid in {"000", "0"}:
            continue
        if requested_agent_set and aid not in requested_agent_set:
            continue
        if allowed_status and _agent_status_value(normalized) not in allowed_status:
            continue
        if allowed_platform and _agent_platform_value(normalized) not in allowed_platform:
            continue
        selected_by_id[aid] = normalized

    # If specific agent IDs were requested but not returned by list API,
    # attempt direct lookups to keep fleet mode robust for partial visibility setups.
    if requested_agent_set:
        for aid in requested_agent_ids:
            if aid in selected_by_id:
                continue
            try:
                agent_data = client.get_agent(aid)
                items = _extract_items(agent_data)
                row = items[0] if isinstance(items, list) and items else agent_data
                if not isinstance(row, dict):
                    continue
                normalized = _normalize_agent_payload(row)
                if allowed_status and _agent_status_value(normalized) not in allowed_status:
                    continue
                if allowed_platform and _agent_platform_value(normalized) not in allowed_platform:
                    continue
                selected_by_id[aid] = normalized
            except HTTPException:
                continue

    selected_rows = sorted(
        selected_by_id.values(),
        key=lambda item: str(item.get("id") or item.get("agent_id") or ""),
    )
    total_candidates = len(selected_rows)
    selected_rows = selected_rows[:limit_agents]
    selected_ids = [
        _normalize_agent_id(row.get("id") or row.get("agent_id") or "")
        for row in selected_rows
        if _normalize_agent_id(row.get("id") or row.get("agent_id") or "")
    ]

    agent_meta: dict[str, dict] = {}
    for row in selected_rows:
        compact = _compact_agent_payload(row)
        aid = _normalize_agent_id(compact.get("id") or compact.get("agent_id") or "")
        if not aid:
            continue
        compact["id"] = aid
        compact["agent_id"] = aid
        agent_meta[aid] = compact

    results_by_id: dict[str, dict] = {}
    if selected_ids:
        workers = min(max(1, parallelism), len(selected_ids))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _build_agent_sca_payload,
                    aid,
                    limit=sca_limit,
                    include_checks=True,
                    checks_limit=checks_limit,
                    recommendation_limit=recommendation_limit,
                ): aid
                for aid in selected_ids
            }
            for future in as_completed(futures):
                aid = futures[future]
                try:
                    results_by_id[aid] = future.result()
                except Exception as exc:
                    results_by_id[aid] = {
                        "agent_id": aid,
                        "items": [],
                        "source": "",
                        "error": str(exc) or "Failed to evaluate agent SCA.",
                        "policies": [],
                        "policy_count": 0,
                        "checks_summary": {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0},
                        "recommendations": [],
                        "telemetry_context": {},
                    }

    fleet_rows: list[dict] = []
    fleet_recommendations: list[dict] = []
    for aid in selected_ids:
        meta = agent_meta.get(aid) or {"id": aid, "agent_id": aid, "name": aid, "status": "", "platform": "", "group": "", "groups": []}
        payload = results_by_id.get(aid) or {
            "source": "",
            "error": "Agent evaluation was not returned.",
            "policy_count": 0,
            "checks_summary": {"passed": 0, "failed": 0, "not_applicable": 0, "unknown": 0, "total": 0},
            "recommendations": [],
            "telemetry_context": {},
            "policies": [],
        }

        checks_summary = payload.get("checks_summary") if isinstance(payload.get("checks_summary"), dict) else {}
        recs = payload.get("recommendations") if isinstance(payload.get("recommendations"), list) else []
        row = {
            "agent_id": aid,
            "agent_name": meta.get("name") or meta.get("hostname") or aid,
            "status": meta.get("status") or "",
            "platform": meta.get("platform") or "",
            "group": meta.get("group") or "",
            "groups": meta.get("groups") if isinstance(meta.get("groups"), list) else [],
            "source": payload.get("source") or "",
            "error": payload.get("error") or "",
            "policy_count": _to_int(payload.get("policy_count"), 0),
            "checks_summary": {
                "passed": _to_int(checks_summary.get("passed"), 0),
                "failed": _to_int(checks_summary.get("failed"), 0),
                "not_applicable": _to_int(checks_summary.get("not_applicable"), 0),
                "unknown": _to_int(checks_summary.get("unknown"), 0),
                "total": _to_int(checks_summary.get("total"), 0),
            },
            "telemetry_context": payload.get("telemetry_context") if isinstance(payload.get("telemetry_context"), dict) else {},
            "recommendations": recs,
        }
        if include_checks:
            row["policies"] = payload.get("policies") if isinstance(payload.get("policies"), list) else []
        fleet_rows.append(row)

        for rec in recs:
            if not isinstance(rec, dict):
                continue
            merged = dict(rec)
            merged["agent_id"] = aid
            merged["agent_name"] = row["agent_name"]
            merged["status"] = row["status"]
            merged["platform"] = row["platform"]
            merged["group"] = row["group"]
            fleet_recommendations.append(merged)

    fleet_recommendations.sort(
        key=lambda item: (
            -float(item.get("priority_score") or 0.0),
            str(item.get("priority") or ""),
            str(item.get("agent_id") or ""),
            str(item.get("check_id") or ""),
        )
    )
    fleet_recommendations = fleet_recommendations[:fleet_recommendation_limit]
    for idx, row in enumerate(fleet_recommendations, start=1):
        row["fleet_rank"] = idx

    return {
        "summary": {
            "agents_candidates": total_candidates,
            "agents_evaluated": len(fleet_rows),
            "agents_with_errors": sum(1 for row in fleet_rows if str(row.get("error") or "").strip()),
            "agents_with_recommendations": sum(1 for row in fleet_rows if row.get("recommendations")),
            "total_policies": sum(_to_int(row.get("policy_count"), 0) for row in fleet_rows),
            "total_failed_checks": sum(_to_int(_as_dict(row.get("checks_summary")).get("failed"), 0) for row in fleet_rows),
            "fleet_recommendations": len(fleet_recommendations),
            "truncated_agents": max(total_candidates - len(fleet_rows), 0),
        },
        "filters": {
            "group": group or "",
            "agent_ids": requested_agent_ids,
            "status": sorted(allowed_status),
            "platform": sorted(allowed_platform),
            "limit_agents": limit_agents,
            "sca_limit": sca_limit,
            "checks_limit": checks_limit,
            "recommendation_limit": recommendation_limit,
            "fleet_recommendation_limit": fleet_recommendation_limit,
        },
        "agents": fleet_rows,
        "fleet_recommendations": fleet_recommendations,
    }


@router.get("/{agent_id}")
def get_agent(agent_id: str, user=Depends(current_user)):
    norm = _normalize_agent_id(agent_id)
    try:
        data = client.get_agent(norm)
    except HTTPException:
        data = {}

    items = _extract_items(data)
    if isinstance(items, list) and items:
        return _normalize_agent_payload(items[0])
    if isinstance(data, dict):
        if data.get("id") or data.get("agent_id"):
            return _normalize_agent_payload(data)
    try:
        agents = _extract_items(client.get_agents())
    except HTTPException:
        agents = []

    for item in agents:
        if not isinstance(item, dict):
            continue
        candidate = item.get("id") or item.get("agent_id")
        if candidate and _normalize_agent_id(candidate) == norm:
            return _normalize_agent_payload(item)

    if isinstance(data, dict):
        return _normalize_agent_payload(data)
    return {}


@router.get("/{agent_id}/vulnerabilities")
def get_agent_vulnerabilities(agent_id: str, limit: int = Query(default=200, ge=1, le=2000), user=Depends(current_user)):
    def _looks_like_vuln(rows):
        if not isinstance(rows, list):
            return False
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("cve") or row.get("vulnerability") or row.get("package"):
                return True
        return False

    items = []
    source = "api"
    error = None

    if indexer.enabled:
        try:
            data = indexer.search_vulnerabilities(agent_id=agent_id, limit=limit)
            items = indexer.extract_vulnerabilities(data)
            source = "indexer"
        except HTTPException as exc:
            error = str(exc.detail) if getattr(exc, "detail", None) else "Wazuh indexer unavailable"
            items = []

    if not items:
        try:
            data = client.get_agent_vulnerabilities(agent_id, limit=limit)
            items = _extract_items(data)
            if not _looks_like_vuln(items) and indexer.enabled:
                try:
                    data = indexer.search_vulnerabilities(agent_id=agent_id, limit=limit)
                    items = indexer.extract_vulnerabilities(data)
                    source = "indexer"
                    error = None
                except HTTPException:
                    pass
        except HTTPException:
            items = []

    if not isinstance(items, list):
        items = []
    return {"items": items, "total": len(items), "source": source, "error": error}


@router.get("/{agent_id}/inventory")
def get_agent_inventory(agent_id: str, limit: int = Query(default=100, ge=1, le=1000), user=Depends(current_user)):
    inventory = {}
    sources = {}
    for resource in ("hardware", "os", "packages"):
        try:
            data = client.get_syscollector(agent_id, resource, limit=limit)
            inventory[resource] = _extract_items(data)
            sources[resource] = "api"
        except HTTPException:
            inventory[resource] = []
            sources[resource] = "api"

        if not inventory[resource] and indexer.enabled:
            try:
                data = indexer.search_syscollector(agent_id=agent_id, resource=resource, limit=limit)
                items = indexer.extract_syscollector(data)
                inventory[resource] = indexer.filter_syscollector(items, resource)
                sources[resource] = "indexer"
            except HTTPException:
                pass

    inventory["source"] = sources
    return inventory


@router.get("/{agent_id}/events")
def get_agent_events(agent_id: str, hours: int = Query(default=24, ge=1, le=168), user=Depends(current_user)):
    try:
        data = indexer.search_alert_histogram(agent_id=agent_id, hours=hours)
    except HTTPException:
        return {"items": []}

    buckets = data.get("aggregations", {}).get("timeline", {}).get("buckets", [])
    items = [{"ts": b.get("key_as_string"), "count": b.get("doc_count", 0)} for b in buckets]
    return {"items": items}


@router.get("/{agent_id}/fim")
def get_agent_fim(agent_id: str, limit: int = Query(default=50, ge=1, le=200), user=Depends(current_user)):
    try:
        data = indexer.search_fim_events(agent_id=agent_id, limit=limit)
        items = indexer.extract_alerts(data)
    except HTTPException:
        items = []

    return {"items": items}


@router.get("/{agent_id}/mitre")
def get_agent_mitre(agent_id: str, hours: int = Query(default=24, ge=1, le=168), user=Depends(current_user)):
    try:
        data = indexer.search_mitre(agent_id=agent_id, hours=hours)
    except HTTPException:
        return {"tactics": [], "techniques": []}

    aggs = data.get("aggregations", {})
    tactics = aggs.get("tactics", {}).get("buckets", [])
    techniques = aggs.get("techniques", {}).get("buckets", [])
    return {"tactics": tactics, "techniques": techniques}


@router.get("/{agent_id}/sca")
def get_agent_sca(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=1000),
    include_checks: bool = Query(default=False, description="Include full check details for each policy."),
    checks_limit: int = Query(default=10000, ge=1, le=20000, description="Max checks returned per policy."),
    recommendation_limit: int = Query(default=25, ge=1, le=250),
    user=Depends(current_user),
):
    payload = _build_agent_sca_payload(
        agent_id,
        limit=limit,
        include_checks=include_checks,
        checks_limit=checks_limit,
        recommendation_limit=recommendation_limit,
    )
    payload.pop("agent_id", None)
    return payload
