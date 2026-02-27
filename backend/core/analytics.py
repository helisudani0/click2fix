from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from math import sqrt
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from sqlalchemy import text

from core.actions import list_actions
from core.indexer_client import IndexerClient
from core.mitre_mapper import MitreMapper
from core.time_utils import parse_utc_datetime, row_to_json_list, utc_iso
from db.database import connect


KILL_CHAIN_MAP = {
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Persistence": "Installation",
    "Privilege Escalation": "Installation",
    "Defense Evasion": "Installation",
    "Credential Access": "Installation",
    "Discovery": "Reconnaissance",
    "Lateral Movement": "Actions on Objectives",
    "Collection": "Actions on Objectives",
    "Command and Control": "Command and Control",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}

_HIGH_IMPACT_TACTICS = {
    "credential access",
    "lateral movement",
    "command and control",
    "impact",
}

_AUTH_HINTS = {
    "failed password",
    "logon failure",
    "bad password",
    "authentication failure",
    "brute force",
    "password spray",
    "pass-the-hash",
}

_EXECUTION_HINTS = {
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mimikatz",
    "malware",
}

_GENERIC_PROCESS_EVENT_HINTS = {
    "a process was created",
    "new process has been created",
    "process creation",
}

_NETWORK_IOC_TYPES = {"ip", "domain", "url"}

_IOC_VERDICT_RANK = {
    "unknown": 0,
    "low_confidence": 1,
    "suspicious": 2,
    "malicious": 3,
}


@dataclass
class AnomalyResult:
    mean: float
    std: float
    last_hour: int
    status: str


def _hourly_counts(conn, window_hours: int = 168) -> List[int]:
    rows = conn.execute(
        text(
            """
            SELECT date_trunc('hour', event_time) as hour, COUNT(*) as cnt
            FROM alerts_store
            WHERE event_time >= NOW() - (:hours || ' hours')::interval
            GROUP BY hour
            ORDER BY hour ASC
            """
        ),
        {"hours": window_hours},
    ).fetchall()
    return [row[1] for row in rows]


def _rows_to_lists(rows) -> List[List]:
    out: List[List] = []
    for row in rows or []:
        out.append(row_to_json_list(row))
    return out

def hourly_volume(hours: int = 72) -> List[Dict[str, str | int]]:
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT date_trunc('hour', event_time) as hour, COUNT(*) as cnt
                FROM alerts_store
                WHERE event_time >= NOW() - (:hours || ' hours')::interval
                GROUP BY hour
                ORDER BY hour ASC
                """
            ),
            {"hours": hours},
        ).fetchall()
        return [{"hour": utc_iso(row[0]), "count": row[1]} for row in rows]
    finally:
        db.close()


def _compute_anomaly(conn) -> AnomalyResult:
    counts = _hourly_counts(conn)
    if not counts:
        return AnomalyResult(mean=0, std=0, last_hour=0, status="no_data")

    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    std = sqrt(variance)

    last_hour_count = conn.execute(
        text(
            """
            SELECT COUNT(*) FROM alerts_store
            WHERE event_time >= NOW() - interval '1 hour'
            """
        )
    ).scalar() or 0

    if std == 0:
        status = "normal"
    elif last_hour_count > mean + 3 * std:
        status = "spike"
    elif last_hour_count < max(mean - 3 * std, 0):
        status = "drop"
    else:
        status = "normal"

    return AnomalyResult(mean=mean, std=std, last_hour=last_hour_count, status=status)


def overview() -> Dict:
    db = connect()
    try:
        total = db.execute(text("SELECT COUNT(*) FROM alerts_store")).scalar() or 0
        last_24h = db.execute(
            text(
                "SELECT COUNT(*) FROM alerts_store WHERE event_time >= NOW() - interval '24 hours'"
            )
        ).scalar() or 0
        last_7d = db.execute(
            text(
                "SELECT COUNT(*) FROM alerts_store WHERE event_time >= NOW() - interval '7 days'"
            )
        ).scalar() or 0

        top_rules_rows = db.execute(
            text(
                """
                SELECT COALESCE(rule_description, rule_id, 'unknown') as rule, COUNT(*) as cnt
                FROM alerts_store
                WHERE event_time >= NOW() - interval '7 days'
                GROUP BY rule
                ORDER BY cnt DESC
                LIMIT 5
                """
            )
        ).fetchall()

        top_agents_rows = db.execute(
            text(
                """
                SELECT COALESCE(agent_name, agent_id, 'unknown') as agent, COUNT(*) as cnt
                FROM alerts_store
                WHERE event_time >= NOW() - interval '7 days'
                GROUP BY agent
                ORDER BY cnt DESC
                LIMIT 5
                """
            )
        ).fetchall()

        severity_rows = db.execute(
            text(
                """
                SELECT COALESCE(rule_level, 0) as level, COUNT(*) as cnt
                FROM alerts_store
                WHERE event_time >= NOW() - interval '7 days'
                GROUP BY level
                ORDER BY level DESC
                """
            )
        ).fetchall()

        anomaly = _compute_anomaly(db)
        top_rules = _rows_to_lists(top_rules_rows)
        top_agents = _rows_to_lists(top_agents_rows)
        severity = _rows_to_lists(severity_rows)

        return {
            "total": total,
            "last_24h": last_24h,
            "last_7d": last_7d,
            "top_rules": top_rules,
            "top_agents": top_agents,
            "severity": severity,
            "anomaly": anomaly.__dict__,
        }
    finally:
        db.close()


def kill_chain(case_id: Optional[int] = None, hours: int = 24) -> Dict:
    lookback_hours = max(1, min(int(hours or 24), 24 * 30))
    db = connect()
    try:
        if case_id:
            rows = db.execute(
                text(
                    """
                    SELECT ma.tactic, COUNT(*) as cnt
                    FROM case_timeline ct
                    JOIN mitre_alerts ma ON ma.alert_id = ct.alert_id
                    WHERE ct.case_id=:case_id AND ct.event_type='alert_attached'
                    GROUP BY ma.tactic
                    """
                ),
                {"case_id": case_id},
            ).fetchall()
        else:
            rows = db.execute(
                text(
                    """
                    SELECT tactic, COUNT(*) as cnt
                    FROM mitre_alerts
                    WHERE created_at >= NOW() - (:hours || ' hours')::interval
                    GROUP BY tactic
                    """
                ),
                {"hours": lookback_hours},
            ).fetchall()

        stages: Dict[str, int] = {}
        for tactic, cnt in rows:
            if not tactic:
                continue
            stage = KILL_CHAIN_MAP.get(tactic, "Other")
            stages[stage] = stages.get(stage, 0) + cnt

        return {"stages": stages, "raw": _rows_to_lists(rows), "hours": lookback_hours}
    finally:
        db.close()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _load_raw_json(raw_value: Any) -> Dict[str, Any]:
    if isinstance(raw_value, dict):
        return raw_value
    if not raw_value:
        return {}
    try:
        parsed = json.loads(str(raw_value))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _to_ioc_objects(ioc_rows: List[List[Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in ioc_rows:
        ioc = row[0] if len(row) > 0 else None
        ioc_type = row[1] if len(row) > 1 else None
        source = row[2] if len(row) > 2 else None
        score = _safe_int(row[3], 0) if len(row) > 3 else 0
        verdict = str(row[4] or "").lower() if len(row) > 4 else ""
        out.append(
            {
                "ioc": ioc,
                "ioc_type": str(ioc_type or "").lower(),
                "source": source,
                "score": score,
                "verdict": verdict,
            }
        )
    return out


def _prefer_ioc_verdict(existing: str, incoming: str) -> str:
    existing_l = str(existing or "unknown").strip().lower() or "unknown"
    incoming_l = str(incoming or "unknown").strip().lower() or "unknown"
    if _IOC_VERDICT_RANK.get(incoming_l, 0) > _IOC_VERDICT_RANK.get(existing_l, 0):
        return incoming_l
    return existing_l


def _aggregate_ioc_objects(ioc_objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_key: Dict[str, Dict[str, Any]] = {}
    for ioc in ioc_objects:
        value = str(ioc.get("ioc") or "").strip()
        ioc_type = str(ioc.get("ioc_type") or "").strip().lower()
        if not value:
            continue
        key = f"{ioc_type}::{value.lower()}"
        score = _safe_int(ioc.get("score"), 0)
        verdict = str(ioc.get("verdict") or "unknown").strip().lower() or "unknown"
        source = str(ioc.get("source") or "").strip()
        existing = by_key.get(key)
        if not existing:
            by_key[key] = {
                "ioc": value,
                "ioc_type": ioc_type,
                "score": score,
                "verdict": verdict,
                "sources": [source] if source else [],
            }
            continue
        existing["score"] = max(_safe_int(existing.get("score"), 0), score)
        existing["verdict"] = _prefer_ioc_verdict(existing.get("verdict"), verdict)
        if source and source not in existing["sources"]:
            existing["sources"].append(source)
    out = list(by_key.values())
    out.sort(
        key=lambda item: (
            -_safe_int(item.get("score"), 0),
            str(item.get("ioc_type") or ""),
            str(item.get("ioc") or ""),
        )
    )
    return out


def _to_mitre_objects(mitre_rows: List[List[Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for idx, row in enumerate(mitre_rows):
        tactic = str(row[0] or "").strip() if len(row) > 0 else ""
        technique = str(row[1] or "").strip() if len(row) > 1 else ""
        technique_id = str(row[2] or "").strip().upper() if len(row) > 2 else ""
        confidence = _safe_int(row[3], 0) if len(row) > 3 else 0
        source = str(row[4] or "").strip() if len(row) > 4 else ""
        mapping_rank = _safe_int(row[5], idx + 1) if len(row) > 5 else (idx + 1)
        out.append(
            {
                "tactic": tactic,
                "technique": technique,
                "technique_id": technique_id,
                "confidence": confidence,
                "source": source,
                "mapping_rank": mapping_rank if mapping_rank > 0 else (idx + 1),
                "is_primary": False,
            }
        )
    out.sort(
        key=lambda item: (
            -_safe_int(item.get("confidence"), 0),
            _safe_int(item.get("mapping_rank"), 9999),
            str(item.get("technique_id") or ""),
            str(item.get("tactic") or ""),
        )
    )
    for idx, item in enumerate(out):
        item["is_primary"] = idx == 0
    return out


def _unique_ioc_count(ioc_objects: List[Dict[str, Any]]) -> int:
    keys = {
        f"{str(ioc.get('ioc_type') or '').lower()}::{str(ioc.get('ioc') or '').strip().lower()}"
        for ioc in ioc_objects
        if str(ioc.get("ioc") or "").strip()
    }
    return len(keys)


def _ioc_score(ioc: Dict[str, Any]) -> int:
    return _safe_int(ioc.get("score"), 0)


def _ioc_verdict(ioc: Dict[str, Any]) -> str:
    return str(ioc.get("verdict") or "").strip().lower()


def _is_internal_network_ioc(ioc: Dict[str, Any]) -> bool:
    ioc_type = str(ioc.get("ioc_type") or "").strip().lower()
    value = str(ioc.get("ioc") or "").strip()
    if not ioc_type or not value:
        return False

    if ioc_type == "ip":
        try:
            ip_obj = ipaddress.ip_address(value)
            return bool(
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except Exception:
            return False

    if ioc_type == "domain":
        host = value.lower().strip(".")
    elif ioc_type == "url":
        try:
            host = (urlsplit(value).hostname or "").lower().strip(".")
        except Exception:
            host = ""
    else:
        return False

    if not host:
        return False
    if host in {"localhost", "localdomain"}:
        return True
    if host.endswith((".local", ".lan", ".home", ".internal")):
        return True
    return False


def _is_high_conf_ioc(ioc: Dict[str, Any]) -> bool:
    return _ioc_score(ioc) >= 85 or _ioc_verdict(ioc) == "malicious"


def _is_suspicious_ioc(ioc: Dict[str, Any]) -> bool:
    return _ioc_score(ioc) >= 55 or _ioc_verdict(ioc) in {"suspicious", "malicious"}


def _derive_impact(
    rule_level: Optional[int],
    tactics: List[str],
    has_high_ioc: bool,
    has_suspicious_ioc: bool,
) -> str:
    tactic_l = {str(t or "").lower() for t in tactics}
    if has_high_ioc:
        return "high"
    if tactic_l & _HIGH_IMPACT_TACTICS:
        return "high"
    if rule_level is not None and rule_level >= 12:
        return "high"
    if has_suspicious_ioc:
        return "medium"
    if tactics:
        return "medium"
    if rule_level is not None and rule_level >= 7:
        return "medium"
    return "low"


def _query_alert_from_indexer(alert_id: str) -> Dict[str, Any] | None:
    text_id = str(alert_id or "").strip()
    if not text_id:
        return None
    escaped = text_id.replace('"', '\\"')
    try:
        payload = IndexerClient().search_alerts(
            limit=3,
            query=f'id:"{escaped}" OR alert_id:"{escaped}"',
        )
    except Exception:
        return None
    hits = (((payload or {}).get("hits") or {}).get("hits") or [])
    if not isinstance(hits, list) or not hits:
        return None
    selected = None
    for hit in hits:
        source = hit.get("_source") if isinstance(hit, dict) else {}
        if not isinstance(source, dict):
            continue
        candidate_ids = {
            str(source.get("id") or "").strip(),
            str(source.get("alert_id") or "").strip(),
            str(hit.get("_id") or "").strip() if isinstance(hit, dict) else "",
        }
        if text_id in candidate_ids:
            selected = source
            break
        if selected is None:
            selected = source
    if not isinstance(selected, dict):
        return None
    rule = selected.get("rule") if isinstance(selected.get("rule"), dict) else {}
    agent = selected.get("agent") if isinstance(selected.get("agent"), dict) else {}
    event_time = (
        selected.get("@timestamp")
        or selected.get("timestamp")
        or selected.get("time")
    )
    parsed_time = parse_utc_datetime(event_time)
    return {
        "alert_id": str(selected.get("id") or selected.get("alert_id") or text_id),
        "agent_name": agent.get("name"),
        "agent_id": agent.get("id") or agent.get("agent_id"),
        "rule_description": rule.get("description") or rule.get("id"),
        "rule_id": str(rule.get("id") or "").strip() or None,
        "rule_level": _safe_int(rule.get("level"), 0),
        "event_time": parsed_time,
        "raw_json": selected,
    }


def alert_summary(alert_id: str) -> Dict:
    db = connect()
    try:
        alert = db.execute(
            text(
                """
                SELECT alert_id, agent_name, agent_id, rule_description, rule_id, rule_level, event_time, raw_json
                FROM alerts_store
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchone()

        if not alert:
            fallback = _query_alert_from_indexer(alert_id)
            if not fallback:
                return {"summary": "Alert not found", "alert_id": alert_id}
            alert_id_value = fallback["alert_id"]
            agent_name = fallback["agent_name"]
            agent_id = fallback["agent_id"]
            rule_desc = fallback["rule_description"]
            rule_id = fallback["rule_id"]
            rule_level = fallback["rule_level"]
            event_time = fallback["event_time"]
            raw_json = fallback["raw_json"]
        else:
            (
                alert_id_value,
                agent_name,
                agent_id,
                rule_desc,
                rule_id,
                rule_level,
                event_time,
                raw_json,
            ) = alert

        ioc_rows = db.execute(
            text(
                """
                SELECT ioc, ioc_type, source, score, verdict
                FROM ioc_enrichments
                WHERE alert_id=:alert_id
                ORDER BY score DESC NULLS LAST
                """
            ),
            {"alert_id": alert_id_value},
        ).fetchall()
        iocs = _rows_to_lists(ioc_rows)
        ioc_objects = _to_ioc_objects(iocs)
        unique_ioc_objects = _aggregate_ioc_objects(ioc_objects)

        mitre_rows = db.execute(
            text(
                """
                SELECT tactic, technique, technique_id, confidence, source, mapping_rank
                FROM mitre_alerts
                WHERE alert_id=:alert_id
                ORDER BY confidence DESC NULLS LAST, mapping_rank ASC NULLS LAST, id ASC
                """
            ),
            {"alert_id": alert_id_value},
        ).fetchall()
        mitre_list = _rows_to_lists(mitre_rows)
        if not mitre_list and raw_json:
            inferred = MitreMapper().map_alerts(_load_raw_json(raw_json))
            for rank_idx, item in enumerate(inferred[:4], start=1):
                mitre_list.append(
                    [
                        str(item.get("tactic") or ""),
                        str(item.get("technique") or ""),
                        str(item.get("technique_id") or ""),
                        _safe_int(item.get("confidence"), 0),
                        str(item.get("source") or ""),
                        rank_idx,
                    ]
                )
        mitre_objects = _to_mitre_objects(mitre_list)
        primary_mitre = mitre_objects[0] if mitre_objects else None
        tactics = [str(item.get("tactic") or "") for item in mitre_objects if item.get("tactic")]
        techniques = [
            str(item.get("technique_id") or item.get("technique") or "")
            for item in mitre_objects
            if item.get("technique_id") or item.get("technique")
        ]

        rule_text = str(rule_desc or rule_id or "").lower()
        raw_alert = _load_raw_json(raw_json)
        platform = (
            str((((raw_alert.get("agent") or {}).get("os") or {}).get("platform") or "")).lower()
            if isinstance(raw_alert, dict)
            else ""
        )

        has_high_ioc = any(_is_high_conf_ioc(ioc) for ioc in unique_ioc_objects)
        has_suspicious_ioc = any(_is_suspicious_ioc(ioc) for ioc in unique_ioc_objects)

        rule_24h = 0
        if rule_id:
            rule_24h = db.execute(
                text(
                    """
                    SELECT COUNT(*) FROM alerts_store
                    WHERE rule_id=:rule_id AND event_time >= NOW() - interval '24 hours'
                    """
                ),
                {"rule_id": rule_id},
            ).scalar() or 0

        agent_24h = 0
        if agent_id:
            agent_24h = db.execute(
                text(
                    """
                    SELECT COUNT(*) FROM alerts_store
                    WHERE agent_id=:agent_id AND event_time >= NOW() - interval '24 hours'
                    """
                ),
                {"agent_id": agent_id},
            ).scalar() or 0

        impact = _derive_impact(rule_level, tactics, has_high_ioc, has_suspicious_ioc)

        root_cause = "Insufficient corroborating telemetry; analyst review recommended."
        if has_high_ioc:
            root_cause = "IOC enrichment indicates high-confidence malicious artifacts associated with this alert."
        elif any(hint in rule_text for hint in _AUTH_HINTS):
            if rule_24h >= 15:
                root_cause = "Repeated authentication failures indicate likely brute-force/password-spray activity."
            else:
                root_cause = "Authentication anomaly detected; validate user behavior and credential exposure."
        elif "vulnerability" in rule_text or "sca" in rule_text or "compliance" in rule_text:
            root_cause = "Compliance or vulnerability drift detected; remediation or rescanning is required."
        elif primary_mitre:
            primary_label = primary_mitre.get("technique_id") or primary_mitre.get("technique") or "unknown"
            root_cause = (
                f"Behavior maps to MITRE {primary_mitre.get('tactic') or 'tactic unknown'} / {primary_label} "
                f"with confidence {primary_mitre.get('confidence', 0)}."
            )
        elif rule_24h > 200 and (rule_level or 0) <= 5:
            root_cause = "High-frequency low-severity rule suggests noisy detection logic or local misconfiguration."
        elif agent_24h > 30:
            root_cause = f"Recurring detections on agent {agent_id} suggest persistent host-specific issues."

        if primary_mitre:
            primary_label = primary_mitre.get("technique_id") or primary_mitre.get("technique") or "unknown"
            mitre_text = (
                f"{primary_label} ({primary_mitre.get('tactic') or 'n/a'}, "
                f"confidence {primary_mitre.get('confidence', 0)})"
            )
        else:
            mitre_text = ", ".join(techniques[:2]) if techniques else "none"
        unique_ioc_count = _unique_ioc_count(unique_ioc_objects)
        top_ioc = unique_ioc_objects[0] if unique_ioc_objects else None
        summary_parts = [
            f"Alert {alert_id_value} on agent {agent_name or agent_id}",
            f"triggered rule '{rule_desc or rule_id}' (level {rule_level}).",
            f"MITRE mapping: {mitre_text}.",
            f"IOC indicators: {unique_ioc_count}.",
        ]
        if top_ioc:
            summary_parts.append(
                f"Top IOC: {top_ioc.get('ioc')} ({top_ioc.get('ioc_type')}, score {top_ioc.get('score')})."
            )
        if has_high_ioc:
            summary_parts.append("Threat intel corroborates malicious activity.")
        elif has_suspicious_ioc:
            summary_parts.append("Threat intel shows suspicious indicators requiring containment review.")
        if rule_24h > 100 and (rule_level or 0) <= 5 and not has_high_ioc:
            summary_parts.append("Rule volume suggests potential tuning need.")
        summary = " ".join(summary_parts)

        suggestions = remediation_suggestions(
            rule_level,
            rule_text=rule_text,
            tactics=tactics,
            iocs=unique_ioc_objects,
            platform=platform,
        )
        fp_score = false_positive_score(
            db,
            rule_id,
            rule_level,
            has_high_conf_ioc=has_high_ioc,
            has_suspicious_ioc=has_suspicious_ioc,
            mitre_count=len(mitre_objects),
            agent_alerts_24h=agent_24h,
            rule_alerts_24h=rule_24h,
            rule_text=rule_text,
        )

        return {
            "alert_id": alert_id_value,
            "summary": summary,
            "agent": agent_name or agent_id,
            "rule": rule_desc or rule_id,
            "rule_level": rule_level,
            "event_time": utc_iso(event_time),
            "iocs": iocs,
            "suggestions": suggestions,
            "false_positive_score": fp_score,
            "impact": impact,
            "root_cause": root_cause,
            "mitre": {
                "primary": primary_mitre,
                "mappings": mitre_objects,
            },
            "ioc_summary": {
                "total_records": len(ioc_objects),
                "unique_indicators": len(unique_ioc_objects),
                "high_confidence_indicators": sum(1 for ioc in unique_ioc_objects if _is_high_conf_ioc(ioc)),
                "suspicious_indicators": sum(1 for ioc in unique_ioc_objects if _is_suspicious_ioc(ioc)),
                "top_indicators": unique_ioc_objects[:5],
            },
        }
    finally:
        db.close()


def remediation_suggestions(
    rule_level: Optional[int],
    *,
    rule_text: str = "",
    tactics: Optional[List[str]] = None,
    iocs: Optional[List[Dict[str, Any]]] = None,
    platform: str = "",
) -> List[str]:
    actions = [a["id"] for a in list_actions() if a.get("id")]
    available = set(actions)
    suggestions: List[str] = []
    rule_l = str(rule_text or "").lower()
    tactic_l = {str(t or "").lower() for t in (tactics or [])}
    ioc_items = iocs or []
    level = _safe_int(rule_level, 0)

    high_iocs = [ioc for ioc in ioc_items if _is_high_conf_ioc(ioc)]
    suspicious_iocs = [ioc for ioc in ioc_items if _is_suspicious_ioc(ioc)]
    network_iocs = [ioc for ioc in ioc_items if str(ioc.get("ioc_type") or "").lower() in _NETWORK_IOC_TYPES]
    suspicious_network_iocs = [
        ioc for ioc in network_iocs if _is_suspicious_ioc(ioc) and not _is_internal_network_ioc(ioc)
    ]
    high_conf_network_iocs = [
        ioc for ioc in network_iocs if _is_high_conf_ioc(ioc) and not _is_internal_network_ioc(ioc)
    ]

    has_high_ioc = bool(high_iocs)
    has_high_conf_network_ioc = bool(high_conf_network_iocs)
    has_suspicious_network_ioc = bool(suspicious_network_iocs)
    is_generic_low_sev_process_event = (
        level > 0
        and level <= 4
        and any(hint in rule_l for hint in _GENERIC_PROCESS_EVENT_HINTS)
        and not has_high_ioc
        and "credential access" not in tactic_l
        and "command and control" not in tactic_l
    )

    def add(candidate: str) -> None:
        if candidate in available and candidate not in suggestions:
            suggestions.append(candidate)

    if is_generic_low_sev_process_event:
        for candidate in ("endpoint-healthcheck", "ioc-scan"):
            add(candidate)
        return suggestions[:3] if suggestions else actions[:2]

    if any(hint in rule_l for hint in _AUTH_HINTS) or "credential access" in tactic_l:
        if level >= 8 or has_high_ioc:
            for candidate in ("disable-account", "ioc-scan", "threat-hunt-persistence"):
                add(candidate)
        else:
            for candidate in ("ioc-scan", "endpoint-healthcheck"):
                add(candidate)

    if has_high_ioc or any(hint in rule_l for hint in _EXECUTION_HINTS):
        for candidate in ("kill-process", "quarantine-file", "malware-scan"):
            add(candidate)

    if has_high_conf_network_ioc and level >= 8:
        for candidate in ("firewall-drop", "host-deny", "route-null", "win-route-null"):
            add(candidate)
    elif has_suspicious_network_ioc and level >= 10:
        for candidate in ("firewall-drop", "host-deny"):
            add(candidate)
    elif "command and control" in tactic_l and level >= 10:
        for candidate in ("host-deny", "route-null", "win-route-null"):
            add(candidate)

    if "vulnerability" in rule_l or "cve" in rule_l or "sca" in rule_l or "patch" in rule_l:
        if platform == "windows":
            for candidate in ("patch-windows", "sca-rescan"):
                add(candidate)
        elif platform == "linux":
            for candidate in ("patch-linux", "sca-rescan"):
                add(candidate)
        else:
            for candidate in ("patch-windows", "patch-linux", "sca-rescan"):
                add(candidate)

    if not suggestions:
        if rule_level is not None and rule_level >= 12:
            for candidate in ("kill-process", "firewall-drop", "malware-scan"):
                add(candidate)
        elif rule_level is not None and rule_level >= 7:
            for candidate in ("ioc-scan", "endpoint-healthcheck"):
                add(candidate)
        else:
            for candidate in ("endpoint-healthcheck",):
                add(candidate)

    return suggestions[:4] if suggestions else actions[:2]


def false_positive_score(
    conn,
    rule_id: Optional[str],
    rule_level: Optional[int],
    *,
    has_high_conf_ioc: bool = False,
    has_suspicious_ioc: bool = False,
    mitre_count: int = 0,
    agent_alerts_24h: int = 0,
    rule_alerts_24h: int = 0,
    rule_text: str = "",
) -> int:
    score = 55

    if rule_level is None:
        score += 5
    elif rule_level >= 12:
        score -= 35
    elif rule_level >= 8:
        score -= 20
    elif rule_level >= 5:
        score -= 8
    else:
        score += 20

    if has_high_conf_ioc:
        score -= 35
    elif has_suspicious_ioc:
        score -= 18

    if mitre_count > 0:
        score -= 10

    if rule_id and rule_alerts_24h <= 0:
        rule_alerts_24h = conn.execute(
            text(
                """
                SELECT COUNT(*) FROM alerts_store
                WHERE rule_id=:rule_id AND event_time >= NOW() - interval '24 hours'
                """
            ),
            {"rule_id": rule_id},
        ).scalar() or 0

    if rule_alerts_24h > 200 and (rule_level or 0) <= 5 and not has_high_conf_ioc:
        score += 25
    elif rule_alerts_24h > 80 and (rule_level or 0) <= 5 and not has_high_conf_ioc:
        score += 12

    if agent_alerts_24h > 80 and (rule_level or 0) <= 5 and not has_high_conf_ioc:
        score += 10

    if any(hint in str(rule_text or "").lower() for hint in _AUTH_HINTS) and rule_alerts_24h >= 15:
        score -= 10

    return max(0, min(100, score))
