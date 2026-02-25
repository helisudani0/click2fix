from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from math import sqrt
from typing import Dict, List, Optional

from sqlalchemy import text

from core.actions import list_actions
from core.time_utils import row_to_json_list, utc_iso
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


def kill_chain(case_id: Optional[int] = None) -> Dict:
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
                    GROUP BY tactic
                    """
                )
            ).fetchall()

        stages: Dict[str, int] = {}
        for tactic, cnt in rows:
            if not tactic:
                continue
            stage = KILL_CHAIN_MAP.get(tactic, "Other")
            stages[stage] = stages.get(stage, 0) + cnt

        return {"stages": stages, "raw": _rows_to_lists(rows)}
    finally:
        db.close()


def alert_summary(alert_id: str) -> Dict:
    db = connect()
    try:
        alert = db.execute(
            text(
                """
                SELECT alert_id, agent_name, agent_id, rule_description, rule_id, rule_level, event_time
                FROM alerts_store
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchone()

        if not alert:
            return {"summary": "Alert not found", "alert_id": alert_id}

        alert_id, agent_name, agent_id, rule_desc, rule_id, rule_level, event_time = alert
        ioc_rows = db.execute(
            text(
                """
                SELECT ioc, ioc_type, source, score, verdict
                FROM ioc_enrichments
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()

        iocs = _rows_to_lists(ioc_rows)
        suggestions = remediation_suggestions(rule_level)
        fp_score = false_positive_score(db, rule_id, rule_level)
        impact = "low"
        if rule_level is not None:
            if rule_level >= 12:
                impact = "high"
            elif rule_level >= 7:
                impact = "medium"

        root_cause = "Isolated event. Requires analyst review."
        try:
            if iocs:
                high_ioc = any(
                    (len(row) > 3 and row[3] is not None and int(row[3]) >= 80)
                    or (len(row) > 4 and row[4] is not None and str(row[4]).lower() == "malicious")
                    for row in iocs
                )
                if high_ioc:
                    root_cause = "IOC enrichment indicates known malicious artifacts."
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
                if agent_24h > 25:
                    root_cause = f"Recurring alerts on agent {agent_id}. Likely persistent local issue."
            if rule_id:
                rule_7d = db.execute(
                    text(
                        """
                        SELECT COUNT(*) FROM alerts_store
                        WHERE rule_id=:rule_id AND event_time >= NOW() - interval '7 days'
                        """
                    ),
                    {"rule_id": rule_id},
                ).scalar() or 0
                if rule_7d > 200:
                    root_cause = "Rule is firing at high volume. Possible noisy detection or misconfiguration."
        except Exception:
            pass

        summary = (
            f"Alert {alert_id} on agent {agent_name or agent_id} "
            f"triggered rule {rule_desc or rule_id} (level {rule_level}). "
            f"IOC count: {len(iocs)}."
        )

        return {
            "alert_id": alert_id,
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
        }
    finally:
        db.close()


def remediation_suggestions(rule_level: Optional[int]) -> List[str]:
    actions = [a["id"] for a in list_actions()]
    suggestions: List[str] = []

    if rule_level is None:
        return actions[:2]

    if rule_level >= 12:
        for candidate in ("kill-process", "firewall-drop", "patch-linux"):
            if candidate in actions:
                suggestions.append(candidate)
    elif rule_level >= 7:
        for candidate in ("firewall-drop", "patch-linux"):
            if candidate in actions:
                suggestions.append(candidate)
    else:
        for candidate in ("patch-linux",):
            if candidate in actions:
                suggestions.append(candidate)

    return suggestions or actions[:2]


def false_positive_score(conn, rule_id: Optional[str], rule_level: Optional[int]) -> int:
    score = 0
    if rule_level is None:
        return 50

    if rule_level <= 3:
        score += 40
    elif rule_level <= 5:
        score += 25
    elif rule_level <= 7:
        score += 10

    if rule_id:
        count_24h = conn.execute(
            text(
                """
                SELECT COUNT(*) FROM alerts_store
                WHERE rule_id=:rule_id AND event_time >= NOW() - interval '24 hours'
                """
            ),
            {"rule_id": rule_id},
        ).scalar() or 0
        if count_24h > 50:
            score += 30
        elif count_24h > 20:
            score += 15

    return min(score, 100)
