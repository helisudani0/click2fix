import json
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import bindparam, text

from core.audit import log_audit
from core.security import current_user
from core.time_utils import parse_utc_datetime, utc_iso, utc_now_naive
from db.database import connect

router = APIRouter(prefix="/incidents")

_ALLOWED_STATUSES = {"open", "investigate", "contain", "verified", "closed"}
_ALLOWED_PRIORITIES = {"critical", "high", "medium", "low"}
_ALLOWED_ESCALATION_STATES = {"normal", "watch", "escalated"}

_PRIORITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

_DEFAULT_PRIORITY_SLA_HOURS = {
    "critical": 4,
    "high": 8,
    "medium": 24,
    "low": 72,
}

_IDENTITY_KEY_HINTS = {
    "user",
    "username",
    "account",
    "actor",
    "principal",
    "login",
    "uid",
    "srcuser",
    "dstuser",
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _as_text(value: Any, default: str = "") -> str:
    text_value = str(value or "").strip()
    return text_value or default


def _normalize_status(value: Any) -> Optional[str]:
    status = _as_text(value).lower()
    if not status:
        return None
    if status not in _ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail=f"Invalid status '{status}'")
    return status


def _normalize_priority(value: Any) -> Optional[str]:
    priority = _as_text(value).lower()
    if not priority:
        return None
    if priority not in _ALLOWED_PRIORITIES:
        raise HTTPException(status_code=400, detail=f"Invalid priority '{priority}'")
    return priority


def _normalize_escalation(value: Any) -> Optional[str]:
    escalation = _as_text(value).lower()
    if not escalation:
        return None
    if escalation not in _ALLOWED_ESCALATION_STATES:
        raise HTTPException(status_code=400, detail=f"Invalid escalation_state '{escalation}'")
    return escalation


def _parse_due_at(value: Any):
    if value is None:
        return None
    raw = str(value).strip()
    if not raw:
        return None
    parsed = parse_utc_datetime(raw)
    if parsed is None:
        raise HTTPException(status_code=400, detail="Invalid due_at timestamp")
    return parsed.replace(tzinfo=None)


def _load_raw_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _extract_identities(raw_json: Dict[str, Any]) -> List[str]:
    identities: set[str] = set()

    def walk(path: str, value: Any, depth: int = 0):
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                child = f"{path}.{key}" if path else str(key)
                walk(child, item, depth + 1)
            return
        if isinstance(value, list):
            for idx, item in enumerate(value):
                walk(f"{path}[{idx}]", item, depth + 1)
            return
        if value is None:
            return

        tokens = {
            token.lower()
            for token in path.replace("[", ".").replace("]", ".").split(".")
            if token
        }
        if not tokens.intersection(_IDENTITY_KEY_HINTS):
            return

        text_value = str(value).strip()
        if not text_value or len(text_value) > 120:
            return
        if "@" in text_value:
            identities.add(text_value.lower())
            return
        if ":" in text_value and text_value.count(":") >= 2:
            return
        if "." in text_value and text_value.replace(".", "").isdigit():
            return
        identities.add(text_value.lower())

    walk("", raw_json)
    return sorted(list(identities))[:8]


def _priority_from_level(max_rule_level: int) -> str:
    if max_rule_level >= 12:
        return "critical"
    if max_rule_level >= 9:
        return "high"
    if max_rule_level >= 6:
        return "medium"
    return "low"


def _prefer_priority(existing: str, incoming: str) -> str:
    existing_l = _as_text(existing, "low").lower()
    incoming_l = _as_text(incoming, "low").lower()
    if _PRIORITY_WEIGHT.get(incoming_l, 0) > _PRIORITY_WEIGHT.get(existing_l, 0):
        return incoming_l
    return existing_l


def _compute_due_state(due_at, status: str) -> str:
    if not due_at:
        return "none"
    if str(status or "").lower() == "closed":
        return "none"
    now = utc_now_naive()
    if due_at < now:
        return "overdue"
    if due_at <= now + timedelta(hours=4):
        return "due_soon"
    return "on_track"


def _signals_and_score(a: Dict[str, Any], b: Dict[str, Any]) -> tuple[int, List[str]]:
    score = 0
    signals: List[str] = []
    if a.get("agent_id") and a.get("agent_id") == b.get("agent_id"):
        score += 2
        signals.append("agent_overlap")
    shared_identities = (a.get("identities") or set()) & (b.get("identities") or set())
    if shared_identities:
        score += 3
        signals.append("identity_overlap")
    shared_iocs = (a.get("iocs") or set()) & (b.get("iocs") or set())
    if shared_iocs:
        score += 3
        signals.append("ioc_overlap")
    shared_tactics = (a.get("tactics") or set()) & (b.get("tactics") or set())
    if shared_tactics:
        score += 1
        signals.append("tactic_overlap")
    if a.get("rule_id") and a.get("rule_id") == b.get("rule_id"):
        score += 1
        signals.append("rule_overlap")
    return score, signals


class _UnionFind:
    def __init__(self, size: int):
        self.parent = list(range(size))
        self.rank = [0] * size

    def find(self, value: int) -> int:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: int, right: int) -> None:
        root_l = self.find(left)
        root_r = self.find(right)
        if root_l == root_r:
            return
        rank_l = self.rank[root_l]
        rank_r = self.rank[root_r]
        if rank_l < rank_r:
            self.parent[root_l] = root_r
        elif rank_l > rank_r:
            self.parent[root_r] = root_l
        else:
            self.parent[root_r] = root_l
            self.rank[root_l] += 1


def _incident_org_clause(org_id: Any) -> tuple[str, Dict[str, Any]]:
    if org_id is None:
        return "1=1", {}
    return "(i.org_id=:org_id OR i.org_id IS NULL)", {"org_id": org_id}


def _fetch_correlation_alerts(
    conn,
    *,
    lookback_hours: int,
    max_alerts: int,
    selected_alert_ids: List[str],
) -> List[Dict[str, Any]]:
    if selected_alert_ids:
        stmt = text(
            """
            SELECT
                alert_id, agent_id, agent_name, rule_id, rule_description, rule_level, tactic, event_time, raw_json
            FROM alerts_store
            WHERE alert_id IN :alert_ids
            ORDER BY event_time DESC NULLS LAST
            """
        ).bindparams(bindparam("alert_ids", expanding=True))
        rows = conn.execute(stmt, {"alert_ids": selected_alert_ids}).fetchall()
    else:
        rows = conn.execute(
            text(
                """
                SELECT
                    alert_id, agent_id, agent_name, rule_id, rule_description, rule_level, tactic, event_time, raw_json
                FROM alerts_store
                WHERE event_time >= NOW() - (:hours || ' hours')::interval
                ORDER BY event_time DESC NULLS LAST
                LIMIT :limit
                """
            ),
            {"hours": lookback_hours, "limit": max_alerts},
        ).fetchall()

    out: List[Dict[str, Any]] = []
    for row in rows:
        if not hasattr(row, "_mapping"):
            continue
        m = row._mapping
        parsed_event_time = parse_utc_datetime(m.get("event_time"))
        out.append(
            {
                "alert_id": str(m.get("alert_id") or "").strip(),
                "agent_id": str(m.get("agent_id") or "").strip(),
                "agent_name": str(m.get("agent_name") or "").strip(),
                "rule_id": str(m.get("rule_id") or "").strip(),
                "rule_description": str(m.get("rule_description") or "").strip(),
                "rule_level": _safe_int(m.get("rule_level"), 0),
                "tactic": str(m.get("tactic") or "").strip(),
                "event_time": parsed_event_time.replace(tzinfo=None) if parsed_event_time else None,
                "raw_json": _load_raw_json(m.get("raw_json")),
            }
        )
    out = [item for item in out if item.get("alert_id")]
    missing_event_fallback = utc_now_naive()
    out.sort(key=lambda item: item.get("event_time") or missing_event_fallback)
    return out


def _fetch_ioc_map(conn, alert_ids: List[str], min_ioc_score: int) -> Dict[str, set[str]]:
    if not alert_ids:
        return {}
    stmt = text(
        """
        SELECT alert_id, ioc, ioc_type
        FROM ioc_enrichments
        WHERE alert_id IN :alert_ids
          AND (
            COALESCE(score, 0) >= :min_ioc_score
            OR LOWER(COALESCE(verdict, '')) IN ('suspicious', 'malicious')
          )
        """
    ).bindparams(bindparam("alert_ids", expanding=True))
    rows = conn.execute(stmt, {"alert_ids": alert_ids, "min_ioc_score": min_ioc_score}).fetchall()
    by_alert: Dict[str, set[str]] = defaultdict(set)
    for row in rows:
        alert_id = str(row[0] or "").strip()
        ioc = str(row[1] or "").strip().lower()
        ioc_type = str(row[2] or "").strip().lower()
        if not alert_id or not ioc:
            continue
        by_alert[alert_id].add(f"{ioc_type}:{ioc}")
    return by_alert


def _fetch_tactic_map(conn, alert_ids: List[str]) -> Dict[str, set[str]]:
    if not alert_ids:
        return {}
    stmt = text(
        """
        SELECT alert_id, tactic
        FROM mitre_alerts
        WHERE alert_id IN :alert_ids
        """
    ).bindparams(bindparam("alert_ids", expanding=True))
    rows = conn.execute(stmt, {"alert_ids": alert_ids}).fetchall()
    by_alert: Dict[str, set[str]] = defaultdict(set)
    for row in rows:
        alert_id = str(row[0] or "").strip()
        tactic = str(row[1] or "").strip().lower()
        if alert_id and tactic:
            by_alert[alert_id].add(tactic)
    return by_alert


def _find_existing_incident(conn, alert_ids: List[str], org_id: Any) -> Optional[int]:
    if not alert_ids:
        return None
    org_clause, org_params = _incident_org_clause(org_id)
    stmt = text(
        f"""
        SELECT i.id
        FROM incidents i
        JOIN incident_alerts ia ON ia.incident_id = i.id
        WHERE ia.alert_id IN :alert_ids
          AND LOWER(COALESCE(i.status, 'open')) != 'closed'
          AND {org_clause}
        ORDER BY i.updated_at DESC NULLS LAST, i.id DESC
        LIMIT 1
        """
    ).bindparams(bindparam("alert_ids", expanding=True))
    params = {"alert_ids": alert_ids, **org_params}
    return conn.execute(stmt, params).scalar()


def _get_incident_row(conn, incident_id: int, org_id: Any):
    org_clause, org_params = _incident_org_clause(org_id)
    row = conn.execute(
        text(
            f"""
            SELECT
                i.id,
                i.title,
                i.summary,
                i.status,
                i.priority,
                i.owner,
                i.due_at,
                i.escalation_state,
                COALESCE(i.alert_count, 0) AS alert_count,
                i.first_event_time,
                i.last_event_time,
                i.created_by,
                i.org_id,
                i.created_at,
                i.updated_at
            FROM incidents i
            WHERE i.id=:incident_id
              AND {org_clause}
            """
        ),
        {"incident_id": incident_id, **org_params},
    ).fetchone()
    return row


def _serialize_incident_row(row) -> Dict[str, Any]:
    if not row:
        return {}
    m = row._mapping if hasattr(row, "_mapping") else {}
    status = str(m.get("status") or "").lower()
    due_at = m.get("due_at")
    return {
        "id": _safe_int(m.get("id"), 0),
        "title": m.get("title"),
        "summary": m.get("summary"),
        "status": status or "open",
        "priority": str(m.get("priority") or "medium").lower(),
        "owner": m.get("owner"),
        "due_at": utc_iso(due_at),
        "due_state": _compute_due_state(due_at, status),
        "escalation_state": str(m.get("escalation_state") or "normal").lower(),
        "alert_count": _safe_int(m.get("alert_count"), 0),
        "first_event_time": utc_iso(m.get("first_event_time")),
        "last_event_time": utc_iso(m.get("last_event_time")),
        "created_by": m.get("created_by"),
        "org_id": m.get("org_id"),
        "created_at": utc_iso(m.get("created_at")),
        "updated_at": utc_iso(m.get("updated_at")),
    }


def _insert_sla_event(conn, incident_id: int, event_type: str, detail: str, actor: str) -> None:
    conn.execute(
        text(
            """
            INSERT INTO incident_sla_events (incident_id, event_type, detail, actor)
            VALUES (:incident_id, :event_type, :detail, :actor)
            """
        ),
        {
            "incident_id": incident_id,
            "event_type": event_type,
            "detail": detail,
            "actor": actor,
        },
    )


@router.post("/correlate")
def correlate_incidents(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    lookback_hours = max(1, min(_safe_int(payload.get("lookback_hours"), 24), 24 * 30))
    time_window_minutes = max(5, min(_safe_int(payload.get("time_window_minutes"), 120), 24 * 60))
    min_group_size = max(2, min(_safe_int(payload.get("min_group_size"), 2), 200))
    min_correlation_score = max(1, min(_safe_int(payload.get("min_correlation_score"), 2), 20))
    max_alerts = max(20, min(_safe_int(payload.get("max_alerts"), 500), 3000))
    min_ioc_score = max(1, min(_safe_int(payload.get("min_ioc_score"), 55), 100))
    persist = _as_bool(payload.get("persist"), True)
    selected_alert_ids = [
        _as_text(item)
        for item in (payload.get("alert_ids") or [])
        if _as_text(item)
    ]
    forced_owner = _as_text(payload.get("owner")) or None

    db = connect()
    try:
        alerts = _fetch_correlation_alerts(
            db,
            lookback_hours=lookback_hours,
            max_alerts=max_alerts,
            selected_alert_ids=selected_alert_ids,
        )
        if len(alerts) < 2:
            return {
                "analyzed_alerts": len(alerts),
                "correlated_groups": 0,
                "groups": [],
                "persisted": False,
                "parameters": {
                    "lookback_hours": lookback_hours,
                    "time_window_minutes": time_window_minutes,
                },
            }

        alert_ids = [item["alert_id"] for item in alerts]
        ioc_map = _fetch_ioc_map(db, alert_ids, min_ioc_score=min_ioc_score)
        tactic_map = _fetch_tactic_map(db, alert_ids)

        contexts: List[Dict[str, Any]] = []
        for item in alerts:
            alert_id = item["alert_id"]
            raw_json = item.get("raw_json") or {}
            identities = set(_extract_identities(raw_json))
            tactics = set(tactic_map.get(alert_id, set()))
            if item.get("tactic"):
                tactics.add(str(item["tactic"]).strip().lower())
            contexts.append(
                {
                    "alert_id": alert_id,
                    "agent_id": item.get("agent_id") or "",
                    "agent_name": item.get("agent_name") or "",
                    "rule_id": item.get("rule_id") or "",
                    "rule_level": _safe_int(item.get("rule_level"), 0),
                    "event_time": item.get("event_time") or utc_now_naive(),
                    "rule_description": item.get("rule_description") or "",
                    "identities": identities,
                    "tactics": tactics,
                    "iocs": set(ioc_map.get(alert_id, set())),
                }
            )

        contexts.sort(key=lambda item: item["event_time"])
        uf = _UnionFind(len(contexts))
        signal_map: Dict[int, set[str]] = defaultdict(set)
        edge_count = 0
        time_window_seconds = float(time_window_minutes) * 60.0

        for idx in range(len(contexts)):
            left = contexts[idx]
            left_time = left["event_time"]
            for jdx in range(idx + 1, len(contexts)):
                right = contexts[jdx]
                delta_seconds = abs((right["event_time"] - left_time).total_seconds())
                if delta_seconds > time_window_seconds:
                    break
                score, signals = _signals_and_score(left, right)
                if score < min_correlation_score:
                    continue
                uf.union(idx, jdx)
                edge_count += 1
                signal_map[idx].update(signals)
                signal_map[jdx].update(signals)

        groups_by_root: Dict[int, List[int]] = defaultdict(list)
        for idx in range(len(contexts)):
            groups_by_root[uf.find(idx)].append(idx)

        groups: List[Dict[str, Any]] = []
        for members in groups_by_root.values():
            if len(members) < min_group_size:
                continue
            member_contexts = [contexts[idx] for idx in members]
            member_contexts.sort(key=lambda item: item["event_time"])
            alert_ids_group = [item["alert_id"] for item in member_contexts]
            agents = sorted({item["agent_id"] for item in member_contexts if item["agent_id"]})
            tactics = sorted({t for item in member_contexts for t in item.get("tactics", set())})
            identities = sorted({i for item in member_contexts for i in item.get("identities", set())})
            iocs = sorted({ioc for item in member_contexts for ioc in item.get("iocs", set())})
            signals = sorted({signal for idx in members for signal in signal_map.get(idx, set())})
            max_rule_level = max([_safe_int(item.get("rule_level"), 0) for item in member_contexts] or [0])
            priority = _priority_from_level(max_rule_level)
            first_event = member_contexts[0]["event_time"]
            last_event = member_contexts[-1]["event_time"]
            lead_agent = agents[0] if agents else "multiple-agents"
            lead_tactic = tactics[0].title() if tactics else "Security Activity"
            title = f"Correlated {lead_tactic} on {lead_agent}"
            summary = (
                f"Correlated cluster with {len(alert_ids_group)} alerts across {len(agents) or 1} agent(s), "
                f"{len(tactics)} tactic(s), and {len(iocs)} high-confidence IOC overlap entries."
            )
            groups.append(
                {
                    "alert_ids": alert_ids_group,
                    "agents": agents,
                    "tactics": tactics,
                    "identities": identities,
                    "ioc_count": len(iocs),
                    "signals": signals,
                    "title": title,
                    "summary": summary,
                    "priority": priority,
                    "first_event_time": first_event,
                    "last_event_time": last_event,
                    "max_rule_level": max_rule_level,
                    "owner": forced_owner,
                }
            )

        groups.sort(
            key=lambda item: (
                len(item["alert_ids"]),
                _PRIORITY_WEIGHT.get(item["priority"], 0),
                item["last_event_time"],
            ),
            reverse=True,
        )

        persisted_count = 0
        created_count = 0
        if persist and groups:
            actor = user.get("sub") if isinstance(user, dict) else str(user)
            org_id = user.get("org_id") if isinstance(user, dict) else None
            now = utc_now_naive()
            for group in groups:
                existing_incident_id = _find_existing_incident(db, group["alert_ids"], org_id)
                if existing_incident_id:
                    existing_alert_rows = db.execute(
                        text("SELECT alert_id FROM incident_alerts WHERE incident_id=:incident_id"),
                        {"incident_id": existing_incident_id},
                    ).fetchall()
                    existing_alerts = {str(row[0] or "").strip() for row in existing_alert_rows}
                    added = 0
                    for alert_id in group["alert_ids"]:
                        if alert_id in existing_alerts:
                            continue
                        member = next((item for item in contexts if item["alert_id"] == alert_id), None)
                        db.execute(
                            text(
                                """
                                INSERT INTO incident_alerts
                                (incident_id, alert_id, agent_id, tactic, identity, matched_signals)
                                VALUES (:incident_id, :alert_id, :agent_id, :tactic, :identity, :matched_signals)
                                """
                            ),
                            {
                                "incident_id": existing_incident_id,
                                "alert_id": alert_id,
                                "agent_id": member.get("agent_id") if member else None,
                                "tactic": next(iter(member.get("tactics") or []), None) if member else None,
                                "identity": next(iter(member.get("identities") or []), None) if member else None,
                                "matched_signals": json.dumps(group["signals"]),
                            },
                        )
                        added += 1

                    if added:
                        existing_row = db.execute(
                            text("SELECT priority, first_event_time, owner FROM incidents WHERE id=:incident_id"),
                            {"incident_id": existing_incident_id},
                        ).fetchone()
                        current_priority = (
                            str(existing_row[0] or "medium").lower()
                            if existing_row and len(existing_row) > 0
                            else "medium"
                        )
                        current_first_event = (
                            parse_utc_datetime(existing_row[1]).replace(tzinfo=None)
                            if existing_row and len(existing_row) > 1 and parse_utc_datetime(existing_row[1])
                            else group["first_event_time"]
                        )
                        owner_to_set = (
                            forced_owner
                            or (existing_row[2] if existing_row and len(existing_row) > 2 else None)
                        )
                        preferred_priority = _prefer_priority(current_priority, group["priority"])
                        alert_count = db.execute(
                            text("SELECT COUNT(*) FROM incident_alerts WHERE incident_id=:incident_id"),
                            {"incident_id": existing_incident_id},
                        ).scalar() or 0
                        db.execute(
                            text(
                                """
                                UPDATE incidents
                                SET priority=:priority,
                                    owner=:owner,
                                    first_event_time=:first_event_time,
                                    last_event_time=:last_event_time,
                                    alert_count=:alert_count,
                                    updated_at=:updated_at
                                WHERE id=:incident_id
                                """
                            ),
                            {
                                "incident_id": existing_incident_id,
                                "priority": preferred_priority,
                                "owner": owner_to_set,
                                "first_event_time": min(current_first_event, group["first_event_time"]),
                                "last_event_time": max(group["last_event_time"], now),
                                "alert_count": int(alert_count),
                                "updated_at": now,
                            },
                        )
                        _insert_sla_event(
                            db,
                            existing_incident_id,
                            "correlated_alerts_added",
                            f"Added {added} correlated alerts via correlation run",
                            actor,
                        )
                        persisted_count += 1
                    group["incident_id"] = existing_incident_id
                    group["created"] = False
                    continue

                due_hours = _DEFAULT_PRIORITY_SLA_HOURS.get(group["priority"], 24)
                due_at = now + timedelta(hours=due_hours)
                incident_id = db.execute(
                    text(
                        """
                        INSERT INTO incidents
                        (title, summary, status, priority, owner, due_at, escalation_state, correlation_key,
                         first_event_time, last_event_time, alert_count, org_id, created_by, created_at, updated_at)
                        VALUES
                        (:title, :summary, :status, :priority, :owner, :due_at, :escalation_state, :correlation_key,
                         :first_event_time, :last_event_time, :alert_count, :org_id, :created_by, :created_at, :updated_at)
                        RETURNING id
                        """
                    ),
                    {
                        "title": group["title"],
                        "summary": group["summary"],
                        "status": "open",
                        "priority": group["priority"],
                        "owner": forced_owner,
                        "due_at": due_at,
                        "escalation_state": "escalated" if group["priority"] in {"critical", "high"} else "normal",
                        "correlation_key": "|".join(sorted(group["alert_ids"]))[:500],
                        "first_event_time": group["first_event_time"],
                        "last_event_time": group["last_event_time"],
                        "alert_count": len(group["alert_ids"]),
                        "org_id": org_id,
                        "created_by": actor,
                        "created_at": now,
                        "updated_at": now,
                    },
                ).scalar()

                for alert_id in group["alert_ids"]:
                    member = next((item for item in contexts if item["alert_id"] == alert_id), None)
                    db.execute(
                        text(
                            """
                            INSERT INTO incident_alerts
                            (incident_id, alert_id, agent_id, tactic, identity, matched_signals)
                            VALUES (:incident_id, :alert_id, :agent_id, :tactic, :identity, :matched_signals)
                            """
                        ),
                        {
                            "incident_id": incident_id,
                            "alert_id": alert_id,
                            "agent_id": member.get("agent_id") if member else None,
                            "tactic": next(iter(member.get("tactics") or []), None) if member else None,
                            "identity": next(iter(member.get("identities") or []), None) if member else None,
                            "matched_signals": json.dumps(group["signals"]),
                        },
                    )

                _insert_sla_event(
                    db,
                    incident_id,
                    "incident_created",
                    "Incident created from correlation",
                    actor,
                )
                _insert_sla_event(
                    db,
                    incident_id,
                    "due_set",
                    f"Due time set to {utc_iso(due_at)}",
                    actor,
                )
                group["incident_id"] = incident_id
                group["created"] = True
                persisted_count += 1
                created_count += 1

            log_audit(
                "incidents_correlated",
                actor=actor,
                entity_type="incidents",
                entity_id=None,
                detail=(
                    f"groups={len(groups)}, created={created_count}, "
                    f"updated={max(0, persisted_count - created_count)}"
                ),
                org_id=org_id,
                ip_address=request.client.host if request.client else None,
                conn=db,
            )
            db.commit()

        response_groups = []
        for index, group in enumerate(groups, start=1):
            response_groups.append(
                {
                    "group_id": index,
                    "alert_ids": group["alert_ids"],
                    "alert_count": len(group["alert_ids"]),
                    "agents": group["agents"],
                    "tactics": group["tactics"],
                    "identities": group["identities"][:10],
                    "signals": group["signals"],
                    "priority": group["priority"],
                    "title": group["title"],
                    "summary": group["summary"],
                    "first_event_time": utc_iso(group["first_event_time"]),
                    "last_event_time": utc_iso(group["last_event_time"]),
                    "incident_id": group.get("incident_id"),
                    "created": bool(group.get("created")),
                }
            )

        return {
            "analyzed_alerts": len(contexts),
            "correlated_groups": len(response_groups),
            "edge_count": edge_count,
            "persisted": bool(persist),
            "persisted_groups": persisted_count,
            "created_incidents": created_count,
            "parameters": {
                "lookback_hours": lookback_hours,
                "time_window_minutes": time_window_minutes,
                "min_group_size": min_group_size,
                "min_correlation_score": min_correlation_score,
                "min_ioc_score": min_ioc_score,
            },
            "groups": response_groups,
        }
    finally:
        db.close()


@router.get("")
def list_incidents(
    status: Optional[str] = None,
    owner: Optional[str] = None,
    priority: Optional[str] = None,
    due_state: Optional[str] = None,
    include_alerts: bool = False,
    include_history: bool = False,
    history_limit: int = 20,
    limit: int = 100,
    offset: int = 0,
    user=Depends(current_user),
):
    status_norm = _normalize_status(status) if status else None
    priority_norm = _normalize_priority(priority) if priority else None
    due_state_norm = _as_text(due_state).lower()
    if due_state_norm and due_state_norm not in {"none", "on_track", "due_soon", "overdue"}:
        raise HTTPException(status_code=400, detail=f"Invalid due_state '{due_state_norm}'")

    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    history_limit = max(1, min(int(history_limit), 200))
    org_id = user.get("org_id") if isinstance(user, dict) else None

    org_clause, org_params = _incident_org_clause(org_id)
    where_parts = [org_clause]
    params: Dict[str, Any] = {**org_params, "limit": limit, "offset": offset}

    if status_norm:
        where_parts.append("LOWER(COALESCE(i.status, 'open'))=:status")
        params["status"] = status_norm
    if owner:
        where_parts.append("LOWER(COALESCE(i.owner, ''))=LOWER(:owner)")
        params["owner"] = owner
    if priority_norm:
        where_parts.append("LOWER(COALESCE(i.priority, 'medium'))=:priority")
        params["priority"] = priority_norm
    if due_state_norm == "none":
        where_parts.append("(i.due_at IS NULL OR LOWER(COALESCE(i.status, 'open'))='closed')")
    elif due_state_norm == "overdue":
        where_parts.append("(i.due_at IS NOT NULL AND i.due_at < NOW() AND LOWER(COALESCE(i.status, 'open'))!='closed')")
    elif due_state_norm == "due_soon":
        where_parts.append(
            "(i.due_at IS NOT NULL AND i.due_at >= NOW() AND i.due_at <= NOW() + interval '4 hours' "
            "AND LOWER(COALESCE(i.status, 'open'))!='closed')"
        )
    elif due_state_norm == "on_track":
        where_parts.append(
            "(i.due_at IS NOT NULL AND i.due_at > NOW() + interval '4 hours' "
            "AND LOWER(COALESCE(i.status, 'open'))!='closed')"
        )

    where_sql = " AND ".join(where_parts) if where_parts else "1=1"

    db = connect()
    try:
        count_row = db.execute(
            text(f"SELECT COUNT(*) FROM incidents i WHERE {where_sql}"),
            params,
        ).scalar() or 0

        rows = db.execute(
            text(
                f"""
                SELECT
                    i.id,
                    i.title,
                    i.summary,
                    i.status,
                    i.priority,
                    i.owner,
                    i.due_at,
                    i.escalation_state,
                    COALESCE(
                        NULLIF(i.alert_count, 0),
                        (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id=i.id)
                    ) AS alert_count,
                    i.first_event_time,
                    i.last_event_time,
                    i.created_by,
                    i.org_id,
                    i.created_at,
                    i.updated_at
                FROM incidents i
                WHERE {where_sql}
                ORDER BY
                    CASE LOWER(COALESCE(i.priority, 'medium'))
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END ASC,
                    CASE WHEN i.due_at IS NULL THEN 1 ELSE 0 END ASC,
                    i.due_at ASC NULLS LAST,
                    i.updated_at DESC NULLS LAST,
                    i.id DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            params,
        ).fetchall()

        items = [_serialize_incident_row(row) for row in rows]
        incident_ids = [item["id"] for item in items if item.get("id")]

        alerts_by_incident: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        if include_alerts and incident_ids:
            alert_rows = db.execute(
                text(
                    """
                    SELECT incident_id, alert_id, agent_id, tactic, identity, matched_signals, created_at
                    FROM incident_alerts
                    WHERE incident_id IN :incident_ids
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    """
                ).bindparams(bindparam("incident_ids", expanding=True)),
                {"incident_ids": incident_ids},
            ).fetchall()
            for row in alert_rows:
                matched_signals = []
                try:
                    matched_signals = json.loads(str(row[5] or "[]"))
                except Exception:
                    matched_signals = []
                alerts_by_incident[_safe_int(row[0], 0)].append(
                    {
                        "alert_id": row[1],
                        "agent_id": row[2],
                        "tactic": row[3],
                        "identity": row[4],
                        "matched_signals": matched_signals if isinstance(matched_signals, list) else [],
                        "attached_at": utc_iso(row[6]),
                    }
                )

        assignments_by_incident: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        sla_by_incident: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        if include_history and incident_ids:
            assignment_rows = db.execute(
                text(
                    """
                    SELECT incident_id, previous_owner, new_owner, changed_by, note, created_at
                    FROM incident_assignments
                    WHERE incident_id IN :incident_ids
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    """
                ).bindparams(bindparam("incident_ids", expanding=True)),
                {"incident_ids": incident_ids},
            ).fetchall()
            for row in assignment_rows:
                incident_id = _safe_int(row[0], 0)
                if len(assignments_by_incident[incident_id]) >= history_limit:
                    continue
                assignments_by_incident[incident_id].append(
                    {
                        "previous_owner": row[1],
                        "new_owner": row[2],
                        "changed_by": row[3],
                        "note": row[4],
                        "created_at": utc_iso(row[5]),
                    }
                )

            sla_rows = db.execute(
                text(
                    """
                    SELECT incident_id, event_type, detail, actor, created_at
                    FROM incident_sla_events
                    WHERE incident_id IN :incident_ids
                    ORDER BY created_at DESC NULLS LAST, id DESC
                    """
                ).bindparams(bindparam("incident_ids", expanding=True)),
                {"incident_ids": incident_ids},
            ).fetchall()
            for row in sla_rows:
                incident_id = _safe_int(row[0], 0)
                if len(sla_by_incident[incident_id]) >= history_limit:
                    continue
                sla_by_incident[incident_id].append(
                    {
                        "event_type": row[1],
                        "detail": row[2],
                        "actor": row[3],
                        "created_at": utc_iso(row[4]),
                    }
                )

        for item in items:
            incident_id = item["id"]
            if include_alerts:
                item["alerts"] = alerts_by_incident.get(incident_id, [])
            if include_history:
                item["assignment_history"] = assignments_by_incident.get(incident_id, [])
                item["sla_events"] = sla_by_incident.get(incident_id, [])

        return {
            "total": int(count_row),
            "limit": limit,
            "offset": offset,
            "items": items,
        }
    finally:
        db.close()


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    allowed = {
        "title",
        "summary",
        "status",
        "priority",
        "owner",
        "due_at",
        "escalation_state",
        "assignment_note",
    }
    if not payload:
        raise HTTPException(status_code=400, detail="No update payload provided")
    unknown = [key for key in payload.keys() if key not in allowed]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unsupported field(s): {', '.join(unknown)}")

    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None

    db = connect()
    try:
        current = _get_incident_row(db, incident_id, org_id)
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")

        current_m = current._mapping if hasattr(current, "_mapping") else {}
        updates: Dict[str, Any] = {}
        events: List[tuple[str, str]] = []

        if "title" in payload:
            updates["title"] = _as_text(payload.get("title"))
        if "summary" in payload:
            updates["summary"] = _as_text(payload.get("summary"))
        if "status" in payload:
            new_status = _normalize_status(payload.get("status"))
            old_status = str(current_m.get("status") or "open").lower()
            if new_status and new_status != old_status:
                updates["status"] = new_status
                events.append(("status_changed", f"{old_status} -> {new_status}"))
        if "priority" in payload:
            new_priority = _normalize_priority(payload.get("priority"))
            old_priority = str(current_m.get("priority") or "medium").lower()
            if new_priority and new_priority != old_priority:
                updates["priority"] = new_priority
                events.append(("priority_changed", f"{old_priority} -> {new_priority}"))
        if "escalation_state" in payload:
            new_escalation = _normalize_escalation(payload.get("escalation_state"))
            old_escalation = str(current_m.get("escalation_state") or "normal").lower()
            if new_escalation and new_escalation != old_escalation:
                updates["escalation_state"] = new_escalation
                events.append(("escalation_state_changed", f"{old_escalation} -> {new_escalation}"))
        if "due_at" in payload:
            parsed_due = _parse_due_at(payload.get("due_at"))
            old_due = current_m.get("due_at")
            updates["due_at"] = parsed_due
            if parsed_due and not old_due:
                events.append(("due_set", f"Due date set to {utc_iso(parsed_due)}"))
            elif not parsed_due and old_due:
                events.append(("due_cleared", "Due date cleared"))
            elif parsed_due and old_due:
                old_iso = utc_iso(old_due)
                new_iso = utc_iso(parsed_due)
                if old_iso != new_iso:
                    events.append(("due_updated", f"Due date changed from {old_iso} to {new_iso}"))

        if "owner" in payload:
            new_owner = _as_text(payload.get("owner")) or None
            old_owner = _as_text(current_m.get("owner")) or None
            if new_owner != old_owner:
                updates["owner"] = new_owner
                db.execute(
                    text(
                        """
                        INSERT INTO incident_assignments
                        (incident_id, previous_owner, new_owner, changed_by, note)
                        VALUES (:incident_id, :previous_owner, :new_owner, :changed_by, :note)
                        """
                    ),
                    {
                        "incident_id": incident_id,
                        "previous_owner": old_owner,
                        "new_owner": new_owner,
                        "changed_by": actor,
                        "note": _as_text(payload.get("assignment_note")),
                    },
                )
                events.append(("assignment_changed", f"{old_owner or 'unassigned'} -> {new_owner or 'unassigned'}"))

        if not updates and not events:
            return {"ok": True, "incident": _serialize_incident_row(current), "updated": False}

        updates["updated_at"] = utc_now_naive()
        set_parts = ", ".join([f"{key}=:{key}" for key in updates.keys()])
        db.execute(
            text(f"UPDATE incidents SET {set_parts} WHERE id=:incident_id"),
            {"incident_id": incident_id, **updates},
        )

        for event_type, detail in events:
            _insert_sla_event(db, incident_id, event_type, detail, actor)

        log_audit(
            "incident_updated",
            actor=actor,
            entity_type="incident",
            entity_id=str(incident_id),
            detail=json.dumps({"fields": sorted(list(updates.keys())), "events": [e[0] for e in events]}),
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()

        refreshed = _get_incident_row(db, incident_id, org_id)
        return {"ok": True, "incident": _serialize_incident_row(refreshed), "updated": True}
    finally:
        db.close()


@router.post("/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(current_user),
):
    owner = _as_text(payload.get("owner"))
    if not owner:
        raise HTTPException(status_code=400, detail="owner is required")
    note = _as_text(payload.get("note"))
    due_at = _parse_due_at(payload.get("due_at")) if "due_at" in payload else None
    actor = user.get("sub") if isinstance(user, dict) else str(user)
    org_id = user.get("org_id") if isinstance(user, dict) else None

    db = connect()
    try:
        current = _get_incident_row(db, incident_id, org_id)
        if not current:
            raise HTTPException(status_code=404, detail="Incident not found")
        current_m = current._mapping if hasattr(current, "_mapping") else {}
        old_owner = _as_text(current_m.get("owner")) or None

        db.execute(
            text(
                """
                INSERT INTO incident_assignments
                (incident_id, previous_owner, new_owner, changed_by, note)
                VALUES (:incident_id, :previous_owner, :new_owner, :changed_by, :note)
                """
            ),
            {
                "incident_id": incident_id,
                "previous_owner": old_owner,
                "new_owner": owner,
                "changed_by": actor,
                "note": note,
            },
        )

        update_parts = ["owner=:owner", "updated_at=:updated_at"]
        update_params: Dict[str, Any] = {
            "incident_id": incident_id,
            "owner": owner,
            "updated_at": utc_now_naive(),
        }
        if "due_at" in payload:
            update_parts.append("due_at=:due_at")
            update_params["due_at"] = due_at

        db.execute(
            text(f"UPDATE incidents SET {', '.join(update_parts)} WHERE id=:incident_id"),
            update_params,
        )

        _insert_sla_event(
            db,
            incident_id,
            "assignment_changed",
            f"{old_owner or 'unassigned'} -> {owner}",
            actor,
        )
        if "due_at" in payload:
            _insert_sla_event(
                db,
                incident_id,
                "due_updated",
                f"Due date set to {utc_iso(due_at)}" if due_at else "Due date cleared",
                actor,
            )

        log_audit(
            "incident_assigned",
            actor=actor,
            entity_type="incident",
            entity_id=str(incident_id),
            detail=json.dumps({"owner": owner, "note": note}),
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()

        refreshed = _get_incident_row(db, incident_id, org_id)
        return {"ok": True, "incident": _serialize_incident_row(refreshed)}
    finally:
        db.close()
