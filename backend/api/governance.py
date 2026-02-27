import json
from datetime import timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import bindparam, text

from core.audit import log_audit
from core.security import current_user, require_role
from core.time_utils import parse_utc_datetime, utc_iso, utc_now_naive
from db.database import connect

router = APIRouter(prefix="/governance")

_ALLOWED_CLASSIFICATIONS = {
    "expected_admin_activity",
    "review_required",
    "suspicious",
}

_CLASSIFICATION_WEIGHT = {
    "expected_admin_activity": 1,
    "review_required": 2,
    "suspicious": 3,
}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_text(value: Any, default: str = "") -> str:
    text_value = str(value or "").strip()
    return text_value or default


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _to_string_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        text_item = _to_text(item)
        if text_item:
            out.append(text_item)
    return out


def _load_json(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _normalize_classification(value: Any) -> str:
    classification = _to_text(value, "review_required").lower()
    if classification not in _ALLOWED_CLASSIFICATIONS:
        raise HTTPException(status_code=400, detail=f"Invalid classification '{classification}'")
    return classification


def _profile_org_clause(org_id: Any) -> tuple[str, Dict[str, Any]]:
    if org_id is None:
        return "1=1", {}
    return "(org_id=:org_id OR org_id IS NULL)", {"org_id": org_id}


def _normalize_profile_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    name = _to_text(payload.get("name"))
    if not name:
        raise HTTPException(status_code=400, detail="name is required")
    classification = _normalize_classification(payload.get("classification"))
    profile_raw = payload.get("profile") if isinstance(payload.get("profile"), dict) else {}
    profile: Dict[str, Any] = {
        "actions": [item.lower() for item in _to_string_list(profile_raw.get("actions"))],
        "actors": [item.lower() for item in _to_string_list(profile_raw.get("actors"))],
        "targets": [item.lower() for item in _to_string_list(profile_raw.get("targets"))],
        "tactics": [item.lower() for item in _to_string_list(profile_raw.get("tactics"))],
    }
    min_rule_level = profile_raw.get("min_rule_level")
    max_rule_level = profile_raw.get("max_rule_level")
    if min_rule_level is not None:
        profile["min_rule_level"] = max(0, min(_safe_int(min_rule_level, 0), 20))
    if max_rule_level is not None:
        profile["max_rule_level"] = max(0, min(_safe_int(max_rule_level, 20), 20))
    return {
        "name": name,
        "description": _to_text(payload.get("description")),
        "enabled": _as_bool(payload.get("enabled"), True),
        "classification": classification,
        "profile_json": json.dumps(profile),
    }


def _row_to_profile(row) -> Dict[str, Any]:
    if not row or not hasattr(row, "_mapping"):
        return {}
    m = row._mapping
    return {
        "id": _safe_int(m.get("id"), 0),
        "name": m.get("name"),
        "description": m.get("description"),
        "enabled": bool(m.get("enabled")),
        "classification": _to_text(m.get("classification"), "review_required").lower(),
        "profile": _load_json(m.get("profile_json")),
        "org_id": m.get("org_id"),
        "created_by": m.get("created_by"),
        "created_at": utc_iso(m.get("created_at")),
        "updated_at": utc_iso(m.get("updated_at")),
    }


def _load_profiles(conn, *, org_id: Any, enabled_only: bool) -> List[Dict[str, Any]]:
    org_clause, org_params = _profile_org_clause(org_id)
    rows = conn.execute(
        text(
            f"""
            SELECT id, name, description, enabled, classification, profile_json, org_id, created_by, created_at, updated_at
            FROM automation_context_profiles
            WHERE {org_clause}
              AND (:enabled_only = false OR enabled = true)
            ORDER BY id DESC
            """
        ),
        {"enabled_only": bool(enabled_only), **org_params},
    ).fetchall()
    return [_row_to_profile(row) for row in rows if row]


def _normalize_agent_id(agent_id: str) -> str:
    raw = _to_text(agent_id)
    if raw.isdigit() and len(raw) < 3:
        return raw.zfill(3)
    return raw


def _resolve_execution_context(conn, execution_id: int) -> Dict[str, Any]:
    row = conn.execute(
        text(
            """
            SELECT id, action, playbook, agent, approved_by, started_at, finished_at, status, org_id
            FROM executions
            WHERE id=:execution_id
            """
        ),
        {"execution_id": int(execution_id)},
    ).fetchone()
    if not row or not hasattr(row, "_mapping"):
        raise HTTPException(status_code=404, detail="Execution not found")
    m = row._mapping
    target_agents: List[str] = []
    target_rows = conn.execute(
        text("SELECT DISTINCT agent_id FROM execution_targets WHERE execution_id=:execution_id"),
        {"execution_id": int(execution_id)},
    ).fetchall()
    for target_row in target_rows:
        candidate = _to_text(target_row[0] if isinstance(target_row, (list, tuple)) else target_row)
        if candidate:
            target_agents.append(_normalize_agent_id(candidate))
    primary_agent = _normalize_agent_id(_to_text(m.get("agent")))
    if primary_agent and primary_agent not in target_agents and primary_agent.lower() != "all":
        target_agents.append(primary_agent)
    started_at = parse_utc_datetime(m.get("started_at")) or utc_now_naive()
    finished_at = parse_utc_datetime(m.get("finished_at"))
    return {
        "execution_id": int(m.get("id")),
        "action_id": _to_text(m.get("action") or m.get("playbook")).lower(),
        "actor": _to_text(m.get("approved_by"), "system").lower(),
        "target": _to_text(m.get("agent"), "all"),
        "target_agents": target_agents,
        "started_at": started_at.replace(tzinfo=None) if started_at and getattr(started_at, "tzinfo", None) else started_at,
        "finished_at": (
            finished_at.replace(tzinfo=None) if finished_at and getattr(finished_at, "tzinfo", None) else finished_at
        ),
        "status": _to_text(m.get("status")).upper(),
        "org_id": m.get("org_id"),
    }


def _fetch_alert_rows(
    conn,
    *,
    alert_ids: List[str],
    target_agents: List[str],
    start_at,
    end_at,
    limit: int,
) -> List[Dict[str, Any]]:
    rows = []
    if alert_ids:
        stmt = text(
            """
            SELECT alert_id, agent_id, rule_id, rule_description, rule_level, tactic, event_time
            FROM alerts_store
            WHERE alert_id IN :alert_ids
            ORDER BY event_time DESC NULLS LAST
            """
        ).bindparams(bindparam("alert_ids", expanding=True))
        rows = conn.execute(stmt, {"alert_ids": alert_ids}).fetchall()
    else:
        where_parts = []
        params: Dict[str, Any] = {"limit": int(limit)}
        if target_agents:
            stmt = text(
                """
                SELECT alert_id, agent_id, rule_id, rule_description, rule_level, tactic, event_time
                FROM alerts_store
                WHERE agent_id IN :target_agents
                  AND event_time >= :start_at
                  AND event_time <= :end_at
                ORDER BY event_time DESC NULLS LAST
                LIMIT :limit
                """
            ).bindparams(bindparam("target_agents", expanding=True))
            rows = conn.execute(
                stmt,
                {
                    "target_agents": target_agents,
                    "start_at": start_at,
                    "end_at": end_at,
                    **params,
                },
            ).fetchall()
        else:
            rows = conn.execute(
                text(
                    """
                    SELECT alert_id, agent_id, rule_id, rule_description, rule_level, tactic, event_time
                    FROM alerts_store
                    WHERE event_time >= :start_at
                      AND event_time <= :end_at
                    ORDER BY event_time DESC NULLS LAST
                    LIMIT :limit
                    """
                ),
                {"start_at": start_at, "end_at": end_at, **params},
            ).fetchall()

    out: List[Dict[str, Any]] = []
    for row in rows:
        if not hasattr(row, "_mapping"):
            continue
        m = row._mapping
        event_time = parse_utc_datetime(m.get("event_time"))
        out.append(
            {
                "alert_id": _to_text(m.get("alert_id")),
                "agent_id": _normalize_agent_id(_to_text(m.get("agent_id"))),
                "rule_id": _to_text(m.get("rule_id")),
                "rule_description": _to_text(m.get("rule_description")),
                "rule_level": _safe_int(m.get("rule_level"), 0),
                "tactic": _to_text(m.get("tactic")).lower(),
                "event_time": event_time.replace(tzinfo=None) if event_time else None,
            }
        )
    return [item for item in out if item.get("alert_id")]


def _fetch_alert_context_maps(conn, alert_ids: List[str]) -> tuple[Dict[str, set[str]], Dict[str, Dict[str, Any]]]:
    tactic_map: Dict[str, set[str]] = {}
    ioc_map: Dict[str, Dict[str, Any]] = {}
    if not alert_ids:
        return tactic_map, ioc_map

    tactic_rows = conn.execute(
        text(
            """
            SELECT alert_id, tactic
            FROM mitre_alerts
            WHERE alert_id IN :alert_ids
            """
        ).bindparams(bindparam("alert_ids", expanding=True)),
        {"alert_ids": alert_ids},
    ).fetchall()
    for row in tactic_rows:
        alert_id = _to_text(row[0] if isinstance(row, (list, tuple)) else None)
        tactic = _to_text(row[1] if isinstance(row, (list, tuple)) else None).lower()
        if not alert_id or not tactic:
            continue
        bucket = tactic_map.setdefault(alert_id, set())
        bucket.add(tactic)

    ioc_rows = conn.execute(
        text(
            """
            SELECT alert_id,
                   MAX(COALESCE(score, 0)) AS max_score,
                   MAX(CASE WHEN LOWER(COALESCE(verdict, '')) IN ('malicious', 'suspicious') THEN 1 ELSE 0 END) AS has_suspicious
            FROM ioc_enrichments
            WHERE alert_id IN :alert_ids
            GROUP BY alert_id
            """
        ).bindparams(bindparam("alert_ids", expanding=True)),
        {"alert_ids": alert_ids},
    ).fetchall()
    for row in ioc_rows:
        if not isinstance(row, (list, tuple)):
            continue
        alert_id = _to_text(row[0])
        if not alert_id:
            continue
        ioc_map[alert_id] = {
            "max_score": _safe_int(row[1], 0),
            "has_suspicious": bool(_safe_int(row[2], 0) > 0),
        }
    return tactic_map, ioc_map


def _profile_matches_context(profile: Dict[str, Any], context: Dict[str, Any]) -> tuple[bool, List[str]]:
    profile_json = profile.get("profile") if isinstance(profile.get("profile"), dict) else {}
    reasons: List[str] = []

    actions = {str(item).lower() for item in (profile_json.get("actions") or [])}
    actors = {str(item).lower() for item in (profile_json.get("actors") or [])}
    targets = {str(item).lower() for item in (profile_json.get("targets") or [])}
    action_id = _to_text(context.get("action_id")).lower()
    actor = _to_text(context.get("actor")).lower()
    target = _to_text(context.get("target")).lower()
    target_agents = {str(item).lower() for item in (context.get("target_agents") or [])}

    if actions:
        if action_id not in actions:
            return False, []
        reasons.append("action")
    if actors:
        if actor not in actors:
            return False, []
        reasons.append("actor")
    if targets:
        has_target_match = False
        if "all" in targets and target == "all":
            has_target_match = True
        if target and target in targets:
            has_target_match = True
        if target_agents and targets.intersection(target_agents):
            has_target_match = True
        if not has_target_match:
            return False, []
        reasons.append("target")
    return True, reasons


def _select_classification(candidates: List[str], default_value: str = "review_required") -> str:
    if not candidates:
        return default_value
    best = default_value
    best_weight = _CLASSIFICATION_WEIGHT.get(best, 0)
    for item in candidates:
        weight = _CLASSIFICATION_WEIGHT.get(item, 0)
        if weight > best_weight:
            best = item
            best_weight = weight
    return best


def _upsert_execution_context_row(conn, payload: Dict[str, Any]) -> None:
    execution_id = payload.get("execution_id")
    if execution_id is None:
        return
    conn.execute(
        text(
            """
            INSERT INTO execution_context
            (execution_id, action_id, actor, target, started_at, finished_at, classification, reason, context_json,
             org_id, created_by, created_at, updated_at)
            VALUES
            (:execution_id, :action_id, :actor, :target, :started_at, :finished_at, :classification, :reason, :context_json,
             :org_id, :created_by, :created_at, :updated_at)
            ON CONFLICT (execution_id)
            DO UPDATE SET
                action_id=EXCLUDED.action_id,
                actor=EXCLUDED.actor,
                target=EXCLUDED.target,
                started_at=EXCLUDED.started_at,
                finished_at=EXCLUDED.finished_at,
                classification=EXCLUDED.classification,
                reason=EXCLUDED.reason,
                context_json=EXCLUDED.context_json,
                org_id=EXCLUDED.org_id,
                created_by=EXCLUDED.created_by,
                updated_at=EXCLUDED.updated_at
            """
        ),
        payload,
    )


def _upsert_alert_correlation_rows(conn, rows: List[Dict[str, Any]]) -> None:
    for row in rows:
        conn.execute(
            text(
                """
                INSERT INTO alert_execution_correlation
                (execution_id, alert_id, agent_id, classification, confidence, reason, matched_profile_ids,
                 org_id, created_by, created_at, updated_at)
                VALUES
                (:execution_id, :alert_id, :agent_id, :classification, :confidence, :reason, :matched_profile_ids,
                 :org_id, :created_by, :created_at, :updated_at)
                ON CONFLICT (execution_id, alert_id)
                DO UPDATE SET
                    agent_id=EXCLUDED.agent_id,
                    classification=EXCLUDED.classification,
                    confidence=EXCLUDED.confidence,
                    reason=EXCLUDED.reason,
                    matched_profile_ids=EXCLUDED.matched_profile_ids,
                    org_id=EXCLUDED.org_id,
                    created_by=EXCLUDED.created_by,
                    updated_at=EXCLUDED.updated_at
                """
            ),
            row,
        )


def _run_automation_context_validation(
    conn,
    *,
    context: Dict[str, Any],
    profiles: List[Dict[str, Any]],
    alert_ids: List[str],
    lookback_minutes: int,
    alert_limit: int,
    actor: str,
    org_id: Any,
    persist: bool,
) -> Dict[str, Any]:
    start_at = (context.get("started_at") or utc_now_naive()) - timedelta(minutes=int(lookback_minutes))
    end_anchor = context.get("finished_at") or utc_now_naive()
    end_at = end_anchor + timedelta(minutes=int(lookback_minutes))
    target_agents = [_normalize_agent_id(item) for item in (context.get("target_agents") or []) if _to_text(item)]

    alerts = _fetch_alert_rows(
        conn,
        alert_ids=alert_ids,
        target_agents=target_agents,
        start_at=start_at,
        end_at=end_at,
        limit=alert_limit,
    )
    alert_id_values = [item["alert_id"] for item in alerts]
    tactic_map, ioc_map = _fetch_alert_context_maps(conn, alert_id_values)

    context_matched_profiles: List[Dict[str, Any]] = []
    for profile in profiles:
        matched, reasons = _profile_matches_context(profile, context)
        if matched:
            item = dict(profile)
            item["matched_on"] = reasons
            context_matched_profiles.append(item)

    correlated_rows: List[Dict[str, Any]] = []
    now = utc_now_naive()
    for alert in alerts:
        alert_id = alert["alert_id"]
        tactics = set(tactic_map.get(alert_id, set()))
        if alert.get("tactic"):
            tactics.add(str(alert["tactic"]).lower())
        ioc_context = ioc_map.get(alert_id, {"max_score": 0, "has_suspicious": False})
        high_risk = bool(ioc_context.get("has_suspicious")) or _safe_int(ioc_context.get("max_score"), 0) >= 85
        if alert.get("rule_level", 0) >= 14:
            high_risk = True

        matched_profiles: List[Dict[str, Any]] = []
        for profile in context_matched_profiles:
            profile_json = profile.get("profile") if isinstance(profile.get("profile"), dict) else {}
            profile_tactics = {str(item).lower() for item in (profile_json.get("tactics") or [])}
            if profile_tactics and not profile_tactics.intersection(tactics):
                continue
            min_rule = profile_json.get("min_rule_level")
            max_rule = profile_json.get("max_rule_level")
            if min_rule is not None and _safe_int(alert.get("rule_level"), 0) < _safe_int(min_rule, 0):
                continue
            if max_rule is not None and _safe_int(alert.get("rule_level"), 0) > _safe_int(max_rule, 20):
                continue
            matched_profiles.append(profile)

        candidate_classes = [_to_text(item.get("classification"), "review_required") for item in matched_profiles]
        classification = _select_classification(candidate_classes, default_value="review_required")
        if high_risk:
            classification = "suspicious"
        confidence = 35
        if matched_profiles:
            confidence += 25
        if target_agents and alert.get("agent_id") and alert.get("agent_id") in target_agents:
            confidence += 15
        if high_risk:
            confidence = max(10, confidence - 25)
        confidence = max(1, min(confidence, 99))
        reason_parts = []
        if matched_profiles:
            reason_parts.append(f"profile_match={','.join(str(item['id']) for item in matched_profiles)}")
        if high_risk:
            reason_parts.append("high_risk_alert_signals")
        if not reason_parts:
            reason_parts.append("default_review")
        reason = "; ".join(reason_parts)

        correlated_rows.append(
            {
                "execution_id": context.get("execution_id"),
                "alert_id": alert_id,
                "agent_id": alert.get("agent_id"),
                "classification": classification,
                "confidence": confidence,
                "reason": reason,
                "matched_profile_ids": [int(item["id"]) for item in matched_profiles if item.get("id")],
                "rule_level": _safe_int(alert.get("rule_level"), 0),
                "rule_id": alert.get("rule_id"),
                "rule_description": alert.get("rule_description"),
                "tactics": sorted(list(tactics)),
                "ioc_max_score": _safe_int(ioc_context.get("max_score"), 0),
                "event_time": utc_iso(alert.get("event_time")),
            }
        )

    overall_candidates = [row["classification"] for row in correlated_rows]
    overall_candidates.extend([_to_text(item.get("classification")) for item in context_matched_profiles])
    overall_classification = _select_classification(overall_candidates, default_value="review_required")
    summary_reason = (
        f"profiles={len(context_matched_profiles)}; correlated_alerts={len(correlated_rows)}; "
        f"classification={overall_classification}"
    )

    if persist and context.get("execution_id") is not None:
        _upsert_execution_context_row(
            conn,
            {
                "execution_id": context.get("execution_id"),
                "action_id": context.get("action_id"),
                "actor": context.get("actor"),
                "target": context.get("target"),
                "started_at": context.get("started_at"),
                "finished_at": context.get("finished_at"),
                "classification": overall_classification,
                "reason": summary_reason,
                "context_json": json.dumps(
                    {
                        "target_agents": context.get("target_agents") or [],
                        "matched_profile_ids": [item["id"] for item in context_matched_profiles],
                        "lookback_minutes": lookback_minutes,
                    }
                ),
                "org_id": org_id,
                "created_by": actor,
                "created_at": now,
                "updated_at": now,
            },
        )
        db_rows: List[Dict[str, Any]] = []
        for row in correlated_rows:
            db_rows.append(
                {
                    "execution_id": context.get("execution_id"),
                    "alert_id": row["alert_id"],
                    "agent_id": row.get("agent_id"),
                    "classification": row["classification"],
                    "confidence": row["confidence"],
                    "reason": row["reason"],
                    "matched_profile_ids": json.dumps(row.get("matched_profile_ids") or []),
                    "org_id": org_id,
                    "created_by": actor,
                    "created_at": now,
                    "updated_at": now,
                }
            )
        _upsert_alert_correlation_rows(conn, db_rows)

    return {
        "execution_id": context.get("execution_id"),
        "classification": overall_classification,
        "correlated_alerts": len(correlated_rows),
        "matched_profiles": [
            {
                "id": item["id"],
                "name": item["name"],
                "classification": item["classification"],
                "matched_on": item.get("matched_on") or [],
            }
            for item in context_matched_profiles
        ],
        "alerts": correlated_rows,
        "persisted": bool(persist and context.get("execution_id") is not None),
    }


@router.post("/automation-context/profiles")
def create_automation_context_profile(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(require_role("admin")),
):
    actor = _to_text(user.get("sub"), "system")
    user_org_id = user.get("org_id")
    org_id = user_org_id
    normalized = _normalize_profile_payload(payload if isinstance(payload, dict) else {})
    now = utc_now_naive()
    db = connect()
    try:
        row = db.execute(
            text(
                """
                INSERT INTO automation_context_profiles
                (name, description, enabled, classification, profile_json, org_id, created_by, created_at, updated_at)
                VALUES
                (:name, :description, :enabled, :classification, :profile_json, :org_id, :created_by, :created_at, :updated_at)
                RETURNING id, name, description, enabled, classification, profile_json, org_id, created_by, created_at, updated_at
                """
            ),
            {
                **normalized,
                "org_id": org_id,
                "created_by": actor,
                "created_at": now,
                "updated_at": now,
            },
        ).fetchone()
        log_audit(
            "automation_context_profile_created",
            actor=actor,
            entity_type="automation_context_profile",
            entity_id=str(row[0]) if row else None,
            detail=f"name={normalized['name']}; classification={normalized['classification']}",
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()
        return {"status": "created", "profile": _row_to_profile(row)}
    finally:
        db.close()


@router.get("/automation-context/profiles")
def list_automation_context_profiles(
    enabled_only: bool = Query(default=False),
    user=Depends(require_role("analyst")),
):
    org_id = user.get("org_id") if isinstance(user, dict) else None
    db = connect()
    try:
        profiles = _load_profiles(db, org_id=org_id, enabled_only=bool(enabled_only))
        return {"count": len(profiles), "profiles": profiles}
    finally:
        db.close()


@router.post("/automation-context/validate")
def validate_automation_context(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
    user=Depends(require_role("analyst")),
):
    body = payload if isinstance(payload, dict) else {}
    execution_id = body.get("execution_id")
    lookback_minutes = max(5, min(_safe_int(body.get("lookback_minutes"), 90), 24 * 60))
    alert_limit = max(20, min(_safe_int(body.get("alert_limit"), 300), 2000))
    persist = _as_bool(body.get("persist"), True)
    actor = _to_text(user.get("sub"), "system")
    user_org_id = user.get("org_id")
    org_id = user_org_id
    alert_ids = [_to_text(item) for item in (body.get("alert_ids") or []) if _to_text(item)]

    db = connect()
    try:
        if execution_id is not None:
            context = _resolve_execution_context(db, _safe_int(execution_id, 0))
        else:
            started_at = parse_utc_datetime(body.get("started_at")) or utc_now_naive()
            finished_at = parse_utc_datetime(body.get("finished_at"))
            context = {
                "execution_id": None,
                "action_id": _to_text(body.get("action_id")).lower(),
                "actor": _to_text(body.get("actor"), actor).lower(),
                "target": _to_text(body.get("target"), "all"),
                "target_agents": [_normalize_agent_id(item) for item in _to_string_list(body.get("target_agents"))],
                "started_at": (
                    started_at.replace(tzinfo=None)
                    if started_at and getattr(started_at, "tzinfo", None)
                    else started_at
                ),
                "finished_at": (
                    finished_at.replace(tzinfo=None)
                    if finished_at and getattr(finished_at, "tzinfo", None)
                    else finished_at
                ),
                "status": _to_text(body.get("status")),
                "org_id": org_id,
            }
        context_org_id = context.get("org_id")
        if user_org_id is not None and context_org_id is not None and int(context_org_id) != int(user_org_id):
            raise HTTPException(status_code=403, detail="Execution is outside your organization scope")
        if context.get("org_id") is not None:
            org_id = context.get("org_id")

        profiles = _load_profiles(db, org_id=org_id, enabled_only=True)
        result = _run_automation_context_validation(
            db,
            context=context,
            profiles=profiles,
            alert_ids=alert_ids,
            lookback_minutes=lookback_minutes,
            alert_limit=alert_limit,
            actor=actor,
            org_id=org_id,
            persist=bool(persist),
        )
        log_audit(
            "automation_context_validated",
            actor=actor,
            entity_type="execution",
            entity_id=str(context.get("execution_id")) if context.get("execution_id") is not None else None,
            detail=(
                f"classification={result['classification']}; correlated_alerts={result['correlated_alerts']}; "
                f"persisted={result['persisted']}"
            ),
            org_id=org_id,
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()
        return result
    finally:
        db.close()


@router.get("/alerts/correlated")
def get_correlated_alerts(
    execution_id: int,
    auto_correlate: bool = Query(default=True),
    user=Depends(require_role("analyst")),
):
    user_org_id = user.get("org_id") if isinstance(user, dict) else None
    org_id = user_org_id
    actor = _to_text(user.get("sub"), "system")
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, execution_id, alert_id, agent_id, classification, confidence, reason, matched_profile_ids, created_at
                FROM alert_execution_correlation
                WHERE execution_id=:execution_id
                  AND (:org_id IS NULL OR org_id=:org_id OR org_id IS NULL)
                ORDER BY confidence DESC, id DESC
                """
            ),
            {"execution_id": int(execution_id), "org_id": org_id},
        ).fetchall()
        if not rows and auto_correlate:
            context = _resolve_execution_context(db, int(execution_id))
            context_org_id = context.get("org_id")
            if (
                user_org_id is not None
                and context_org_id is not None
                and int(context_org_id) != int(user_org_id)
            ):
                raise HTTPException(status_code=403, detail="Execution is outside your organization scope")
            if context.get("org_id") is not None:
                org_id = context.get("org_id")
            profiles = _load_profiles(db, org_id=org_id, enabled_only=True)
            generated = _run_automation_context_validation(
                db,
                context=context,
                profiles=profiles,
                alert_ids=[],
                lookback_minutes=90,
                alert_limit=300,
                actor=actor,
                org_id=org_id,
                persist=True,
            )
            db.commit()
            return {
                "execution_id": int(execution_id),
                "count": generated["correlated_alerts"],
                "classification": generated["classification"],
                "alerts": generated["alerts"],
                "generated": True,
            }

        alerts: List[Dict[str, Any]] = []
        for row in rows:
            if not hasattr(row, "_mapping"):
                continue
            m = row._mapping
            try:
                matched_profile_ids = json.loads(str(m.get("matched_profile_ids") or "[]"))
                if not isinstance(matched_profile_ids, list):
                    matched_profile_ids = []
            except Exception:
                matched_profile_ids = []
            alerts.append(
                {
                    "id": _safe_int(m.get("id"), 0),
                    "execution_id": _safe_int(m.get("execution_id"), 0),
                    "alert_id": _to_text(m.get("alert_id")),
                    "agent_id": _to_text(m.get("agent_id")),
                    "classification": _to_text(m.get("classification"), "review_required"),
                    "confidence": _safe_int(m.get("confidence"), 0),
                    "reason": _to_text(m.get("reason")),
                    "matched_profile_ids": matched_profile_ids,
                    "created_at": utc_iso(m.get("created_at")),
                }
            )
        classifications = [item.get("classification") for item in alerts]
        summary_classification = _select_classification(classifications, default_value="review_required")
        return {
            "execution_id": int(execution_id),
            "count": len(alerts),
            "classification": summary_classification,
            "alerts": alerts,
            "generated": False,
        }
    finally:
        db.close()
