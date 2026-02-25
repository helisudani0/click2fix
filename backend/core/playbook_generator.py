from __future__ import annotations

import json
import os
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import text

from core.actions import list_actions
from core.time_utils import utc_iso_now, utc_now
from db.database import connect


def _collect_actions() -> Dict[str, Dict]:
    return {a["id"]: a for a in list_actions() if a.get("id")}


def _safe_name(name: str) -> str:
    cleaned = "".join(c for c in name if c.isalnum() or c in ("-", "_", ".")).strip()
    return cleaned or f"playbook_{int(utc_now().timestamp())}"


def _walk_values(obj, keys: Iterable[str]) -> Optional[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and v is not None:
                return str(v)
            found = _walk_values(v, keys)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _walk_values(item, keys)
            if found is not None:
                return found
    return None


def _find_pid(payload: dict) -> Optional[str]:
    keys = {
        "pid",
        "process_id",
        "processId",
        "process.pid",
        "win.eventdata.ProcessId",
    }
    value = _walk_values(payload, keys)
    if value and value.isdigit():
        return value
    return None


def _find_ips(iocs: List[Tuple]) -> List[str]:
    ips: List[str] = []
    for row in iocs:
        ioc, ioc_type, score, verdict = row
        if not ioc:
            continue
        if ioc_type and str(ioc_type).lower() in {"ip", "ipv4", "ipv6"}:
            ips.append(str(ioc))
    return ips


def _load_alert(alert_id: str) -> Optional[Dict]:
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT alert_id, agent_id, agent_name, rule_id, rule_description, rule_level, raw_json
                FROM alerts_store
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchone()
        if not row:
            return None
        raw_json = {}
        if row[6]:
            try:
                raw_json = json.loads(row[6])
            except json.JSONDecodeError:
                raw_json = {}
        return {
            "alert_id": row[0],
            "agent_id": row[1],
            "agent_name": row[2],
            "rule_id": row[3],
            "rule_description": row[4],
            "rule_level": row[5],
            "raw_json": raw_json,
        }
    finally:
        db.close()


def _load_iocs(alert_id: str) -> List[Tuple]:
    db = connect()
    try:
        return db.execute(
            text(
                """
                SELECT ioc, ioc_type, score, verdict
                FROM ioc_enrichments
                WHERE alert_id=:alert_id
                ORDER BY score DESC NULLS LAST
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()
    finally:
        db.close()


def _load_case_alerts(case_id: int) -> List[str]:
    db = connect()
    try:
        rows = db.execute(
            text("SELECT alert_id FROM case_alerts WHERE case_id=:case_id"),
            {"case_id": case_id},
        ).fetchall()
        return [row[0] for row in rows if row and row[0]]
    finally:
        db.close()


def _heuristic_steps(
    alert: Dict,
    iocs: List[Tuple],
    actions: Dict[str, Dict],
) -> List[Dict]:
    steps: List[Dict] = []
    rule_level = alert.get("rule_level")
    rule_desc = (alert.get("rule_description") or "").lower()
    raw_json = alert.get("raw_json") or {}

    ip_candidates = _find_ips(iocs)
    if ip_candidates and "firewall-drop" in actions:
        steps.append(
            {
                "id": "block_ip",
                "action": "firewall-drop",
                "args": {"ip": ip_candidates[0]},
                "reason": "IOC IP detected",
            }
        )

    pid = _find_pid(raw_json)
    if pid and "kill-process" in actions:
        steps.append(
            {
                "id": "kill_process",
                "action": "kill-process",
                "args": {"pid": pid},
                "reason": "Suspicious process detected",
            }
        )

    if (
        ("vulnerability" in rule_desc or "cve" in rule_desc or "outdated" in rule_desc)
        and "patch-linux" in actions
    ):
        steps.append(
            {
                "id": "patch_system",
                "action": "patch-linux",
                "args": {},
                "reason": "Vulnerability or patching rule",
            }
        )

    if rule_level is not None and rule_level >= 12 and "patch-linux" in actions:
        steps.append(
            {
                "id": "patch_system_high",
                "action": "patch-linux",
                "args": {},
                "reason": "High severity alert",
            }
        )

    if not steps and actions:
        fallback = next(iter(actions.keys()))
        steps.append(
            {
                "id": "default_action",
                "action": fallback,
                "args": {},
                "reason": "Fallback action",
            }
        )

    return steps


def generate_playbook(
    alert_id: Optional[str] = None,
    case_id: Optional[int] = None,
) -> Dict:
    actions = _collect_actions()
    alert = None
    target_alert_ids: List[str] = []

    if alert_id:
        alert = _load_alert(alert_id)
        if alert:
            target_alert_ids = [alert_id]
    elif case_id:
        target_alert_ids = _load_case_alerts(case_id)
        if target_alert_ids:
            alert = _load_alert(target_alert_ids[0])

    if not alert:
        return {
            "name": "Generated Playbook",
            "description": "No alert context available",
            "generated_at": utc_iso_now(),
            "source": {"alert_id": alert_id, "case_id": case_id},
            "steps": [],
        }

    iocs = _load_iocs(alert.get("alert_id"))
    steps = _heuristic_steps(alert, iocs, actions)

    name = f"Auto-Response-{alert.get('alert_id')}"
    description = f"Generated playbook for rule {alert.get('rule_description') or alert.get('rule_id')}"

    return {
        "name": name,
        "description": description,
        "generated_at": utc_iso_now(),
        "source": {
            "alert_id": alert.get("alert_id"),
            "case_id": case_id,
            "agent_id": alert.get("agent_id"),
            "agent_name": alert.get("agent_name"),
            "rule_id": alert.get("rule_id"),
            "rule_description": alert.get("rule_description"),
            "rule_level": alert.get("rule_level"),
            "related_alerts": target_alert_ids,
        },
        "steps": steps,
    }


def save_playbook(path: str, payload: Dict) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return path


def build_playbook_path(base_dir: str, name: str) -> str:
    safe = _safe_name(name)
    if not safe.endswith(".json"):
        safe += ".json"
    return os.path.join(base_dir, safe)
