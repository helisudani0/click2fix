import json
from datetime import datetime
from typing import Iterable

from sqlalchemy import text

from core.enrichment import IOCEnricher
from core.mitre_mapper import MitreMapper
from core.time_utils import parse_utc_datetime, utc_now_naive
from db.database import connect


enricher = IOCEnricher()
mapper = MitreMapper()


def _extract_alert_id(alert: dict):
    return alert.get("id") or alert.get("alert_id")


def _parse_event_time(alert: dict) -> datetime:
    event_time = alert.get("@timestamp") or alert.get("timestamp") or alert.get("time")
    if isinstance(event_time, datetime):
        return event_time
    parsed = parse_utc_datetime(event_time)
    if parsed is None:
        return utc_now_naive()
    return parsed.replace(tzinfo=None)


def store_alerts(alerts: Iterable[dict]) -> int:
    db = connect()
    stored = 0
    try:
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            alert_id = _extract_alert_id(alert)
            if not alert_id:
                continue

            try:
                enricher.enrich_alert(str(alert_id), alert)
            except Exception as exc:
                print(f"Failed to enrich alert {alert_id}: {exc}")

            primary_mitre = None
            try:
                mitre_matches = []
                if hasattr(mapper, "map_alerts"):
                    mitre_matches = mapper.map_alerts(alert) or []
                if not mitre_matches:
                    fallback = mapper.map_alert(alert)
                    if fallback:
                        mitre_matches = [fallback]

                if mitre_matches:
                    primary_mitre = mitre_matches[0]

                for rank_idx, match in enumerate(mitre_matches, start=1):
                    tactic = str(match.get("tactic") or "").strip()
                    technique = str(match.get("technique") or "").strip()
                    technique_id = str(match.get("technique_id") or "").strip().upper()
                    confidence = int(match.get("confidence") or 0)
                    source = str(match.get("source") or "").strip() or None
                    if not tactic and not technique and not technique_id:
                        continue

                    existing = db.execute(
                        text(
                            """
                            SELECT id, confidence, source, mapping_rank
                            FROM mitre_alerts
                            WHERE alert_id=:alert_id
                              AND COALESCE(technique_id, '')=:technique_id
                              AND COALESCE(tactic, '')=:tactic
                              AND COALESCE(technique, '')=:technique
                            LIMIT 1
                            """
                        ),
                        {
                            "alert_id": alert_id,
                            "technique_id": technique_id,
                            "tactic": tactic,
                            "technique": technique,
                        },
                    ).fetchone()
                    if existing:
                        existing_id = existing[0]
                        try:
                            existing_confidence = int(existing[1] or 0)
                        except Exception:
                            existing_confidence = 0
                        existing_source = str(existing[2] or "").strip() or None
                        try:
                            existing_rank = int(existing[3]) if existing[3] is not None else None
                        except Exception:
                            existing_rank = None

                        merged_confidence = max(existing_confidence, confidence)
                        merged_source = existing_source or source
                        if existing_rank is not None and existing_rank > 0:
                            merged_rank = min(existing_rank, rank_idx)
                        else:
                            merged_rank = rank_idx

                        if (
                            merged_confidence != existing_confidence
                            or merged_source != existing_source
                            or merged_rank != existing_rank
                        ):
                            db.execute(
                                text(
                                    """
                                    UPDATE mitre_alerts
                                    SET confidence=:confidence, source=:source, mapping_rank=:mapping_rank
                                    WHERE id=:id
                                    """
                                ),
                                {
                                    "id": existing_id,
                                    "confidence": merged_confidence,
                                    "source": merged_source,
                                    "mapping_rank": merged_rank,
                                },
                            )
                        continue

                    db.execute(
                        text(
                            """
                            INSERT INTO mitre_alerts
                            (alert_id, tactic, technique, technique_id, confidence, source, mapping_rank)
                            VALUES (:alert_id, :tactic, :technique, :technique_id, :confidence, :source, :mapping_rank)
                            """
                        ),
                        {
                            "alert_id": alert_id,
                            "tactic": tactic,
                            "technique": technique,
                            "technique_id": technique_id,
                            "confidence": confidence,
                            "source": source,
                            "mapping_rank": rank_idx,
                        },
                    )
            except Exception as exc:
                print(f"Failed to map MITRE for alert {alert_id}: {exc}")

            try:
                rule = alert.get("rule") or {}
                agent = alert.get("agent") or {}
                event_dt = _parse_event_time(alert)

                result = db.execute(
                    text(
                        """
                        INSERT INTO alerts_store
                        (alert_id, agent_id, agent_name, rule_id, rule_description, rule_level, tactic, technique_id, event_time, raw_json)
                        VALUES
                        (:alert_id, :agent_id, :agent_name, :rule_id, :rule_description, :rule_level, :tactic, :technique_id, :event_time, :raw_json)
                        ON CONFLICT (alert_id) DO NOTHING
                        """
                    ),
                    {
                        "alert_id": str(alert_id),
                        "agent_id": agent.get("id") or agent.get("agent_id"),
                        "agent_name": agent.get("name") or agent.get("hostname"),
                        "rule_id": rule.get("id"),
                        "rule_description": rule.get("description"),
                        "rule_level": rule.get("level") if isinstance(rule, dict) else None,
                        "tactic": (primary_mitre["tactic"] if primary_mitre else None),
                        "technique_id": (
                            primary_mitre["technique_id"] if primary_mitre else None
                        ),
                        "event_time": event_dt,
                        "raw_json": json.dumps(alert, default=str),
                    },
                )
                stored += result.rowcount or 0
            except Exception as exc:
                print(f"Failed to store alert {alert_id}: {exc}")

        db.commit()
        return stored
    finally:
        db.close()
