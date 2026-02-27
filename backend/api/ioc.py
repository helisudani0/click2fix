import json
from datetime import datetime
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException
from sqlalchemy import text

from db.database import connect

router = APIRouter(prefix="/ioc")

_VERDICT_RANK = {
    "unknown": 0,
    "low_confidence": 1,
    "suspicious": 2,
    "malicious": 3,
}


def _safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _safe_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _parse_details(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _prefer_verdict(existing: str, incoming: str) -> str:
    existing_l = str(existing or "unknown").strip().lower() or "unknown"
    incoming_l = str(incoming or "unknown").strip().lower() or "unknown"
    if _VERDICT_RANK.get(incoming_l, 0) > _VERDICT_RANK.get(existing_l, 0):
        return incoming_l
    return existing_l


def _aggregate_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_key: Dict[str, Dict[str, Any]] = {}
    for row in records:
        ioc = str(row.get("ioc") or "").strip()
        ioc_type = str(row.get("ioc_type") or "").strip().lower()
        if not ioc:
            continue
        key = f"{ioc_type}::{ioc.lower()}"
        item = by_key.get(key)
        row_score = _safe_int(row.get("score"), 0)
        row_verdict = str(row.get("verdict") or "unknown").strip().lower() or "unknown"
        row_source = str(row.get("source") or "").strip()
        row_created = str(row.get("created_at") or "")
        if not item:
            by_key[key] = {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "max_score": row_score,
                "verdict": row_verdict,
                "sources": [row_source] if row_source else [],
                "first_seen": row_created or None,
                "last_seen": row_created or None,
                "evidence_count": 1,
            }
            continue
        item["max_score"] = max(_safe_int(item.get("max_score"), 0), row_score)
        item["verdict"] = _prefer_verdict(item.get("verdict"), row_verdict)
        if row_source and row_source not in item["sources"]:
            item["sources"].append(row_source)
        item["evidence_count"] = _safe_int(item.get("evidence_count"), 0) + 1
        first_seen = str(item.get("first_seen") or "")
        last_seen = str(item.get("last_seen") or "")
        if row_created:
            if not first_seen or row_created < first_seen:
                item["first_seen"] = row_created
            if not last_seen or row_created > last_seen:
                item["last_seen"] = row_created

    indicators = list(by_key.values())
    indicators.sort(
        key=lambda item: (
            -_safe_int(item.get("max_score"), 0),
            str(item.get("ioc_type") or ""),
            str(item.get("ioc") or ""),
        )
    )

    high_confidence = [
        item
        for item in indicators
        if _safe_int(item.get("max_score"), 0) >= 85
        or str(item.get("verdict") or "").lower() == "malicious"
    ]
    suspicious = [
        item
        for item in indicators
        if _safe_int(item.get("max_score"), 0) >= 55
        or str(item.get("verdict") or "").lower() in {"suspicious", "malicious"}
    ]
    summary = {
        "total_records": len(records),
        "unique_indicators": len(indicators),
        "high_confidence_indicators": len(high_confidence),
        "suspicious_indicators": len(suspicious),
        "top_indicator": indicators[0] if indicators else None,
    }
    return {"indicators": indicators, "summary": summary}


@router.get("/{alert_id}")
def iocs(alert_id: str, include_summary: bool = False):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT ioc, ioc_type, source, score, verdict, details, created_at
                FROM ioc_enrichments
                WHERE alert_id=:alert_id
                ORDER BY score DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()

        records: List[Dict[str, Any]] = []
        for row in rows:
            if hasattr(row, "_mapping"):
                m = row._mapping
                record = {
                    "ioc": _safe(m.get("ioc")),
                    "ioc_type": _safe(m.get("ioc_type")),
                    "source": _safe(m.get("source")),
                    "score": _safe(m.get("score")),
                    "verdict": _safe(m.get("verdict")),
                    "details": _parse_details(m.get("details")),
                    "created_at": _safe(m.get("created_at")),
                }
            elif isinstance(row, (list, tuple)):
                row_values = [_safe(value) for value in row]
                record = {
                    "ioc": row_values[0] if len(row_values) > 0 else None,
                    "ioc_type": row_values[1] if len(row_values) > 1 else None,
                    "source": row_values[2] if len(row_values) > 2 else None,
                    "score": row_values[3] if len(row_values) > 3 else None,
                    "verdict": row_values[4] if len(row_values) > 4 else None,
                    "details": _parse_details(row_values[5] if len(row_values) > 5 else None),
                    "created_at": row_values[6] if len(row_values) > 6 else None,
                }
            else:
                record = {
                    "ioc": str(row),
                    "ioc_type": None,
                    "source": None,
                    "score": None,
                    "verdict": None,
                    "details": {},
                    "created_at": None,
                }
            records.append(record)

        if not include_summary:
            return records

        aggregate = _aggregate_records(records)
        return {
            "records": records,
            "indicators": aggregate["indicators"],
            "summary": aggregate["summary"],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to load IOC enrichment data") from exc
    finally:
        db.close()
