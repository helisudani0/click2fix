from fastapi import APIRouter
from db.database import connect
from sqlalchemy import text

router = APIRouter(prefix="/mitre")


def _safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


@router.get("/alert/{alert_id}")
def for_alert(alert_id: str):

    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT tactic, technique, technique_id, confidence, source, mapping_rank
                FROM mitre_alerts
                WHERE alert_id=:alert_id
                ORDER BY confidence DESC NULLS LAST, mapping_rank ASC NULLS LAST, id ASC
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()
        out = []
        for idx, row in enumerate(rows):
            out.append(
                {
                    "tactic": row[0],
                    "technique": row[1],
                    "technique_id": row[2],
                    "confidence": _safe_int(row[3], 0),
                    "source": row[4],
                    "mapping_rank": _safe_int(row[5], idx + 1),
                    "is_primary": idx == 0,
                }
            )
        return out
    finally:
        db.close()


@router.get("/heatmap")
def heatmap():

    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    tactic,
                    COUNT(*) AS total,
                    AVG(COALESCE(confidence, 0)) AS avg_confidence
                FROM mitre_alerts
                GROUP BY tactic
                ORDER BY total DESC, tactic ASC
                """
            )
        ).fetchall()
        return [
            {
                "tactic": row[0],
                "count": _safe_int(row[1], 0),
                "avg_confidence": round(float(row[2] or 0), 2),
            }
            for row in rows
        ]
    finally:
        db.close()
