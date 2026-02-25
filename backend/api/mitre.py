from fastapi import APIRouter
from db.database import connect, rows_to_list
from sqlalchemy import text

router = APIRouter(prefix="/mitre")

@router.get("/alert/{alert_id}")
def for_alert(alert_id: str):

    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT tactic, technique, technique_id
                FROM mitre_alerts
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        )

        return rows_to_list(rows.fetchall())
    finally:
        db.close()


@router.get("/heatmap")
def heatmap():

    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT tactic, COUNT(*) FROM mitre_alerts
                GROUP BY tactic
                """
            )
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()
