from fastapi import APIRouter, Depends
from db.database import connect
from sqlalchemy import text
from core.security import current_user

router = APIRouter(prefix="/dashboard")


@router.get("/summary")
def summary(user=Depends(current_user)):
    db = connect()
    approvals_pending = db.execute(
        text("SELECT COUNT(*) FROM approvals WHERE status='PENDING'")
    ).fetchone()[0]

    executions_total = db.execute(
        text("SELECT COUNT(*) FROM executions")
    ).fetchone()[0]

    cases_total = db.execute(
        text("SELECT COUNT(*) FROM cases")
    ).fetchone()[0]

    cases_open = db.execute(
        text("SELECT COUNT(*) FROM cases WHERE status='OPEN'")
    ).fetchone()[0]

    scheduled_total = db.execute(
        text("SELECT COUNT(*) FROM scheduled_jobs")
    ).fetchone()[0]

    scheduled_enabled = db.execute(
        text("SELECT COUNT(*) FROM scheduled_jobs WHERE enabled=true")
    ).fetchone()[0]

    mitre_heatmap = db.execute(
        text("SELECT tactic, COUNT(*) FROM mitre_alerts GROUP BY tactic")
    ).fetchall()

    db.close()

    return {
        "approvals_pending": approvals_pending,
        "executions_total": executions_total,
        "cases_total": cases_total,
        "cases_open": cases_open,
        "scheduled_total": scheduled_total,
        "scheduled_enabled": scheduled_enabled,
        "mitre_heatmap": [list(row) for row in mitre_heatmap],
    }
