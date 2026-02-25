from typing import Iterable, List, Optional

from sqlalchemy import text

from db.database import connect, rows_to_list


def case_ids_for_alert(alert_id: str, conn=None) -> List[int]:
    if not alert_id:
        return []

    close_conn = False
    if conn is None:
        conn = connect()
        close_conn = True

    try:
        rows = conn.execute(
            text(
                """
                SELECT case_id
                FROM case_alerts
                WHERE alert_id=:alert_id
                """
            ),
            {"alert_id": alert_id},
        ).fetchall()
        return [row[0] for row in rows]
    finally:
        if close_conn:
            conn.close()


def log_case_event(
    case_id: int,
    event_type: str,
    message: Optional[str] = None,
    actor: Optional[str] = None,
    alert_id: Optional[str] = None,
    approval_id: Optional[int] = None,
    execution_id: Optional[int] = None,
    action: Optional[str] = None,
    conn=None,
):
    close_conn = False
    if conn is None:
        conn = connect()
        close_conn = True

    try:
        conn.execute(
            text(
                """
                INSERT INTO case_timeline
                (case_id, event_type, message, actor, alert_id, approval_id, execution_id, action)
                VALUES
                (:case_id, :event_type, :message, :actor, :alert_id, :approval_id, :execution_id, :action)
                """
            ),
            {
                "case_id": case_id,
                "event_type": event_type,
                "message": message,
                "actor": actor,
                "alert_id": alert_id,
                "approval_id": approval_id,
                "execution_id": execution_id,
                "action": action,
            },
        )
        if close_conn:
            conn.commit()
    finally:
        if close_conn:
            conn.close()


def list_case_events(case_id: int, event_type: str | None = None, limit: int = 200):
    db = connect()
    try:
        if event_type:
            rows = db.execute(
                text(
                    """
                    SELECT
                        id,
                        event_type,
                        message,
                        actor,
                        created_at,
                        alert_id,
                        approval_id,
                        execution_id,
                        action
                    FROM case_timeline
                    WHERE case_id=:case_id AND event_type=:event_type
                    ORDER BY created_at DESC
                    LIMIT :limit
                    """
                ),
                {"case_id": case_id, "event_type": event_type, "limit": limit},
            ).fetchall()
            return rows_to_list(rows)

        rows = db.execute(
            text(
                """
                SELECT
                    id,
                    event_type,
                    message,
                    actor,
                    created_at,
                    alert_id,
                    approval_id,
                    execution_id,
                    action
                FROM case_timeline
                WHERE case_id=:case_id
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"case_id": case_id, "limit": limit},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()
