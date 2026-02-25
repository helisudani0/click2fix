from typing import Optional

from sqlalchemy import text

from db.database import connect


def log_audit(
    action: str,
    actor: Optional[str],
    entity_type: str,
    entity_id: Optional[str] = None,
    detail: Optional[str] = None,
    org_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    conn=None,
):
    owns_conn = False
    db = conn
    if db is None:
        db = connect()
        owns_conn = True

    try:
        db.execute(
            text(
                """
                INSERT INTO audit_logs
                (actor, action, entity_type, entity_id, detail, org_id, ip_address)
                VALUES (:actor, :action, :entity_type, :entity_id, :detail, :org_id, :ip_address)
                """
            ),
            {
                "actor": actor,
                "action": action,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "detail": detail,
                "org_id": org_id,
                "ip_address": ip_address,
            },
        )
        if owns_conn:
            db.commit()
    finally:
        if owns_conn:
            db.close()
