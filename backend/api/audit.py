import csv
import io

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import text

from core.security import require_role
from core.time_utils import parse_utc_datetime
from db.database import connect, row_to_list


router = APIRouter(prefix="/audit")


@router.get("")
def list_audit(
    q: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 200,
    user=Depends(require_role("admin")),
):
    db = connect()
    try:
        stmt = """
            SELECT id, actor, action, entity_type, entity_id, detail, org_id, ip_address, created_at
            FROM audit_logs
            WHERE 1=1
        """
        params = {}
        if q:
            stmt += (
                " AND ("
                "COALESCE(actor, '') ILIKE :q OR "
                "COALESCE(action, '') ILIKE :q OR "
                "COALESCE(entity_type, '') ILIKE :q OR "
                "COALESCE(CAST(entity_id AS TEXT), '') ILIKE :q OR "
                "COALESCE(CAST(detail AS TEXT), '') ILIKE :q OR "
                "COALESCE(ip_address, '') ILIKE :q"
                ")"
            )
            params["q"] = f"%{q}%"
        if actor:
            stmt += " AND COALESCE(actor, '') ILIKE :actor"
            params["actor"] = f"%{actor}%"
        if action:
            stmt += " AND COALESCE(action, '') ILIKE :action"
            params["action"] = f"%{action}%"
        if entity_type:
            stmt += " AND COALESCE(entity_type, '') ILIKE :entity_type"
            params["entity_type"] = f"%{entity_type}%"
        if entity_id:
            stmt += " AND COALESCE(CAST(entity_id AS TEXT), '') ILIKE :entity_id"
            params["entity_id"] = f"%{entity_id}%"
        start_dt = parse_utc_datetime(start) if start else None
        end_dt = parse_utc_datetime(end) if end else None
        if start_dt:
            stmt += " AND created_at >= :start"
            params["start"] = start_dt.replace(tzinfo=None)
        if end_dt:
            stmt += " AND created_at <= :end"
            params["end"] = end_dt.replace(tzinfo=None)
        stmt += " ORDER BY created_at DESC LIMIT :limit"
        params["limit"] = max(1, min(limit, 20000))
        rows = db.execute(text(stmt), params).fetchall()
        return [row_to_list(row) for row in rows]
    finally:
        db.close()


@router.get("/export")
def export_audit(
    format: str = "csv",
    q: str | None = None,
    actor: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    start: str | None = None,
    end: str | None = None,
    limit: int = 5000,
    user=Depends(require_role("admin")),
):
    rows = list_audit(
        q=q,
        actor=actor,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        start=start,
        end=end,
        limit=limit,
        user=user,
    )
    if format == "json":
        return {"events": rows}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "actor",
            "action",
            "entity_type",
            "entity_id",
            "detail",
            "org_id",
            "ip_address",
            "created_at",
        ]
    )
    for row in rows:
        writer.writerow(row)
    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
    )
