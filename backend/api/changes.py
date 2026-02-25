from collections.abc import Mapping

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text

from core.audit import log_audit
from core.security import require_role
from core.time_utils import to_json_safe, utc_now_naive
from db.database import connect


router = APIRouter(prefix="/changes")


_CHANGE_COLUMNS = [
    "id",
    "title",
    "action_id",
    "target",
    "risk_score",
    "impact",
    "requested_by",
    "status",
    "created_at",
    "approved_by",
    "approved_at",
    "scheduled_for",
    "executed_at",
]


def _json_safe(value):
    return to_json_safe(value)


def _serialize_mapping_row(row):
    if row is None:
        return {}
    if isinstance(row, Mapping):
        return {key: _json_safe(row.get(key)) for key in _CHANGE_COLUMNS}
    if hasattr(row, "_mapping"):
        mapping = row._mapping
        return {key: _json_safe(mapping.get(key)) for key in _CHANGE_COLUMNS}
    if isinstance(row, dict):
        return {key: _json_safe(row.get(key)) for key in _CHANGE_COLUMNS}
    if isinstance(row, (list, tuple)):
        return {
            key: _json_safe(row[idx] if idx < len(row) else None)
            for idx, key in enumerate(_CHANGE_COLUMNS)
        }
    return {}


@router.post("")
async def create_change(request: Request, user=Depends(require_role("analyst"))):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    title = body.get("title")
    if not title:
        raise HTTPException(status_code=400, detail="title is required")

    db = connect()
    try:
        result = db.execute(
            text(
                """
                INSERT INTO change_requests
                (title, description, action_id, target, justification, risk_score, impact, requested_by, status, scheduled_for)
                VALUES (:title, :description, :action_id, :target, :justification, :risk_score, :impact, :requested_by, :status, :scheduled_for)
                RETURNING id
                """
            ),
            {
                "title": title,
                "description": body.get("description"),
                "action_id": body.get("action_id"),
                "target": body.get("target"),
                "justification": body.get("justification"),
                "risk_score": body.get("risk_score"),
                "impact": body.get("impact"),
                "requested_by": user.get("sub"),
                "status": "PROPOSED",
                "scheduled_for": body.get("scheduled_for"),
            },
        )
        change_id = result.scalar()
        log_audit(
            "change_requested",
            actor=user.get("sub"),
            entity_type="change",
            entity_id=str(change_id),
            detail=title,
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()
        return {"id": change_id, "status": "proposed"}
    finally:
        db.close()


@router.get("")
def list_changes(status: str | None = None, user=Depends(require_role("analyst"))):
    db = connect()
    try:
        stmt = """
            SELECT id, title, action_id, target, risk_score, impact, requested_by, status, created_at, approved_by, approved_at, scheduled_for, executed_at
            FROM change_requests
            WHERE 1=1
        """
        params = {}
        if status:
            stmt += " AND status=:status"
            params["status"] = status
        stmt += " ORDER BY created_at DESC"
        result = db.execute(text(stmt), params)
        if hasattr(result, "mappings"):
            rows = result.mappings().all()
        else:
            rows = result.fetchall()
        return [_serialize_mapping_row(row) for row in rows]
    finally:
        db.close()


@router.post("/{change_id}/approve")
def approve_change(change_id: int, request: Request, user=Depends(require_role("admin"))):
    db = connect()
    try:
        db.execute(
            text(
                """
                UPDATE change_requests
                SET status='APPROVED', approved_by=:approved_by, approved_at=:approved_at
                WHERE id=:id
                """
            ),
            {
                "approved_by": user.get("sub"),
                "approved_at": utc_now_naive(),
                "id": change_id,
            },
        )
        log_audit(
            "change_approved",
            actor=user.get("sub"),
            entity_type="change",
            entity_id=str(change_id),
            detail="Change approved",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()
        return {"status": "approved"}
    finally:
        db.close()


@router.post("/{change_id}/close")
def close_change(change_id: int, request: Request, user=Depends(require_role("admin"))):
    db = connect()
    try:
        db.execute(
            text(
                """
                UPDATE change_requests
                SET status='COMPLETED', executed_at=:executed_at
                WHERE id=:id
                """
            ),
            {"executed_at": utc_now_naive(), "id": change_id},
        )
        log_audit(
            "change_closed",
            actor=user.get("sub"),
            entity_type="change",
            entity_id=str(change_id),
            detail="Change closed",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
            conn=db,
        )
        db.commit()
        return {"status": "completed"}
    finally:
        db.close()
