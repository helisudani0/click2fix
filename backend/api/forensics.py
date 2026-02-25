"""
Forensic Report Management API
Handles collection, storage, and retrieval of forensic evidence from endpoint actions.
"""

import json
import os
import re
from pathlib import Path
from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import text

from core.security import current_user, require_role
from core.time_utils import serialize_row
from db.database import connect

router = APIRouter(prefix="/forensics")

# Storage path for forensic reports
FORENSICS_PATH = os.getenv("C2F_FORENSICS_PATH", "./data/forensics")
MAX_FORENSICS_UPLOAD_BYTES = max(1, int(os.getenv("C2F_FORENSICS_MAX_UPLOAD_BYTES", str(25 * 1024 * 1024))))
os.makedirs(FORENSICS_PATH, exist_ok=True)


def _ensure_forensics_dir():
    """Ensure forensics storage directory exists."""
    os.makedirs(FORENSICS_PATH, exist_ok=True)


def _sanitize_filename(filename: str) -> str:
    base = os.path.basename(str(filename or "").strip()) or "report.bin"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return safe[:240] or "report.bin"


def _sanitize_action(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip())
    return safe[:80] or "forensics"


def _resolve_safe_forensics_path(stored_path: str) -> Path:
    root = Path(FORENSICS_PATH).resolve()
    candidate = Path(stored_path or "").resolve()
    if root == candidate or root in candidate.parents:
        return candidate
    raise HTTPException(status_code=400, detail="Invalid report path")


@router.post("/reports")
async def upload_forensic_report(
    file: UploadFile = File(...),
    execution_id: str = Query(...),
    action: str = Query(...),
    user=Depends(current_user),
):
    """
    Upload a forensic report from an endpoint action.
    
    Parameters:
    - file: The forensic report file (JSON)
    - execution_id: ID of the related execution
    - action: Action name that generated the report
    
    Returns:
    - Report metadata and storage location
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")
    
    if not file.filename.endswith((".json", ".txt", ".zip")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Accepted: .json, .txt, .zip"
        )
    
    _ensure_forensics_dir()
    
    try:
        # Store the file
        file_content = await file.read()
        if len(file_content) > MAX_FORENSICS_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Max allowed size is {MAX_FORENSICS_UPLOAD_BYTES} bytes.",
            )

        safe_action = _sanitize_action(action)
        safe_source_name = _sanitize_filename(file.filename)
        safe_filename = f"{safe_action}_{execution_id}_{safe_source_name}"
        file_path = os.path.join(FORENSICS_PATH, safe_filename)
        
        with open(file_path, "wb") as f:
            f.write(file_content)
        
        # Store metadata in database
        db = connect()
        try:
            db.execute(
                text(
                    """
                    INSERT INTO forensic_reports 
                    (execution_id, action, report_path, file_size, uploaded_by, uploaded_at)
                    VALUES (:execution_id, :action, :report_path, :file_size, :uploaded_by, NOW())
                    """
                ),
                {
                    "execution_id": execution_id,
                    "action": action,
                    "report_path": file_path,
                    "file_size": len(file_content),
                    "uploaded_by": user.get("sub") if isinstance(user, dict) else str(user),
                },
            )
            db.commit()
        finally:
            db.close()
        
        return {
            "ok": True,
            "execution_id": execution_id,
            "action": action,
            "filename": safe_filename,
            "file_size": len(file_content),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to upload report") from exc


@router.get("/reports")
def list_forensic_reports(
    execution_id: str | None = None,
    action: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    user=Depends(current_user),
):
    """
    List forensic reports with optional filtering.
    
    Parameters:
    - execution_id: Filter by execution ID
    - action: Filter by action name
    - limit: Maximum number of results
    
    Returns:
    - List of forensic report metadata
    """
    db = connect()
    try:
        where = []
        params = {"limit": limit}
        
        if execution_id:
            where.append("execution_id = :execution_id")
            params["execution_id"] = execution_id
        
        if action:
            where.append("action = :action")
            params["action"] = action
        
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        
        rows = db.execute(
            text(
                f"""
                SELECT
                    id,
                    execution_id,
                    action,
                    file_size,
                    uploaded_by,
                    uploaded_at
                FROM forensic_reports
                {where_sql}
                ORDER BY uploaded_at DESC
                LIMIT :limit
                """
            ),
            params,
        ).fetchall()
        
        return [serialize_row(row) for row in rows]
    finally:
        db.close()


@router.get("/reports/{report_id}")
def get_forensic_report(report_id: int, user=Depends(current_user)):
    """
    Retrieve a specific forensic report by ID.
    
    Parameters:
    - report_id: The forensic report ID
    
    Returns:
    - Forensic report content with metadata
    """
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT
                    id,
                    execution_id,
                    action,
                    report_path,
                    file_size,
                    uploaded_by,
                    uploaded_at
                FROM forensic_reports
                WHERE id = :id
                """
            ),
            {"id": report_id},
        ).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        
        row_data = serialize_row(row) or {}
        report_path = row_data.get("report_path")
        report_meta = dict(row_data)
        report_meta.pop("report_path", None)
        
        # Read report content
        report_content = None
        if report_path:
            try:
                safe_path = _resolve_safe_forensics_path(str(report_path))
                if not safe_path.exists():
                    raise FileNotFoundError("Report file missing")
                with safe_path.open("r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    # Try to parse as JSON
                    try:
                        report_content = json.loads(content)
                    except json.JSONDecodeError:
                        report_content = content
            except Exception:
                report_content = {"error": "Could not read report file"}
        
        return {
            "metadata": report_meta,
            "content": report_content,
        }
    finally:
        db.close()


@router.get("/summary")
def get_forensic_summary(
    days: int = Query(default=7, ge=1, le=90),
    user=Depends(current_user),
):
    """
    Get forensic collection summary for the last N days.
    
    Parameters:
    - days: Number of days to include in summary
    
    Returns:
    - Summary statistics and top actions
    """
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    action,
                    COUNT(*) as count,
                    AVG(file_size) as avg_size,
                    MAX(uploaded_at) as last_uploaded
                FROM forensic_reports
                WHERE uploaded_at >= NOW() - (:days || ' days')::interval
                GROUP BY action
                ORDER BY count DESC
                """
            ),
            {"days": days},
        ).fetchall()
        
        total = db.execute(
            text(
                """
                SELECT COUNT(*) as total
                FROM forensic_reports
                WHERE uploaded_at >= NOW() - (:days || ' days')::interval
                """
            ),
            {"days": days},
        ).fetchone()
        
        return {
            "period_days": days,
            "total_reports": total[0] if total else 0,
            "by_action": [serialize_row(row) for row in rows],
        }
    finally:
        db.close()


@router.delete("/reports/{report_id}")
def delete_forensic_report(report_id: int, user=Depends(require_role("admin"))):
    """
    Delete a forensic report (physically remove the file).
    
    Parameters:
    - report_id: The forensic report ID to delete
    
    Returns:
    - Confirmation of deletion
    """
    db = connect()
    try:
        row = db.execute(
            text("SELECT report_path FROM forensic_reports WHERE id = :id"),
            {"id": report_id},
        ).fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        
        report_path = row[0]
        
        # Delete physical file
        if report_path:
            try:
                safe_path = _resolve_safe_forensics_path(str(report_path))
                if safe_path.exists():
                    os.remove(str(safe_path))
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to delete report file"
                ) from exc
        
        # Delete database record
        db.execute(
            text("DELETE FROM forensic_reports WHERE id = :id"),
            {"id": report_id},
        )
        db.commit()
        
        return {"ok": True, "report_id": report_id, "message": "Report deleted"}
    finally:
        db.close()
