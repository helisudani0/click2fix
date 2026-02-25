import hashlib
import os
import uuid

import csv
import io

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, Request
from fastapi.responses import FileResponse, Response
from db.database import connect, row_to_list, rows_to_list
from core.case_timeline import log_case_event, list_case_events
from core.forensic_integrity import (
    verify_attachment_integrity,
    verify_evidence_integrity,
)
from core.settings import SETTINGS
from sqlalchemy import text, bindparam
from core.security import current_user
from core.audit import log_audit


router = APIRouter(prefix="/cases")
ATTACHMENTS_ROOT = (
    SETTINGS.get("attachments_path")
    if isinstance(SETTINGS, dict) and SETTINGS.get("attachments_path")
    else "./data/attachments"
)
EVIDENCE_ROOT = (
    SETTINGS.get("evidence_path")
    if isinstance(SETTINGS, dict) and SETTINGS.get("evidence_path")
    else "./data/evidence"
)
_INTEGRITY_CFG = (
    SETTINGS.get("forensics_integrity", {})
    if isinstance(SETTINGS, dict) and isinstance(SETTINGS.get("forensics_integrity", {}), dict)
    else {}
)


def _to_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


VERIFY_INTEGRITY_ON_DOWNLOAD = _to_bool(_INTEGRITY_CFG.get("verify_on_download", True), True)
VERIFY_INTEGRITY_ON_LOCK = _to_bool(_INTEGRITY_CFG.get("verify_on_lock", True), True)


def _case_dir(case_id: int) -> str:
    return os.path.join(ATTACHMENTS_ROOT, f"case_{case_id}")


def _evidence_dir(case_id: int) -> str:
    return os.path.join(EVIDENCE_ROOT, f"case_{case_id}")

@router.post("")
def create_case(
    title: str,
    description: str,
    request: Request,
    user=Depends(current_user)
):

    db = connect()
    try:
        result = db.execute(
            text(
                """
                INSERT INTO cases (title, description, status, owner)
                VALUES (:title, :description, 'OPEN', :owner)
                RETURNING id
                """
            ),
            {"title": title, "description": description, "owner": user["sub"]},
        )

        case_id = result.scalar()
        log_case_event(
            case_id,
            "case_created",
            message=f"Case created: {title}",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "case_created",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(case_id),
            detail=title,
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"id": case_id}
    finally:
        db.close()


@router.post("/{id}/alerts")
def attach_alert(
    id: int,
    alert_id: str,
    request: Request,
    user=Depends(current_user)
):

    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO case_alerts (case_id, alert_id)
                VALUES (:case_id, :alert_id)
                """
            ),
            {"case_id": id, "alert_id": alert_id},
        )

        log_case_event(
            id,
            "alert_attached",
            message=f"Alert attached: {alert_id}",
            actor=user["sub"],
            alert_id=alert_id,
            conn=db,
        )
        db.commit()
        log_audit(
            "alert_attached",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=f"alert_id={alert_id}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
    finally:
        db.close()


@router.get("")
def list_cases(user=Depends(current_user)):

    db = connect()
    try:
        rows = db.execute(
            text("SELECT * FROM cases ORDER BY created_at DESC")
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()


@router.get("/{id}")
def case_detail(id: int, user=Depends(current_user)):

    db = connect()
    try:
        case = db.execute(
            text("SELECT * FROM cases WHERE id=:id"),
            {"id": id},
        ).fetchone()

        alerts = db.execute(
            text("SELECT alert_id FROM case_alerts WHERE case_id=:id"),
            {"id": id},
        ).fetchall()

        notes = db.execute(
            text("SELECT author, note, created_at FROM case_notes WHERE case_id=:id"),
            {"id": id},
        ).fetchall()

        risk = db.execute(
            text(
                """
                SELECT risk_score, impact, updated_by, updated_at
                FROM case_risk
                WHERE case_id=:id
                """
            ),
            {"id": id},
        ).fetchone()

        return {
            "case": row_to_list(case),
            "alerts": rows_to_list(alerts),
            "notes": rows_to_list(notes),
            "risk": row_to_list(risk),
        }
    finally:
        db.close()


@router.get("/{id}/timeline")
def case_timeline(
    id: int,
    event_type: str | None = None,
    limit: int = 200,
    user=Depends(current_user)
):
    return list_case_events(id, event_type=event_type, limit=limit)


@router.get("/{id}/timeline/export")
def export_timeline(
    id: int,
    event_type: str | None = None,
    format: str = "csv",
    user=Depends(current_user)
):
    rows = list_case_events(id, event_type=event_type, limit=1000)

    if format == "json":
        return {"case_id": id, "events": rows}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "event_type",
            "message",
            "actor",
            "created_at",
            "alert_id",
            "approval_id",
            "execution_id",
            "action",
        ]
    )
    for row in rows:
        writer.writerow(list(row))

    csv_data = output.getvalue()
    filename = f"case_{id}_timeline.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/{id}/notes")
def add_note(
    id: int,
    note: str,
    request: Request,
    user=Depends(current_user)
):

    db = connect()
    try:
        db.execute(
            text(
                """
                INSERT INTO case_notes (case_id, author, note)
                VALUES (:case_id, :author, :note)
                """
            ),
            {"case_id": id, "author": user["sub"], "note": note},
        )

        log_case_event(
            id,
            "note_added",
            message=note,
            actor=user["sub"],
            conn=db,
        )

        db.commit()
        log_audit(
            "note_added",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=note[:200],
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
    finally:
        db.close()




@router.post("/{id}/attachments")
def upload_attachment(
    id: int,
    request: Request,
    file: UploadFile = File(...),
    user=Depends(current_user)
):
    os.makedirs(_case_dir(id), exist_ok=True)
    safe_name = os.path.basename(file.filename or "attachment.bin")
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    stored_path = os.path.join(_case_dir(id), stored_name)

    sha256 = hashlib.sha256()
    size = 0
    with open(stored_path, "wb") as out:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            sha256.update(chunk)
            size += len(chunk)

    db = connect()
    try:
        result = db.execute(
            text(
                """
                INSERT INTO case_attachments
                (case_id, filename, stored_path, content_type, size, sha256, uploaded_by)
                VALUES (:case_id, :filename, :stored_path, :content_type, :size, :sha256, :uploaded_by)
                RETURNING id
                """
            ),
            {
                "case_id": id,
                "filename": safe_name,
                "stored_path": stored_name,
                "content_type": file.content_type,
                "size": size,
                "sha256": sha256.hexdigest(),
                "uploaded_by": user["sub"],
            },
        )
        attachment_id = result.scalar()
        log_case_event(
            id,
            "attachment_added",
            message=f"Attachment uploaded: {safe_name} ({size} bytes)",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "attachment_added",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=safe_name,
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"id": attachment_id, "filename": safe_name}
    finally:
        db.close()


@router.get("/{id}/attachments")
def list_attachments(id: int, user=Depends(current_user)):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, filename, content_type, size, sha256, uploaded_by, created_at
                FROM case_attachments
                WHERE case_id=:case_id
                ORDER BY created_at DESC
                """
            ),
            {"case_id": id},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()


@router.get("/{id}/attachments/{attachment_id}")
def download_attachment(id: int, attachment_id: int, request: Request, user=Depends(current_user)):
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT filename, stored_path, content_type, sha256
                FROM case_attachments
                WHERE id=:id AND case_id=:case_id
                """
            ),
            {"id": attachment_id, "case_id": id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")
        filename, stored_name, content_type, expected_sha256 = row
        if VERIFY_INTEGRITY_ON_DOWNLOAD:
            integrity = verify_attachment_integrity(
                case_id=id,
                stored_path=str(stored_name or ""),
                expected_sha256=str(expected_sha256 or ""),
            )
            if not integrity.get("ok"):
                log_audit(
                    "attachment_integrity_failed",
                    actor=user.get("sub") if isinstance(user, dict) else str(user),
                    entity_type="case_attachment",
                    entity_id=str(attachment_id),
                    detail=str(integrity),
                    org_id=user.get("org_id") if isinstance(user, dict) else None,
                    ip_address=request.client.host if request.client else None,
                )
                raise HTTPException(
                    status_code=409,
                    detail="Attachment integrity verification failed",
                )
        file_path = os.path.join(_case_dir(id), stored_name)
        return FileResponse(
            file_path,
            media_type=content_type or "application/octet-stream",
            filename=filename,
        )
    finally:
        db.close()


@router.get("/{id}/attack-path")
def attack_path(id: int, user=Depends(current_user)):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    ct.alert_id,
                    ct.created_at,
                    ma.tactic,
                    ma.technique,
                    ma.technique_id
                FROM case_timeline ct
                LEFT JOIN mitre_alerts ma ON ma.alert_id = ct.alert_id
                WHERE ct.case_id=:case_id AND ct.event_type='alert_attached'
                ORDER BY ct.created_at ASC
                """
            ),
            {"case_id": id},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()


@router.get("/{id}/ioc-graph")
def ioc_graph(id: int, user=Depends(current_user)):
    db = connect()
    try:
        alert_rows = db.execute(
            text("SELECT alert_id FROM case_alerts WHERE case_id=:case_id"),
            {"case_id": id},
        ).fetchall()
        alert_ids = [row[0] for row in alert_rows]

        nodes = []
        edges = []

        case_node_id = f"case:{id}"
        nodes.append({"id": case_node_id, "label": f"Case {id}", "type": "case"})

        if not alert_ids:
            return {"nodes": nodes, "edges": edges}

        for alert_id in alert_ids:
            alert_node_id = f"alert:{alert_id}"
            nodes.append({"id": alert_node_id, "label": str(alert_id), "type": "alert"})
            edges.append({"source": case_node_id, "target": alert_node_id, "type": "case_alert"})

        ioc_stmt = text(
            """
            SELECT alert_id, ioc, ioc_type, source, score, verdict
            FROM ioc_enrichments
            WHERE alert_id IN :alert_ids
            """
        ).bindparams(bindparam("alert_ids", expanding=True))
        ioc_rows = db.execute(ioc_stmt, {"alert_ids": alert_ids}).fetchall()

        seen_iocs = set()
        for row in ioc_rows:
            alert_id, ioc, ioc_type, source, score, verdict = row
            if not ioc:
                continue
            ioc_key = f"{ioc_type}:{ioc}"
            node_id = f"ioc:{ioc_key}"
            if node_id not in seen_iocs:
                nodes.append(
                    {
                        "id": node_id,
                        "label": ioc,
                        "type": "ioc",
                        "ioc_type": ioc_type,
                        "source": source,
                        "score": score,
                        "verdict": verdict,
                    }
                )
                seen_iocs.add(node_id)

            edges.append(
                {
                    "source": f"alert:{alert_id}",
                    "target": node_id,
                    "type": "alert_ioc",
                }
            )

        return {"nodes": nodes, "edges": edges}
    finally:
        db.close()


@router.post("/{id}/evidence")
def upload_evidence(
    id: int,
    request: Request,
    file: UploadFile = File(...),
    label: str | None = None,
    category: str | None = None,
    notes: str | None = None,
    user=Depends(current_user)
):
    os.makedirs(_evidence_dir(id), exist_ok=True)
    safe_name = os.path.basename(file.filename or "evidence.bin")
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    stored_path = os.path.join(_evidence_dir(id), stored_name)

    sha256 = hashlib.sha256()
    size = 0
    with open(stored_path, "wb") as out:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            out.write(chunk)
            sha256.update(chunk)
            size += len(chunk)

    db = connect()
    try:
        result = db.execute(
            text(
                """
                INSERT INTO evidence_items
                (case_id, filename, stored_path, content_type, size, sha256, label, category, notes, collected_by)
                VALUES (:case_id, :filename, :stored_path, :content_type, :size, :sha256, :label, :category, :notes, :collected_by)
                RETURNING id
                """
            ),
            {
                "case_id": id,
                "filename": safe_name,
                "stored_path": stored_name,
                "content_type": file.content_type,
                "size": size,
                "sha256": sha256.hexdigest(),
                "label": label,
                "category": category,
                "notes": notes,
                "collected_by": user["sub"],
            },
        )
        evidence_id = result.scalar()
        db.execute(
            text(
                """
                INSERT INTO evidence_events
                (evidence_id, event_type, actor, message)
                VALUES (:evidence_id, 'uploaded', :actor, :message)
                """
            ),
            {
                "evidence_id": evidence_id,
                "actor": user["sub"],
                "message": f"Uploaded evidence: {safe_name} ({size} bytes)",
            },
        )
        log_case_event(
            id,
            "evidence_added",
            message=f"Evidence added: {safe_name}",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "evidence_added",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=safe_name,
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"id": evidence_id, "filename": safe_name}
    finally:
        db.close()


@router.get("/{id}/evidence")
def list_evidence(id: int, user=Depends(current_user)):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT
                    id, filename, content_type, size, sha256, label, category,
                    notes, collected_by, locked, created_at
                FROM evidence_items
                WHERE case_id=:case_id
                ORDER BY created_at DESC
                """
            ),
            {"case_id": id},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()


@router.get("/{id}/evidence/{evidence_id}/download")
def download_evidence(id: int, evidence_id: int, request: Request, user=Depends(current_user)):
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT filename, stored_path, content_type, sha256
                FROM evidence_items
                WHERE id=:id AND case_id=:case_id
                """
            ),
            {"id": evidence_id, "case_id": id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidence not found")
        filename, stored_name, content_type, expected_sha256 = row
        if VERIFY_INTEGRITY_ON_DOWNLOAD:
            integrity = verify_evidence_integrity(
                case_id=id,
                stored_path=str(stored_name or ""),
                expected_sha256=str(expected_sha256 or ""),
            )
            if not integrity.get("ok"):
                db.execute(
                    text(
                        """
                        INSERT INTO evidence_events
                        (evidence_id, event_type, actor, message)
                        VALUES (:evidence_id, 'integrity_mismatch', :actor, :message)
                        """
                    ),
                    {
                        "evidence_id": evidence_id,
                        "actor": user["sub"],
                        "message": (
                            f"Integrity check failed on download: expected={integrity.get('expected_sha256')} "
                            f"actual={integrity.get('actual_sha256')} error={integrity.get('error')}"
                        ),
                    },
                )
                db.commit()
                log_audit(
                    "evidence_integrity_failed",
                    actor=user.get("sub") if isinstance(user, dict) else str(user),
                    entity_type="evidence",
                    entity_id=str(evidence_id),
                    detail=str(integrity),
                    org_id=user.get("org_id") if isinstance(user, dict) else None,
                    ip_address=request.client.host if request.client else None,
                )
                raise HTTPException(
                    status_code=409,
                    detail="Evidence integrity verification failed",
                )
        file_path = os.path.join(_evidence_dir(id), stored_name)
        db.execute(
            text(
                """
                INSERT INTO evidence_events
                (evidence_id, event_type, actor, message)
                VALUES (:evidence_id, 'accessed', :actor, :message)
                """
            ),
            {
                "evidence_id": evidence_id,
                "actor": user["sub"],
                "message": "Evidence downloaded",
            },
        )
        if VERIFY_INTEGRITY_ON_DOWNLOAD:
            db.execute(
                text(
                    """
                    INSERT INTO evidence_events
                    (evidence_id, event_type, actor, message)
                    VALUES (:evidence_id, 'integrity_verified', :actor, :message)
                    """
                ),
                {
                    "evidence_id": evidence_id,
                    "actor": user["sub"],
                    "message": "Integrity verified on download",
                },
            )
        db.commit()
        return FileResponse(
            file_path,
            media_type=content_type or "application/octet-stream",
            filename=filename,
        )
    finally:
        db.close()


@router.post("/{id}/evidence/{evidence_id}/lock")
def lock_evidence(id: int, evidence_id: int, request: Request, user=Depends(current_user)):
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT locked, stored_path, sha256
                FROM evidence_items
                WHERE id=:id AND case_id=:case_id
                """
            ),
            {"id": evidence_id, "case_id": id},
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Evidence not found")
        locked, stored_path, expected_sha256 = row
        if locked:
            return {"status": "locked"}
        if VERIFY_INTEGRITY_ON_LOCK:
            integrity = verify_evidence_integrity(
                case_id=id,
                stored_path=str(stored_path or ""),
                expected_sha256=str(expected_sha256 or ""),
            )
            if not integrity.get("ok"):
                db.execute(
                    text(
                        """
                        INSERT INTO evidence_events
                        (evidence_id, event_type, actor, message)
                        VALUES (:evidence_id, 'integrity_mismatch', :actor, :message)
                        """
                    ),
                    {
                        "evidence_id": evidence_id,
                        "actor": user["sub"],
                        "message": (
                            f"Integrity check failed on lock: expected={integrity.get('expected_sha256')} "
                            f"actual={integrity.get('actual_sha256')} error={integrity.get('error')}"
                        ),
                    },
                )
                db.commit()
                log_audit(
                    "evidence_integrity_failed",
                    actor=user.get("sub") if isinstance(user, dict) else str(user),
                    entity_type="evidence",
                    entity_id=str(evidence_id),
                    detail=str(integrity),
                    org_id=user.get("org_id") if isinstance(user, dict) else None,
                    ip_address=request.client.host if request.client else None,
                )
                raise HTTPException(
                    status_code=409,
                    detail="Evidence integrity verification failed",
                )
        db.execute(
            text(
                """
                UPDATE evidence_items
                SET locked=true
                WHERE id=:id AND case_id=:case_id
                """
            ),
            {"id": evidence_id, "case_id": id},
        )
        db.execute(
            text(
                """
                INSERT INTO evidence_events
                (evidence_id, event_type, actor, message)
                VALUES (:evidence_id, 'locked', :actor, :message)
                """
            ),
            {
                "evidence_id": evidence_id,
                "actor": user["sub"],
                "message": "Evidence locked (immutable)",
            },
        )
        if VERIFY_INTEGRITY_ON_LOCK:
            db.execute(
                text(
                    """
                    INSERT INTO evidence_events
                    (evidence_id, event_type, actor, message)
                    VALUES (:evidence_id, 'integrity_verified', :actor, :message)
                    """
                ),
                {
                    "evidence_id": evidence_id,
                    "actor": user["sub"],
                    "message": "Integrity verified before lock",
                },
            )
        log_case_event(
            id,
            "evidence_locked",
            message=f"Evidence locked: {evidence_id}",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "evidence_locked",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=f"evidence_id={evidence_id}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "locked"}
    finally:
        db.close()


@router.get("/{id}/evidence/{evidence_id}/custody")
def evidence_custody(id: int, evidence_id: int, user=Depends(current_user)):
    db = connect()
    try:
        rows = db.execute(
            text(
                """
                SELECT id, event_type, actor, message, created_at
                FROM evidence_events
                WHERE evidence_id=:evidence_id
                ORDER BY created_at DESC
                """
            ),
            {"evidence_id": evidence_id},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()


@router.get("/{id}/risk")
def get_risk(id: int, user=Depends(current_user)):
    db = connect()
    try:
        row = db.execute(
            text(
                """
                SELECT risk_score, impact, updated_by, updated_at
                FROM case_risk
                WHERE case_id=:case_id
                """
            ),
            {"case_id": id},
        ).fetchone()
        if not row:
            return {"risk_score": None, "impact": None, "updated_by": None, "updated_at": None}
        return {
            "risk_score": row[0],
            "impact": row[1],
            "updated_by": row[2],
            "updated_at": row[3],
        }
    finally:
        db.close()


@router.post("/{id}/risk")
async def set_risk(
    id: int,
    request: Request,
    risk_score: int | None = None,
    impact: str | None = None,
    user=Depends(current_user),
):
    body = {}
    try:
        body = await request.json()
    except Exception:
        body = {}

    if "risk_score" in body:
        risk_score = body.get("risk_score")
    if "impact" in body:
        impact = body.get("impact")

    if risk_score is not None:
        try:
            risk_score = int(risk_score)
        except (TypeError, ValueError):
            return {"status": "invalid", "detail": "risk_score must be integer"}
        risk_score = max(0, min(100, risk_score))

    if impact:
        impact = impact.lower()

    db = connect()
    try:
        exists = db.execute(
            text("SELECT 1 FROM case_risk WHERE case_id=:case_id"),
            {"case_id": id},
        ).scalar()
        if exists:
            db.execute(
                text(
                    """
                    UPDATE case_risk
                    SET risk_score=:risk_score, impact=:impact, updated_by=:updated_by, updated_at=NOW()
                    WHERE case_id=:case_id
                    """
                ),
                {
                    "risk_score": risk_score,
                    "impact": impact,
                    "updated_by": user["sub"],
                    "case_id": id,
                },
            )
        else:
            db.execute(
                text(
                    """
                    INSERT INTO case_risk
                    (case_id, risk_score, impact, updated_by)
                    VALUES (:case_id, :risk_score, :impact, :updated_by)
                    """
                ),
                {
                    "case_id": id,
                    "risk_score": risk_score,
                    "impact": impact,
                    "updated_by": user["sub"],
                },
            )

        log_case_event(
            id,
            "risk_updated",
            message=f"Risk set to {risk_score}, impact {impact}",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "risk_updated",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=f"risk={risk_score},impact={impact}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"status": "updated"}
    finally:
        db.close()


@router.post("/{id}/status")
def update_status(
    id: int,
    status: str,
    request: Request,
    user=Depends(current_user)
):
    status = status.upper()
    if status not in {"OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"}:
        return {"status": "invalid", "detail": "Unsupported status"}

    db = connect()
    try:
        db.execute(
            text("UPDATE cases SET status=:status WHERE id=:id"),
            {"status": status, "id": id},
        )
        log_case_event(
            id,
            "status_changed",
            message=f"Status set to {status}",
            actor=user["sub"],
            conn=db,
        )
        db.commit()
        log_audit(
            "status_changed",
            actor=user["sub"],
            entity_type="case",
            entity_id=str(id),
            detail=f"status={status}",
            org_id=user.get("org_id"),
            ip_address=request.client.host if request.client else None,
        )
        return {"status": status}
    finally:
        db.close()
