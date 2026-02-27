from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List

from sqlalchemy import text

from core.audit import log_audit
from core.settings import SETTINGS
from core.time_utils import utc_now_naive
from db.database import connect

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


def _case_dir(case_id: int) -> str:
    return os.path.join(ATTACHMENTS_ROOT, f"case_{case_id}")


def _evidence_dir(case_id: int) -> str:
    return os.path.join(EVIDENCE_ROOT, f"case_{case_id}")


def compute_sha256(path: str, chunk_size: int = 1024 * 1024) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def verify_hash(path: str, expected_sha256: str | None) -> Dict[str, Any]:
    expected = str(expected_sha256 or "").strip().lower()
    if not expected:
        return {
            "ok": False,
            "error": "missing_expected_hash",
            "expected_sha256": expected,
            "actual_sha256": None,
            "path": path,
        }
    if not os.path.exists(path):
        return {
            "ok": False,
            "error": "file_missing",
            "expected_sha256": expected,
            "actual_sha256": None,
            "path": path,
        }
    try:
        actual = compute_sha256(path)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "expected_sha256": expected,
            "actual_sha256": None,
            "path": path,
        }
    return {
        "ok": actual.lower() == expected.lower(),
        "error": None if actual.lower() == expected.lower() else "hash_mismatch",
        "expected_sha256": expected,
        "actual_sha256": actual,
        "path": path,
    }


def verify_attachment_integrity(case_id: int, stored_path: str, expected_sha256: str | None) -> Dict[str, Any]:
    path = os.path.join(_case_dir(case_id), stored_path)
    result = verify_hash(path, expected_sha256)
    result["case_id"] = int(case_id)
    result["stored_path"] = stored_path
    result["kind"] = "attachment"
    return result


def verify_evidence_integrity(case_id: int, stored_path: str, expected_sha256: str | None) -> Dict[str, Any]:
    path = os.path.join(_evidence_dir(case_id), stored_path)
    result = verify_hash(path, expected_sha256)
    result["case_id"] = int(case_id)
    result["stored_path"] = stored_path
    result["kind"] = "evidence"
    return result


def _record_evidence_integrity_event(
    conn,
    *,
    evidence_id: int,
    actor: str,
    result: Dict[str, Any],
    source: str,
) -> None:
    if result.get("ok"):
        event_type = "integrity_verified"
        message = f"Integrity verified by {source}"
    else:
        event_type = "integrity_mismatch"
        message = (
            f"Integrity check failed by {source}: expected={result.get('expected_sha256')} "
            f"actual={result.get('actual_sha256')} error={result.get('error')}"
        )
    conn.execute(
        text(
            """
            INSERT INTO evidence_events
            (evidence_id, event_type, actor, message)
            VALUES (:evidence_id, :event_type, :actor, :message)
            """
        ),
        {
            "evidence_id": int(evidence_id),
            "event_type": event_type,
            "actor": actor,
            "message": message,
        },
    )


def run_integrity_sweep(max_items: int = 2000) -> Dict[str, Any]:
    db = connect()
    checked = 0
    mismatches = 0
    missing = 0
    evidence_checked = 0
    attachment_checked = 0
    issues: List[Dict[str, Any]] = []
    limit_value = max(1, int(max_items or 2000))

    try:
        evidence_rows = db.execute(
            text(
                """
                SELECT id, case_id, stored_path, sha256
                FROM evidence_items
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit_value},
        ).fetchall()

        for row in evidence_rows:
            evidence_id, case_id, stored_path, expected_sha = row
            result = verify_evidence_integrity(
                int(case_id), str(stored_path or ""), str(expected_sha or "")
            )
            checked += 1
            evidence_checked += 1
            if not result.get("ok"):
                mismatches += 1
                if result.get("error") == "file_missing":
                    missing += 1
                issues.append(
                    {
                        "kind": "evidence",
                        "evidence_id": int(evidence_id),
                        "case_id": int(case_id),
                        "stored_path": str(stored_path or ""),
                        "error": result.get("error"),
                        "expected_sha256": result.get("expected_sha256"),
                        "actual_sha256": result.get("actual_sha256"),
                    }
                )
            _record_evidence_integrity_event(
                db,
                evidence_id=int(evidence_id),
                actor="scheduler",
                result=result,
                source="periodic_sweep",
            )

        attachment_rows = db.execute(
            text(
                """
                SELECT id, case_id, stored_path, sha256
                FROM case_attachments
                ORDER BY created_at DESC
                LIMIT :limit
                """
            ),
            {"limit": limit_value},
        ).fetchall()

        for row in attachment_rows:
            attachment_id, case_id, stored_path, expected_sha = row
            result = verify_attachment_integrity(
                int(case_id), str(stored_path or ""), str(expected_sha or "")
            )
            checked += 1
            attachment_checked += 1
            if not result.get("ok"):
                mismatches += 1
                if result.get("error") == "file_missing":
                    missing += 1
                issues.append(
                    {
                        "kind": "attachment",
                        "attachment_id": int(attachment_id),
                        "case_id": int(case_id),
                        "stored_path": str(stored_path or ""),
                        "error": result.get("error"),
                        "expected_sha256": result.get("expected_sha256"),
                        "actual_sha256": result.get("actual_sha256"),
                    }
                )

        db.commit()
    finally:
        db.close()

    summary = {
        "checked": checked,
        "evidence_checked": evidence_checked,
        "attachment_checked": attachment_checked,
        "mismatches": mismatches,
        "missing_files": missing,
        "ok": mismatches == 0,
        "issues": issues[:200],
    }

    try:
        sweep_db = connect()
        try:
            now = utc_now_naive()
            sweep_db.execute(
                text(
                    """
                    INSERT INTO forensic_integrity_sweeps
                    (status, checked, evidence_checked, attachment_checked, mismatches, missing_files,
                     summary_json, org_id, created_by, created_at, updated_at)
                    VALUES
                    (:status, :checked, :evidence_checked, :attachment_checked, :mismatches, :missing_files,
                     :summary_json, :org_id, :created_by, :created_at, :updated_at)
                    """
                ),
                {
                    "status": "ok" if summary["ok"] else "drift_detected",
                    "checked": int(summary["checked"]),
                    "evidence_checked": int(summary["evidence_checked"]),
                    "attachment_checked": int(summary["attachment_checked"]),
                    "mismatches": int(summary["mismatches"]),
                    "missing_files": int(summary["missing_files"]),
                    "summary_json": str(summary),
                    "org_id": None,
                    "created_by": "scheduler",
                    "created_at": now,
                    "updated_at": now,
                },
            )
            sweep_db.commit()
        finally:
            sweep_db.close()
    except Exception:
        # Keep sweep execution resilient even if summary persistence is unavailable.
        pass

    log_audit(
        "integrity_sweep_completed",
        actor="scheduler",
        entity_type="forensics",
        entity_id="periodic_integrity_sweep",
        detail=str(summary),
        org_id=None,
        ip_address=None,
    )
    return summary
