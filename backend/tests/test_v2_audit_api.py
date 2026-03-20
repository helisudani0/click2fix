from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from sqlalchemy import create_engine, text


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "v2-audit-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from api.v2 import audit as v2_audit  # noqa: E402
from db import database as db_database  # noqa: E402


def _admin_user(org_id: int | None = 1) -> dict:
    return {"sub": "auditor", "role": "admin", "org_id": org_id}


def _audit_rows(engine):
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT id, org_id, detail
                FROM audit_logs
                ORDER BY id ASC
                """
            )
        ).fetchall()
    out = []
    for row in rows:
        out.append(
            {
                "id": int(row[0]),
                "org_id": row[1],
                "detail": json.loads(str(row[2] or "{}")),
            }
        )
    return out


def _tamper_row_detail(engine, *, row_id: int, field: str, value):
    with engine.begin() as conn:
        raw = conn.execute(
            text("SELECT detail FROM audit_logs WHERE id=:id"),
            {"id": row_id},
        ).scalar()
        payload = json.loads(str(raw or "{}"))
        payload[field] = value
        conn.execute(
            text("UPDATE audit_logs SET detail=:detail WHERE id=:id"),
            {"id": row_id, "detail": json.dumps(payload, sort_keys=True, separators=(",", ":"))},
        )


def _sqlite_engine(tmp_path, monkeypatch):
    db_path = tmp_path / "v2_audit_api.db"
    engine = create_engine(f"sqlite+pysqlite:///{db_path}", future=True)
    monkeypatch.setattr(db_database, "engine", engine)
    db_database.metadata.create_all(engine)
    return engine


def test_v2_immutable_chain_links_per_tenant(tmp_path, monkeypatch):
    engine = _sqlite_engine(tmp_path, monkeypatch)
    try:
        v2_audit.log_v2_write_audit(
            action="v2.tests.first",
            entity_type="case",
            entity_id="1",
            user=_admin_user(1),
            tenant_id=1,
        )
        v2_audit.log_v2_write_audit(
            action="v2.tests.second",
            entity_type="case",
            entity_id="2",
            user=_admin_user(1),
            tenant_id=1,
        )
        v2_audit.log_v2_write_audit(
            action="v2.tests.third",
            entity_type="incident",
            entity_id="9",
            user=_admin_user(2),
            tenant_id=2,
        )

        rows = _audit_rows(engine)
        tenant_1 = [row for row in rows if row["org_id"] == 1]
        tenant_2 = [row for row in rows if row["org_id"] == 2]

        assert len(tenant_1) == 2
        assert len(tenant_2) == 1

        first = tenant_1[0]["detail"]
        second = tenant_1[1]["detail"]
        third = tenant_2[0]["detail"]

        assert first["immutability"]["prev_event_hash"] is None
        assert second["immutability"]["prev_event_hash"] == first["immutability"]["event_hash"]
        assert third["immutability"]["prev_event_hash"] is None
        assert first["immutability"]["chain_scope"] == "tenant:1"
        assert third["immutability"]["chain_scope"] == "tenant:2"
        assert isinstance(first["immutability"].get("signature"), str)
        assert first["immutability"].get("signature")
    finally:
        engine.dispose()


def test_v2_audit_verify_reports_tamper(tmp_path, monkeypatch):
    engine = _sqlite_engine(tmp_path, monkeypatch)
    try:
        v2_audit.log_v2_write_audit(
            action="v2.tests.verify.1",
            entity_type="execution",
            entity_id="101",
            user=_admin_user(1),
            tenant_id=1,
            changes={"status": "started"},
        )
        v2_audit.log_v2_write_audit(
            action="v2.tests.verify.2",
            entity_type="execution",
            entity_id="101",
            user=_admin_user(1),
            tenant_id=1,
            changes={"status": "done"},
        )
        rows = _audit_rows(engine)
        tampered_row_id = rows[-1]["id"]
        _tamper_row_detail(
            engine,
            row_id=tampered_row_id,
            field="changes",
            value={"status": "tampered"},
        )

        response = v2_audit.verify_audit_chain(
            actor=None,
            action=None,
            entity_type=None,
            entity_id=None,
            start=None,
            end=None,
            limit=100,
            tenant_id=1,
            user=_admin_user(1),
        )
        verification = response.get("data", {}).get("verification", {})
        summary = verification.get("summary", {})
        anomaly_types = {item.get("type") for item in verification.get("anomalies", [])}

        assert bool(summary.get("tampered")) is True
        assert "hash_mismatch" in anomaly_types
        assert "signature_mismatch" in anomaly_types
    finally:
        engine.dispose()


def test_v2_audit_export_json_contains_verification_report(tmp_path, monkeypatch):
    engine = _sqlite_engine(tmp_path, monkeypatch)
    try:
        v2_audit.log_v2_write_audit(
            action="v2.tests.export.1",
            entity_type="approval",
            entity_id="500",
            user=_admin_user(1),
            tenant_id=1,
        )
        v2_audit.log_v2_write_audit(
            action="v2.tests.export.2",
            entity_type="approval",
            entity_id="500",
            user=_admin_user(1),
            tenant_id=1,
        )

        export_response = v2_audit.export_audit_events(
            format="json",
            actor=None,
            action=None,
            entity_type=None,
            entity_id=None,
            start=None,
            end=None,
            limit=100,
            tenant_id=1,
            verify_chain=True,
            user=_admin_user(1),
        )
        payload = json.loads(export_response.body.decode("utf-8"))

        assert isinstance(payload.get("events"), list)
        assert len(payload.get("events", [])) == 2
        assert isinstance(payload.get("verification"), dict)
        assert payload.get("verification", {}).get("summary", {}).get("immutable_rows") == 2
        assert payload.get("verification", {}).get("summary", {}).get("tampered") is False
    finally:
        engine.dispose()
