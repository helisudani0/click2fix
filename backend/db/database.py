import os

from passlib.context import CryptContext
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    text,
)

from core.settings import SETTINGS
from core.time_utils import row_to_json_list


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    (SETTINGS.get("database", {}) if isinstance(SETTINGS, dict) else {}).get(
        "url",
        "postgresql+psycopg2://click2fix:click2fix@db:5432/click2fix",
    ),
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
metadata = MetaData()

approvals = Table(
    "approvals",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent", String),
    Column("playbook", String),
    Column("action", String),
    Column("args", Text),
    Column("alert_id", String),
    Column("alert_json", Text),
    Column("requested_by", String),
    Column("status", String),
    Column("org_id", Integer),
    Column("created_at", DateTime, server_default=func.now()),
    Column("decided_at", DateTime),
)

approval_requirements = Table(
    "approval_requirements",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("approval_id", Integer),
    Column("role", String),
    Column("required_count", Integer),
    Column("current_count", Integer, server_default=text("0")),
    Column("status", String, server_default=text("'PENDING'")),
    Column("created_at", DateTime, server_default=func.now()),
)

approval_decisions = Table(
    "approval_decisions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("approval_id", Integer),
    Column("decided_by", String),
    Column("role", String),
    Column("decision", String),
    Column("created_at", DateTime, server_default=func.now()),
)

approval_metadata = Table(
    "approval_metadata",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("approval_id", Integer),
    Column("justification", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

execution_metadata = Table(
    "execution_metadata",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", Integer),
    Column("justification", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

executions = Table(
    "executions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("approval_id", Integer),
    Column("agent", String),
    Column("playbook", String),
    Column("action", String),
    Column("args", Text),
    Column("alert_id", String),
    Column("status", String),
    Column("approved_by", String),
    Column("org_id", Integer),
    Column("started_at", DateTime),
    Column("finished_at", DateTime),
)

execution_steps = Table(
    "execution_steps",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", Integer),
    Column("step", String),
    Column("stdout", Text),
    Column("stderr", Text),
    Column("status", String),
)

execution_targets = Table(
    "execution_targets",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", Integer),
    Column("agent_id", String),
    Column("agent_name", String),
    Column("target_ip", String),
    Column("platform", String),
    Column("ok", Boolean),
    Column("status_code", Integer),
    Column("stdout", Text),
    Column("stderr", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

vulnerability_local_closures = Table(
    "vulnerability_local_closures",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("vulnerability_id", String, nullable=False),
    Column("agent_id", String, nullable=False),
    Column("state", String, nullable=False, server_default=text("'closed'")),
    Column("reason", Text),
    Column("execution_id", Integer),
    Column("closed_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now()),
    UniqueConstraint("vulnerability_id", "agent_id", name="uq_vulnerability_local_closure"),
)

scheduled_jobs = Table(
    "scheduled_jobs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String),
    Column("playbook", String),
    Column("target", String),
    Column("cron", String),
    Column("enabled", Boolean),
    Column("require_approval", Boolean),
    Column("last_run", DateTime),
    Column("org_id", Integer),
)

ioc_enrichments = Table(
    "ioc_enrichments",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String),
    Column("ioc", String),
    Column("ioc_type", String),
    Column("source", String),
    Column("score", Integer),
    Column("verdict", String),
    Column("details", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

cases = Table(
    "cases",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String),
    Column("description", Text),
    Column("status", String),
    Column("owner", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("org_id", Integer),
)

case_alerts = Table(
    "case_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer),
    Column("alert_id", String),
)

case_notes = Table(
    "case_notes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer),
    Column("author", String),
    Column("note", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

case_risk = Table(
    "case_risk",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer, unique=True),
    Column("risk_score", Integer),
    Column("impact", String),
    Column("updated_by", String),
    Column("updated_at", DateTime, server_default=func.now()),
)

alerts_store = Table(
    "alerts_store",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String, unique=True),
    Column("agent_id", String),
    Column("agent_name", String),
    Column("rule_id", String),
    Column("rule_description", String),
    Column("rule_level", Integer),
    Column("tactic", String),
    Column("technique_id", String),
    Column("event_time", DateTime),
    Column("raw_json", Text),
)

case_timeline = Table(
    "case_timeline",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer),
    Column("event_type", String),
    Column("message", Text),
    Column("actor", String),
    Column("alert_id", String),
    Column("approval_id", Integer),
    Column("execution_id", Integer),
    Column("action", String),
    Column("created_at", DateTime, server_default=func.now()),
)

case_attachments = Table(
    "case_attachments",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer),
    Column("filename", String),
    Column("stored_path", String),
    Column("content_type", String),
    Column("size", Integer),
    Column("sha256", String),
    Column("uploaded_by", String),
    Column("created_at", DateTime, server_default=func.now()),
)

evidence_items = Table(
    "evidence_items",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer),
    Column("filename", String),
    Column("stored_path", String),
    Column("content_type", String),
    Column("size", Integer),
    Column("sha256", String),
    Column("label", String),
    Column("category", String),
    Column("notes", Text),
    Column("collected_by", String),
    Column("locked", Boolean, server_default=text("false")),
    Column("created_at", DateTime, server_default=func.now()),
)

evidence_events = Table(
    "evidence_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("evidence_id", Integer),
    Column("event_type", String),
    Column("actor", String),
    Column("message", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

mitre_alerts = Table(
    "mitre_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String),
    Column("tactic", String),
    Column("technique", String),
    Column("technique_id", String),
)

audit_logs = Table(
    "audit_logs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("actor", String),
    Column("action", String),
    Column("entity_type", String),
    Column("entity_id", String),
    Column("detail", Text),
    Column("org_id", Integer),
    Column("ip_address", String),
    Column("created_at", DateTime, server_default=func.now()),
)

change_requests = Table(
    "change_requests",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String),
    Column("description", Text),
    Column("action_id", String),
    Column("target", String),
    Column("justification", Text),
    Column("risk_score", Integer),
    Column("impact", String),
    Column("requested_by", String),
    Column("status", String),
    Column("approved_by", String),
    Column("scheduled_for", DateTime),
    Column("executed_at", DateTime),
    Column("created_at", DateTime, server_default=func.now()),
    Column("approved_at", DateTime),
)

orgs = Table(
    "orgs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String, unique=True),
    Column("created_at", DateTime, server_default=func.now()),
)

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String, unique=True),
    Column("password", String),
    Column("role", String),
    Column("org_id", Integer),
    Column("created_at", DateTime, server_default=func.now()),
)

forensic_reports = Table(
    "forensic_reports",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", String),
    Column("action", String),
    Column("report_path", String),
    Column("file_size", Integer),
    Column("uploaded_by", String),
    Column("uploaded_at", DateTime, server_default=func.now()),
)

# State-aware execution tracking tables
execution_state = Table(
    "execution_state",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", String, unique=True, nullable=False, index=True),
    Column("action_id", String, nullable=False),
    Column("agent_id", String, nullable=False),
    Column("agent_name", String),
    Column("platform", String),
    Column("status", String, nullable=False),
    Column("result", String),
    Column("exit_code", Integer),
    Column("reboot_required", Boolean, server_default=text("false")),
    Column("matches_found", Integer, server_default=text("0")),
    Column("artifact_url", Text),
    Column("stdout", Text),
    Column("stderr", Text),
    Column("error_message", Text),
    Column("metadata", Text),
    Column("created_at", DateTime, server_default=func.now()),
    Column("expires_at", DateTime, nullable=False),
    Column("started_at", DateTime),
    Column("completed_at", DateTime),
)

agent_state = Table(
    "agent_state",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent_id", String, unique=True, nullable=False),
    Column("agent_name", String),
    Column("platform", String),
    Column("ip_address", String),
    Column("online_status", String),
    Column("last_heartbeat", DateTime),
    Column("has_pending_reboot", Boolean, server_default=text("false")),
    Column("reboot_reason", String),
    Column("free_memory_mb", Integer),
    Column("last_action_status", String),
    Column("last_action_time", DateTime),
    Column("consecutive_failures", Integer, server_default=text("0")),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

reboot_requirements = Table(
    "reboot_requirements",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("agent_id", String, nullable=False),
    Column("execution_id", String),
    Column("reboot_reason", String),
    Column("scheduled_for", DateTime),
    Column("status", String, server_default=text("'PENDING'")),
    Column("acknowledged_by", String),
    Column("prevent_until", DateTime),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

action_idempotency_cache = Table(
    "action_idempotency_cache",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("cache_key", String, nullable=False, unique=True),
    Column("action_id", String, nullable=False),
    Column("agent_id", String, nullable=False),
    Column("execution_id", String),
    Column("action_state", String),
    Column("result_data", Text),
    Column("last_execution_time", DateTime),
    Column("expires_at", DateTime),
    Column("created_at", DateTime, server_default=func.now()),
)

orphaned_executions = Table(
    "orphaned_executions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", String, unique=True, nullable=False),
    Column("action_id", String, nullable=False),
    Column("agent_id", String, nullable=False),
    Column("agent_name", String),
    Column("expiry_reason", String),
    Column("discovered_at", DateTime),
    Column("recovery_attempted_at", DateTime),
    Column("recovery_status", String),
    Column("recovery_message", Text),
    Column("automation_context", Text),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

action_execution_history = Table(
    "action_execution_history",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", String),
    Column("action_id", String, nullable=False),
    Column("agent_id", String, nullable=False),
    Column("status", String),
    Column("result", String),
    Column("exit_code", Integer),
    Column("duration_seconds", Integer),
    Column("reboot_required", Boolean),
    Column("matches_found", Integer),
    Column("executed_at", DateTime, server_default=func.now()),
)


def connect():
    return engine.connect()


def init():
    metadata.create_all(engine)

    pwd = CryptContext(schemes=["bcrypt"])
    security_cfg = SETTINGS.get("security", {}) if isinstance(SETTINGS, dict) else {}
    allow_demo_users_cfg = security_cfg.get("allow_demo_users", False)
    allow_demo_users_env = os.getenv("C2F_ALLOW_DEMO_USERS")
    if allow_demo_users_env is None:
        allow_demo_users = bool(allow_demo_users_cfg)
    else:
        allow_demo_users = str(allow_demo_users_env).strip().lower() in {"1", "true", "yes", "on"}
    with engine.begin() as conn:
        org_id = conn.execute(
            text("SELECT id FROM orgs ORDER BY id LIMIT 1")
        ).scalar()

        if not org_id:
            conn.execute(
                text("INSERT INTO orgs (name) VALUES (:name)"),
                {"name": "Default Org"},
            )
            org_id = conn.execute(
                text("SELECT id FROM orgs ORDER BY id LIMIT 1")
            ).scalar()

        def ensure_user(username, password, role):
            exists = conn.execute(
                text("SELECT 1 FROM users WHERE username=:username"),
                {"username": username},
            ).scalar()
            if not exists:
                conn.execute(
                    text(
                        """
                        INSERT INTO users (username, password, role, org_id)
                        VALUES (:username, :password, :role, :org_id)
                        """
                    ),
                    {
                        "username": username,
                        "password": pwd.hash(password),
                        "role": role,
                        "org_id": org_id,
                    },
                )

        if allow_demo_users:
            ensure_user("admin", "admin123", "admin")
            ensure_user("analyst", "analyst123", "analyst")
            ensure_user("superadmin", "super123", "superadmin")


def row_to_list(row):
    return row_to_json_list(row)


def rows_to_list(rows):
    return [row_to_list(row) for row in rows]
