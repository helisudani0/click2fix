import os
import time

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
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError

from core.settings import SETTINGS
from core.time_utils import row_to_json_list


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    (SETTINGS.get("database", {}) if isinstance(SETTINGS, dict) else {}).get(
        "url",
        "postgresql+psycopg2://click2fix:click2fix@db:5432/click2fix",
    ),
)

_DB_SETTINGS = SETTINGS.get("database", {}) if isinstance(SETTINGS, dict) else {}


def _int_setting(env_key: str, settings_key: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(env_key)
    if raw is None:
        raw = _DB_SETTINGS.get(settings_key)
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    return max(int(minimum), value)


_DB_POOL_SIZE = _int_setting("C2F_DB_POOL_SIZE", "pool_size", 20, minimum=1)
_DB_MAX_OVERFLOW = _int_setting("C2F_DB_MAX_OVERFLOW", "max_overflow", 40, minimum=0)
_DB_POOL_TIMEOUT = _int_setting("C2F_DB_POOL_TIMEOUT_SECONDS", "pool_timeout_seconds", 30, minimum=1)
_DB_POOL_RECYCLE = _int_setting("C2F_DB_POOL_RECYCLE_SECONDS", "pool_recycle_seconds", 1800, minimum=30)
_DB_CONNECT_RETRIES = _int_setting("C2F_DB_CONNECT_RETRIES", "connect_retries", 3, minimum=1)
_DB_CONNECT_RETRY_DELAY_MS = _int_setting(
    "C2F_DB_CONNECT_RETRY_DELAY_MS",
    "connect_retry_delay_ms",
    250,
    minimum=25,
)


engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=_DB_POOL_SIZE,
    max_overflow=_DB_MAX_OVERFLOW,
    pool_timeout=_DB_POOL_TIMEOUT,
    pool_recycle=_DB_POOL_RECYCLE,
    future=True,
)
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
    Column("target_total", Integer, server_default=text("0")),
    Column("target_completed", Integer, server_default=text("0")),
    Column("target_success", Integer, server_default=text("0")),
    Column("target_failed", Integer, server_default=text("0")),
    Column("batch_size", Integer, server_default=text("0")),
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
    Column("created_at", DateTime, server_default=func.now()),
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
    Column("job_kind", String, server_default=text("'action'")),
    Column("payload_json", Text),
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

alert_triage = Table(
    "alert_triage",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String, nullable=False),
    Column("org_id", Integer),
    Column("status", String, server_default=text("'open'")),
    Column("owner", String),
    Column("classification", String),
    Column("severity_override", String),
    Column("notes", Text),
    Column("last_triaged_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("org_id", "alert_id", name="uq_alert_triage_org_alert"),
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

case_sla_policies = Table(
    "case_sla_policies",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer, nullable=False),
    Column("response_due_at", DateTime),
    Column("resolution_due_at", DateTime),
    Column("target_response_minutes", Integer),
    Column("target_resolution_minutes", Integer),
    Column("status", String, server_default=text("'active'")),
    Column("severity", String),
    Column("breach_state", String, server_default=text("'on_track'")),
    Column("notes", Text),
    Column("updated_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("case_id", name="uq_case_sla_policies_case_id"),
)

case_sla_events = Table(
    "case_sla_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("case_id", Integer, nullable=False),
    Column("event_type", String),
    Column("detail", Text),
    Column("actor", String),
    Column("created_at", DateTime, server_default=func.now()),
)

incidents = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("title", String),
    Column("summary", Text),
    Column("status", String, server_default=text("'open'")),
    Column("priority", String, server_default=text("'medium'")),
    Column("owner", String),
    Column("due_at", DateTime),
    Column("escalation_state", String, server_default=text("'normal'")),
    Column("correlation_key", String),
    Column("first_event_time", DateTime),
    Column("last_event_time", DateTime),
    Column("alert_count", Integer, server_default=text("0")),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

incident_alerts = Table(
    "incident_alerts",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", Integer),
    Column("alert_id", String),
    Column("agent_id", String),
    Column("tactic", String),
    Column("identity", String),
    Column("matched_signals", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

incident_assignments = Table(
    "incident_assignments",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", Integer),
    Column("previous_owner", String),
    Column("new_owner", String),
    Column("changed_by", String),
    Column("note", Text),
    Column("created_at", DateTime, server_default=func.now()),
)

incident_sla_events = Table(
    "incident_sla_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("incident_id", Integer),
    Column("event_type", String),
    Column("detail", Text),
    Column("actor", String),
    Column("created_at", DateTime, server_default=func.now()),
)

execution_context = Table(
    "execution_context",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", Integer),
    Column("action_id", String),
    Column("actor", String),
    Column("target", String),
    Column("started_at", DateTime),
    Column("finished_at", DateTime),
    Column("classification", String),
    Column("reason", Text),
    Column("context_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("execution_id", name="uq_execution_context_execution_id"),
)

automation_context_profiles = Table(
    "automation_context_profiles",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("name", String),
    Column("description", Text),
    Column("enabled", Boolean, server_default=text("true")),
    Column("classification", String, server_default=text("'review_required'")),
    Column("profile_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

alert_execution_correlation = Table(
    "alert_execution_correlation",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("execution_id", Integer),
    Column("alert_id", String),
    Column("agent_id", String),
    Column("classification", String),
    Column("confidence", Integer),
    Column("reason", Text),
    Column("matched_profile_ids", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("execution_id", "alert_id", name="uq_alert_execution_correlation_exec_alert"),
)

ioc_enrichment_records = Table(
    "ioc_enrichment_records",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("alert_id", String),
    Column("ioc", String),
    Column("ioc_type", String),
    Column("source", String),
    Column("score", Integer),
    Column("confidence", Integer),
    Column("verdict", String),
    Column("evidence_json", Text),
    Column("observed_at", DateTime),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("alert_id", "ioc", "ioc_type", "source", name="uq_ioc_enrichment_records_key"),
)

forensic_integrity_sweeps = Table(
    "forensic_integrity_sweeps",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("status", String),
    Column("checked", Integer, server_default=text("0")),
    Column("evidence_checked", Integer, server_default=text("0")),
    Column("attachment_checked", Integer, server_default=text("0")),
    Column("mismatches", Integer, server_default=text("0")),
    Column("missing_files", Integer, server_default=text("0")),
    Column("summary_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

detection_tuning_suggestions = Table(
    "detection_tuning_suggestions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("rule_id", String),
    Column("rule_description", String),
    Column("tactic", String),
    Column("suggestion", Text),
    Column("confidence", Integer),
    Column("status", String, server_default=text("'open'")),
    Column("source", String),
    Column("context_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

detection_rules = Table(
    "detection_rules",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("rule_key", String),
    Column("name", String),
    Column("description", Text),
    Column("rule_type", String, server_default=text("'atomic'")),
    Column("severity", String, server_default=text("'medium'")),
    Column("confidence_threshold", Integer, server_default=text("60")),
    Column("enabled", Boolean, server_default=text("true")),
    Column("conditions_json", Text),
    Column("tags_json", Text),
    Column("tuning_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)

detection_suppressions = Table(
    "detection_suppressions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("rule_key", String),
    Column("scope_type", String, server_default=text("'rule'")),
    Column("scope_value", String),
    Column("reason", Text),
    Column("status", String, server_default=text("'active'")),
    Column("starts_at", DateTime, server_default=func.now()),
    Column("expires_at", DateTime),
    Column("context_json", Text),
    Column("org_id", Integer),
    Column("created_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
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
    Column("confidence", Integer),
    Column("source", String),
    Column("mapping_rank", Integer),
    Column("created_at", DateTime, server_default=func.now()),
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

security_events = Table(
    "security_events",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_type", String, nullable=False),
    Column("severity", String, nullable=False, server_default=text("'warning'")),
    Column("username", String),
    Column("role", String),
    Column("org_id", Integer),
    Column("ip_address", String),
    Column("method", String),
    Column("path", String),
    Column("detail", Text),
    Column("metadata_json", Text),
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

tenant_quotas = Table(
    "tenant_quotas",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("org_id", Integer, nullable=False),
    Column("max_agents", Integer),
    Column("max_cases", Integer),
    Column("max_incidents", Integer),
    Column("max_approvals_per_day", Integer),
    Column("max_executions_per_day", Integer),
    Column("config_json", Text),
    Column("updated_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("org_id", name="uq_tenant_quotas_org_id"),
)

tenant_config_revisions = Table(
    "tenant_config_revisions",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("org_id", Integer, nullable=False),
    Column("config_key", String, nullable=False),
    Column("version", Integer, nullable=False),
    Column("status", String, server_default=text("'draft'")),
    Column("config_json", Text),
    Column("notes", Text),
    Column("created_by", String),
    Column("updated_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    Column("activated_at", DateTime),
    Column("retired_at", DateTime),
    UniqueConstraint("org_id", "config_key", "version", name="uq_tenant_config_revision"),
)

retention_policies = Table(
    "retention_policies",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("org_id", Integer, nullable=False),
    Column("data_class", String, nullable=False),
    Column("storage_backend", String, nullable=False, server_default=text("'event_indexer'")),
    Column("stream", String),
    Column("warm_after_days", Integer, nullable=False),
    Column("cold_after_days", Integer, nullable=False),
    Column("archive_after_days", Integer, nullable=False),
    Column("delete_after_days", Integer),
    Column("archive_backend", String),
    Column("legal_hold", Boolean, server_default=text("false")),
    Column("status", String, nullable=False, server_default=text("'active'")),
    Column("notes", Text),
    Column("created_by", String),
    Column("updated_by", String),
    Column("last_applied_at", DateTime),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("org_id", "data_class", name="uq_retention_policies_org_data_class"),
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

event_ingestion_queue = Table(
    "event_ingestion_queue",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("queue_event_id", String, unique=True, nullable=False, index=True),
    Column("tenant_id", Integer, index=True),
    Column("source_type", String, nullable=False),
    Column("stream", String, nullable=False, server_default=text("'events'"), index=True),
    Column("event_kind", String, nullable=False, server_default=text("'canonical_event'")),
    Column("actor", String),
    Column("trace_id", String, index=True),
    Column("dedupe_key", String, index=True),
    Column("payload_json", Text, nullable=False),
    Column("metadata_json", Text),
    Column("status", String, nullable=False, server_default=text("'PENDING'"), index=True),
    Column("attempt_count", Integer, nullable=False, server_default=text("0")),
    Column("max_attempts", Integer, nullable=False, server_default=text("6")),
    Column("next_attempt_at", DateTime, nullable=False, server_default=func.now(), index=True),
    Column("locked_by", String),
    Column("locked_at", DateTime),
    Column("last_error", Text),
    Column("result_json", Text),
    Column("replay_of_queue_event_id", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    Column("completed_at", DateTime),
)

agent_runtime_state = Table(
    "agent_runtime_state",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant_scope", Integer, nullable=False, server_default=text("0")),
    Column("agent_id", String, nullable=False),
    Column("state_kind", String, nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("updated_by", String),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
    UniqueConstraint("tenant_scope", "agent_id", "state_kind", name="uq_agent_runtime_state_scope"),
)

service_runtime_leases = Table(
    "service_runtime_leases",
    metadata,
    Column("lease_name", String, primary_key=True),
    Column("owner_id", String, nullable=False),
    Column("lease_token", String, nullable=False),
    Column("lease_expires_at", DateTime, nullable=False),
    Column("metadata_json", Text),
    Column("created_at", DateTime, server_default=func.now()),
    Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
)


def connect():
    retries = max(1, int(_DB_CONNECT_RETRIES))
    delay_seconds = max(0.025, int(_DB_CONNECT_RETRY_DELAY_MS) / 1000.0)
    for attempt in range(retries):
        try:
            return engine.connect()
        except (OperationalError, SATimeoutError):
            if attempt >= retries - 1:
                raise
            time.sleep(delay_seconds * (attempt + 1))


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
        try:
            conn.execute(text("ALTER TABLE executions ADD COLUMN IF NOT EXISTS target_total INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE executions ADD COLUMN IF NOT EXISTS target_completed INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE executions ADD COLUMN IF NOT EXISTS target_success INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE executions ADD COLUMN IF NOT EXISTS target_failed INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE executions ADD COLUMN IF NOT EXISTS batch_size INTEGER DEFAULT 0"))
            conn.execute(
                text(
                    "ALTER TABLE scheduled_jobs "
                    "ADD COLUMN IF NOT EXISTS job_kind VARCHAR DEFAULT 'action'"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE scheduled_jobs "
                    "ADD COLUMN IF NOT EXISTS payload_json TEXT"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE execution_steps ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    """
                    UPDATE executions
                    SET
                        target_total = COALESCE(target_total, 0),
                        target_completed = COALESCE(target_completed, 0),
                        target_success = COALESCE(target_success, 0),
                        target_failed = COALESCE(target_failed, 0),
                        batch_size = COALESCE(batch_size, 0)
                    """
                )
            )
            conn.execute(
                text(
                    """
                    CREATE INDEX IF NOT EXISTS idx_executions_status_started
                    ON executions (status, started_at DESC)
                    """
                )
            )
        except Exception:
            pass

        # Best-effort schema evolution for existing deployments that already
        # have mitre_alerts without confidence/source metadata columns.
        try:
            conn.execute(text("ALTER TABLE mitre_alerts ADD COLUMN IF NOT EXISTS confidence INTEGER"))
            conn.execute(text("ALTER TABLE mitre_alerts ADD COLUMN IF NOT EXISTS source VARCHAR"))
            conn.execute(text("ALTER TABLE mitre_alerts ADD COLUMN IF NOT EXISTS mapping_rank INTEGER"))
            conn.execute(
                text(
                    "ALTER TABLE mitre_alerts ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
        except Exception:
            # Keep startup resilient if backend is pointed to a restricted/legacy DB.
            pass

        # Best-effort schema evolution for incident operations tables introduced in v1.1.
        try:
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS title VARCHAR"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS summary TEXT"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'open'"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS priority VARCHAR DEFAULT 'medium'"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS owner VARCHAR"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS due_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(
                text(
                    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS escalation_state "
                    "VARCHAR DEFAULT 'normal'"
                )
            )
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_key VARCHAR"))
            conn.execute(
                text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS first_event_time TIMESTAMP WITHOUT TIME ZONE")
            )
            conn.execute(
                text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_event_time TIMESTAMP WITHOUT TIME ZONE")
            )
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alert_count INTEGER DEFAULT 0"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS incident_id INTEGER"))
            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS alert_id VARCHAR"))
            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS agent_id VARCHAR"))
            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS tactic VARCHAR"))
            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS identity VARCHAR"))
            conn.execute(text("ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS matched_signals TEXT"))
            conn.execute(
                text(
                    "ALTER TABLE incident_alerts ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS incident_id INTEGER"))
            conn.execute(text("ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS previous_owner VARCHAR"))
            conn.execute(text("ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS new_owner VARCHAR"))
            conn.execute(text("ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS changed_by VARCHAR"))
            conn.execute(text("ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS note TEXT"))
            conn.execute(
                text(
                    "ALTER TABLE incident_assignments ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE incident_sla_events ADD COLUMN IF NOT EXISTS incident_id INTEGER"))
            conn.execute(text("ALTER TABLE incident_sla_events ADD COLUMN IF NOT EXISTS event_type VARCHAR"))
            conn.execute(text("ALTER TABLE incident_sla_events ADD COLUMN IF NOT EXISTS detail TEXT"))
            conn.execute(text("ALTER TABLE incident_sla_events ADD COLUMN IF NOT EXISTS actor VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE incident_sla_events ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
        except Exception:
            pass

        # Best-effort schema evolution for governance/context tables introduced in v1.1.
        try:
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS execution_id INTEGER"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS action_id VARCHAR"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS actor VARCHAR"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS target VARCHAR"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS started_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS classification VARCHAR"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS reason TEXT"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS context_json TEXT"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE execution_context ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS name VARCHAR"))
            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS description TEXT"))
            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE"))
            conn.execute(
                text(
                    "ALTER TABLE automation_context_profiles "
                    "ADD COLUMN IF NOT EXISTS classification VARCHAR DEFAULT 'review_required'"
                )
            )
            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS profile_json TEXT"))
            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE automation_context_profiles ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS execution_id INTEGER"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS alert_id VARCHAR"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS agent_id VARCHAR"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS classification VARCHAR"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS confidence INTEGER"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS reason TEXT"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS matched_profile_ids TEXT"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE alert_execution_correlation ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS alert_id VARCHAR"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS ioc VARCHAR"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS ioc_type VARCHAR"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS source VARCHAR"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS score INTEGER"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS confidence INTEGER"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS verdict VARCHAR"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS evidence_json TEXT"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS observed_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE ioc_enrichment_records ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS status VARCHAR"))
            conn.execute(text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS checked INTEGER DEFAULT 0"))
            conn.execute(
                text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS evidence_checked INTEGER DEFAULT 0")
            )
            conn.execute(
                text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS attachment_checked INTEGER DEFAULT 0")
            )
            conn.execute(
                text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS mismatches INTEGER DEFAULT 0")
            )
            conn.execute(
                text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS missing_files INTEGER DEFAULT 0")
            )
            conn.execute(text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS summary_json TEXT"))
            conn.execute(text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE forensic_integrity_sweeps ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS rule_id VARCHAR"))
            conn.execute(
                text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS rule_description VARCHAR")
            )
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS tactic VARCHAR"))
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS suggestion TEXT"))
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS confidence INTEGER"))
            conn.execute(
                text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'open'")
            )
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS source VARCHAR"))
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS context_json TEXT"))
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE detection_tuning_suggestions ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_key VARCHAR"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS name VARCHAR"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS description TEXT"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS rule_type VARCHAR DEFAULT 'atomic'"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS severity VARCHAR DEFAULT 'medium'"))
            conn.execute(
                text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS confidence_threshold INTEGER DEFAULT 60")
            )
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT TRUE"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS conditions_json TEXT"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS tags_json TEXT"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS tuning_json TEXT"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS rule_key VARCHAR"))
            conn.execute(
                text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS scope_type VARCHAR DEFAULT 'rule'")
            )
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS scope_value VARCHAR"))
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS reason TEXT"))
            conn.execute(
                text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'active'")
            )
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS starts_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS context_json TEXT"))
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE detection_suppressions ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS alert_id VARCHAR"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'open'"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS owner VARCHAR"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS classification VARCHAR"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS severity_override VARCHAR"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS notes TEXT"))
            conn.execute(text("ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS last_triaged_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE alert_triage ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS case_id INTEGER"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS response_due_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS resolution_due_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS target_response_minutes INTEGER"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS target_resolution_minutes INTEGER"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'active'"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS severity VARCHAR"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS breach_state VARCHAR DEFAULT 'on_track'"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS notes TEXT"))
            conn.execute(text("ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS updated_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE case_sla_policies ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE case_sla_events ADD COLUMN IF NOT EXISTS case_id INTEGER"))
            conn.execute(text("ALTER TABLE case_sla_events ADD COLUMN IF NOT EXISTS event_type VARCHAR"))
            conn.execute(text("ALTER TABLE case_sla_events ADD COLUMN IF NOT EXISTS detail TEXT"))
            conn.execute(text("ALTER TABLE case_sla_events ADD COLUMN IF NOT EXISTS actor VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE case_sla_events ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_agents INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_cases INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_incidents INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_approvals_per_day INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_executions_per_day INTEGER"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS config_json TEXT"))
            conn.execute(text("ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS updated_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )

            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS config_key VARCHAR"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS version INTEGER"))
            conn.execute(
                text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'draft'")
            )
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS config_json TEXT"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS notes TEXT"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS updated_by VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS activated_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(text("ALTER TABLE tenant_config_revisions ADD COLUMN IF NOT EXISTS retired_at TIMESTAMP WITHOUT TIME ZONE"))

            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS org_id INTEGER"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS data_class VARCHAR"))
            conn.execute(
                text(
                    "ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS storage_backend "
                    "VARCHAR DEFAULT 'event_indexer'"
                )
            )
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS stream VARCHAR"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS warm_after_days INTEGER"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS cold_after_days INTEGER"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS archive_after_days INTEGER"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS delete_after_days INTEGER"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS archive_backend VARCHAR"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN DEFAULT FALSE"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS status VARCHAR DEFAULT 'active'"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS notes TEXT"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS created_by VARCHAR"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS updated_by VARCHAR"))
            conn.execute(text("ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS last_applied_at TIMESTAMP WITHOUT TIME ZONE"))
            conn.execute(
                text(
                    "ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS created_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE retention_policies ADD COLUMN IF NOT EXISTS updated_at "
                    "TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW()"
                )
            )
        except Exception:
            pass

        try:
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incidents_owner ON incidents (owner)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incidents_due_at ON incidents (due_at)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incidents_org_id ON incidents (org_id)"))
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_incident_alerts_incident_alert "
                    "ON incident_alerts (incident_id, alert_id)"
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts (alert_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incident_assignments_incident_id ON incident_assignments (incident_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_incident_sla_events_incident_id ON incident_sla_events (incident_id)"))
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_context_execution_id "
                    "ON execution_context (execution_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_automation_context_profiles_org_enabled "
                    "ON automation_context_profiles (org_id, enabled)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_execution_correlation_exec_alert "
                    "ON alert_execution_correlation (execution_id, alert_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_alert_execution_correlation_execution_id "
                    "ON alert_execution_correlation (execution_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_alert_execution_correlation_alert_id "
                    "ON alert_execution_correlation (alert_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_enrichment_records_key "
                    "ON ioc_enrichment_records (alert_id, ioc, ioc_type, source)"
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_ioc_enrichment_records_alert_id ON ioc_enrichment_records (alert_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_forensic_integrity_sweeps_created_at ON forensic_integrity_sweeps (created_at)"))
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_detection_tuning_suggestions_status "
                    "ON detection_tuning_suggestions (status)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_detection_rules_org_rule_key "
                    "ON detection_rules (org_id, rule_key)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_detection_rules_org_enabled "
                    "ON detection_rules (org_id, enabled)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_detection_suppressions_status_expires "
                    "ON detection_suppressions (status, expires_at)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_detection_suppressions_org_scope "
                    "ON detection_suppressions (org_id, scope_type, rule_key)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_triage_org_alert "
                    "ON alert_triage (org_id, alert_id)"
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_alert_triage_org_status ON alert_triage (org_id, status)"))
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_case_sla_policies_case_id "
                    "ON case_sla_policies (case_id)"
                )
            )
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_case_sla_events_case_id ON case_sla_events (case_id)"))
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_quotas_org_id "
                    "ON tenant_quotas (org_id)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_config_revision "
                    "ON tenant_config_revisions (org_id, config_key, version)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_tenant_config_revision_lookup "
                    "ON tenant_config_revisions (org_id, config_key, status, version)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_event_ingestion_queue_status_next_attempt "
                    "ON event_ingestion_queue (status, next_attempt_at, id)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_event_ingestion_queue_tenant_stream "
                    "ON event_ingestion_queue (tenant_id, stream, id DESC)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_event_ingestion_queue_dedupe_key "
                    "ON event_ingestion_queue (tenant_id, stream, dedupe_key)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_retention_policies_org_data_class "
                    "ON retention_policies (org_id, data_class)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_retention_policies_org_status "
                    "ON retention_policies (org_id, status, data_class)"
                )
            )
            conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_runtime_state_scope "
                    "ON agent_runtime_state (tenant_scope, agent_id, state_kind)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_agent_runtime_state_agent_kind "
                    "ON agent_runtime_state (agent_id, state_kind, updated_at DESC)"
                )
            )
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_service_runtime_leases_expires "
                    "ON service_runtime_leases (lease_expires_at)"
                )
            )
        except Exception:
            pass

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
