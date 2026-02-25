"""
Database schema extensions for state-aware execution tracking.

New tables:
- execution_state: TTL-based execution state tracking
- agent_state: Current agent status & health
- reboot_requirements: Track pending/scheduled reboots
- action_idempotency_cache: State-aware deduplication
- orphaned_executions: Recovery queue for disconnected agents
"""

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
    ForeignKey,
    Index,
    func,
    text,
)


def get_state_tracking_tables(metadata: MetaData):
    """Define state tracking tables."""
    
    # Execution state with TTL
    execution_state = Table(
        "execution_state",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("execution_id", String, unique=True, nullable=False, index=True),
        Column("action_id", String, nullable=False),
        Column("agent_id", String, nullable=False),
        Column("agent_name", String),
        Column("platform", String),
        Column("status", String, nullable=False),  # PENDING, RUNNING, COMPLETED, FAILED, etc.
        Column("result", String),  # SUCCESS, FAILED, PARTIAL, FAILED_SOURCE_UNAVAILABLE, etc.
        Column("exit_code", Integer),
        Column("reboot_required", Boolean, server_default=text("false")),
        Column("matches_found", Integer, server_default=text("0")),
        Column("artifact_url", Text),
        Column("stdout", Text),
        Column("stderr", Text),
        Column("error_message", Text),
        Column("metadata", Text),  # JSON: tags, fleet_index, context
        Column("created_at", DateTime, server_default=func.now()),
        Column("expires_at", DateTime, nullable=False),  # TTL boundary
        Column("started_at", DateTime),
        Column("completed_at", DateTime),
        Index("idx_execution_state_agent_created", "agent_id", "created_at"),
        Index("idx_execution_state_expires", "expires_at"),
    )
    
    # Current agent state & health
    agent_state = Table(
        "agent_state",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("agent_id", String, unique=True, nullable=False),
        Column("agent_name", String),
        Column("platform", String),
        Column("ip_address", String),
        Column("online_status", String),  # online, offline, disconnected
        Column("last_heartbeat", DateTime),
        Column("has_pending_reboot", Boolean, server_default=text("false")),
        Column("reboot_reason", String),  # patch, update, manual, system
        Column("free_memory_mb", Integer),
        Column("last_action_status", String),
        Column("last_action_time", DateTime),
        Column("consecutive_failures", Integer, server_default=text("0")),
        Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
        Index("idx_agent_state_online", "online_status"),
        Index("idx_agent_state_reboot", "has_pending_reboot"),
    )
    
    # Track reboot requirements
    reboot_requirements = Table(
        "reboot_requirements",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("agent_id", String, nullable=False),
        Column("execution_id", String),
        Column("reboot_reason", String),  # patch_installed, update_installed, manual
        Column("scheduled_for", DateTime),
        Column("status", String, server_default=text("'PENDING'")),  # PENDING, SCHEDULED, COMPLETED
        Column("acknowledged_by", String),
        Column("prevent_until", DateTime),  # Block further actions until this time
        Column("created_at", DateTime, server_default=func.now()),
        Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
        Index("idx_reboot_req_agent", "agent_id"),
        Index("idx_reboot_req_status", "status"),
    )
    
    # Idempotency cache: store state for recent actions
    action_idempotency_cache = Table(
        "action_idempotency_cache",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("cache_key", String, nullable=False, unique=True),  # e.g., "package_installed:vim:agent001"
        Column("action_id", String, nullable=False),
        Column("agent_id", String, nullable=False),
        Column("execution_id", String),
        Column("action_state", String),  # applied, skipped, failed
        Column("result_data", Text),  # JSON of last successful execution
        Column("last_execution_time", DateTime),
        Column("expires_at", DateTime),  # Auto-cleanup
        Column("created_at", DateTime, server_default=func.now()),
        Index("idx_idempotency_agent_action", "agent_id", "action_id"),
        Index("idx_idempotency_expires", "expires_at"),
    )
    
    # Orphaned/zombie execution recovery
    orphaned_executions = Table(
        "orphaned_executions",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("execution_id", String, unique=True, nullable=False),
        Column("action_id", String, nullable=False),
        Column("agent_id", String, nullable=False),
        Column("agent_name", String),
        Column("expiry_reason", String),  # TTL_EXCEEDED, DISCONNECTED, TIMEOUT
        Column("discovered_at", DateTime),
        Column("recovery_attempted_at", DateTime),
        Column("recovery_status", String),  # PENDING, ATTEMPTED, RESOLVED, FAILED
        Column("recovery_message", Text),
        Column("automation_context", Text),  # JSON context for auto-repair
        Column("created_at", DateTime, server_default=func.now()),
        Column("updated_at", DateTime, server_default=func.now(), onupdate=func.now()),
        Index("idx_orphan_status", "recovery_status"),
        Index("idx_orphan_agent", "agent_id"),
    )
    
    # Action execution history (for deduplication & trending)
    action_execution_history = Table(
        "action_execution_history",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("execution_id", String),
        Column("action_id", String, nullable=False),
        Column("agent_id", String, nullable=False),
        Column("status", String),  # completed, failed
        Column("result", String),  # SUCCESS, FAILED, etc.
        Column("exit_code", Integer),
        Column("duration_seconds", Integer),
        Column("reboot_required", Boolean),
        Column("matches_found", Integer),
        Column("executed_at", DateTime, server_default=func.now()),
        Index("idx_execution_history_agent_action", "agent_id", "action_id", "executed_at"),
        Index("idx_execution_history_recent", "executed_at"),
    )
    
    return {
        "execution_state": execution_state,
        "agent_state": agent_state,
        "reboot_requirements": reboot_requirements,
        "action_idempotency_cache": action_idempotency_cache,
        "orphaned_executions": orphaned_executions,
        "action_execution_history": action_execution_history,
    }
