"""
Standardized Output Schema for all Click2Fix Actions.
Ensures all actions return structured, predictable results with:
  - status (SUCCESS, FAILED, PARTIAL, PENDING_REBOOT)
  - exit_code (0, 1, 3 for reboot, etc.)
  - reboot_required (bool)
  - matches_found (count)
  - artifact_url (cloud-uploaded path)
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
import json
import uuid

from core.time_utils import utc_iso_now, utc_now


class ActionStatus(str, Enum):
    """All possible action execution states."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    PENDING_REBOOT = "PENDING_REBOOT"
    FAILED_REBOOT_INTERRUPTED = "FAILED_REBOOT_INTERRUPTED"
    SUCCESS_NO_CHANGE = "SUCCESS_NO_CHANGE"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"


class ExitCode(int, Enum):
    """Standard exit codes for Windows actions."""
    SUCCESS = 0
    GENERAL_ERROR = 1
    MISUSE_ERROR = 2
    REBOOT_REQUIRED = 3
    TIMEOUT = 124
    CANCELLED = 137


@dataclass
class ActionResult:
    """
    Universal result schema for all C2F actions.
    Guarantees consistent structure across all remediation & forensics actions.
    """
    action_id: str
    exec_id: str
    agent_id: str
    timestamp: str = field(default_factory=utc_iso_now)
    
    # Status & Exit Information
    status: ActionStatus = ActionStatus.FAILED
    exit_code: int = 1
    reboot_required: bool = False
    reboot_scheduled: bool = False
    
    # Forensics & Hunt Results
    matches_found: int = 0
    artifacts: List[Dict[str, str]] = field(default_factory=list)  # [{"type": "report", "url": "..."}, ...]
    
    # Execution Metadata
    duration_seconds: float = 0.0
    hostname: Optional[str] = None
    username: Optional[str] = None
    
    # Action-Specific Details
    action_output: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    warning_message: Optional[str] = None
    
    # For state reconciliation
    state_before: Optional[Dict[str, Any]] = None
    state_after: Optional[Dict[str, Any]] = None
    state_changed: bool = False
    
    # For audit trail
    audit_trail: List[str] = field(default_factory=list)
    
    def to_json(self) -> str:
        """Serialize to JSON with safe encoding."""
        return json.dumps(asdict(self), default=str, ensure_ascii=False)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ActionResult":
        """Deserialize from dictionary."""
        # Convert string status to enum
        if isinstance(data.get("status"), str):
            data["status"] = ActionStatus(data["status"])
        return ActionResult(**{k: v for k, v in data.items() if k in ActionResult.__dataclass_fields__})


@dataclass
class StateSnapshot:
    """
    Represents system state at a point in time for idempotency checks.
    """
    firewall_rules: Dict[str, Any] = field(default_factory=dict)
    installed_packages: Dict[str, str] = field(default_factory=dict)  # {package_id: version}
    registry_keys: Dict[str, Any] = field(default_factory=dict)
    process_hashes: List[str] = field(default_factory=list)
    services_status: Dict[str, str] = field(default_factory=dict)  # {service_name: status}
    pending_reboots: bool = False
    timestamp: str = field(default_factory=utc_iso_now)
    
    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, ensure_ascii=False)
    
    @staticmethod
    def from_json(data: str) -> "StateSnapshot":
        d = json.loads(data)
        return StateSnapshot(**{k: v for k, v in d.items() if k in StateSnapshot.__dataclass_fields__})


class ArtifactUploadTarget:
    """Defines where forensics artifacts are uploaded."""
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url  # e.g., "https://c2f-api.internal/artifacts"
        self.api_key = api_key
    
    def get_upload_url(self, artifact_id: str) -> str:
        """Generate upload URL for artifact."""
        return f"{self.base_url}/{artifact_id}"


class ExecutionReconciliationState:
    """
    Tracks multi-agent fleet execution with TTL-aware resumption.
    If agent disconnects mid-action, this allows detection & auto-resume.
    """
    def __init__(self):
        self.executions: Dict[str, Dict[str, Any]] = {}  # {exec_id: {agent_id: {...}}}
    
    def record_execution(self, exec_id: str, agent_id: str, status: str, ttl_seconds: int = 3600):
        """Record agent execution with TTL."""
        if exec_id not in self.executions:
            self.executions[exec_id] = {}
        
        self.executions[exec_id][agent_id] = {
            "status": status,
            "timestamp": utc_iso_now(),
            "ttl_expires": (utc_now().timestamp() + ttl_seconds),
        }
    
    def check_reboot_interrupted(self, exec_id: str, agent_id: str) -> bool:
        """Check if execution was interrupted by reboot."""
        exec_record = self.executions.get(exec_id, {}).get(agent_id, {})
        if not exec_record:
            return False
        
        # If status is RUNNING but TTL expired without heartbeat, it was interrupted
        if exec_record.get("status") == "RUNNING":
            if utc_now().timestamp() > exec_record.get("ttl_expires", 0):
                return True
        return False
    
    def is_idempotent_safe(self, exec_id: str, agent_id: str) -> bool:
        """Check if it's safe to retry without causing double-execution."""
        exec_record = self.executions.get(exec_id, {}).get(agent_id, {})
        return exec_record.get("status") in [None, "PENDING_REBOOT", "RUNNING"]


# Global reconciliation state (in production, use Redis or persistent DB)
RECONCILIATION_STATE = ExecutionReconciliationState()
