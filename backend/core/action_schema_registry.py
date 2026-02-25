"""
Execution Schema Registry: Define all C2F actions with strict JSON schemas.

This module provides:
1. Centralized action metadata & schema validation
2. Capability matrix for fleet orchestration
3. Standardized output validation
4. Idempotency rules per action
"""

import json
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod


class OutputStatus(str, Enum):
    """Output status field values."""
    SUCCESS = "SUCCESS"
    SUCCESS_NO_CHANGE = "SUCCESS_NO_CHANGE"
    FAILED = "FAILED"
    FAILED_SOURCE_UNAVAILABLE = "FAILED_SOURCE_UNAVAILABLE"
    FAILED_INSUFFICIENT_MEMORY = "FAILED_INSUFFICIENT_MEMORY"
    FAILED_REBOOT_INTERRUPTED = "FAILED_REBOOT_INTERRUPTED"
    PARTIAL = "PARTIAL"


class IdempotencyMode(str, Enum):
    """Idempotency strategy."""
    ALWAYS_RUN = "always_run"  # No idempotency check
    STATE_AWARE = "state_aware"  # Check state first
    SKIP_IF_RECENT = "skip_if_recent"  # Skip if run recently
    ATOMIC = "atomic"  # All-or-nothing


@dataclass
class OutputSchema:
    """Standardized output schema for all actions."""
    status: str  # OutputStatus value
    exit_code: int
    reboot_required: bool
    matches_found: int
    artifact_url: Optional[str]
    stdout: str
    stderr: str
    metadata: Dict[str, Any]
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "reboot_required": self.reboot_required,
            "matches_found": self.matches_found,
            "artifact_url": self.artifact_url,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "metadata": self.metadata,
            "error_message": self.error_message,
        }


@dataclass
class ActionInput:
    """Action parameter definition."""
    name: str
    type: str  # string, int, bool, array, object
    required: bool = False
    default: Any = None
    description: str = ""
    validation_regex: Optional[str] = None
    enum_values: Optional[List[Any]] = None
    
    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate input against schema."""
        if not self.required and value is None:
            return True, None
        
        if value is None and self.required:
            return False, f"Missing required parameter: {self.name}"
        
        # Type check
        type_map = {
            "string": str,
            "int": int,
            "bool": bool,
            "array": list,
            "object": dict,
        }
        
        if self.type in type_map and not isinstance(value, type_map[self.type]):
            return False, f"Parameter {self.name} must be {self.type}"
        
        # Enum check
        if self.enum_values and value not in self.enum_values:
            return False, f"Parameter {self.name} must be one of: {self.enum_values}"
        
        # Regex validation
        if self.validation_regex and isinstance(value, str):
            import re
            if not re.match(self.validation_regex, value):
                return False, f"Parameter {self.name} format invalid"
        
        return True, None


@dataclass
class IdempotencyRule:
    """Define how to check idempotency for an action."""
    mode: IdempotencyMode
    
    # For STATE_AWARE: function to check current state
    state_checker: Optional[Callable] = None
    
    # For SKIP_IF_RECENT: how many seconds to consider "recent"
    recent_threshold_seconds: int = 3600
    
    # Cache key pattern (e.g., "firewall_rule:{rule_name}")
    cache_key_pattern: Optional[str] = None


@dataclass
class ActionCapability:
    """Complete action capability definition."""
    id: str
    label: str
    description: str
    category: str  # patching, forensics, hunting, remediation, etc.
    risk_level: str  # low, medium, high, critical
    supported_platforms: List[str]  # windows, linux
    requires_approval: bool = False
    requires_agent_credentials: bool = False
    requires_network: bool = True
    timeout_seconds: int = 300
    inputs: List[ActionInput] = field(default_factory=list)
    idempotency: IdempotencyRule = field(default_factory=lambda: IdempotencyRule(IdempotencyMode.ALWAYS_RUN))
    
    # Wazuh integration
    triggers_sca_rescan: bool = False  # Auto-trigger SCA verification after
    wazuh_module: Optional[str] = None  # Module to verify (e.g., "vulnerability_detector")
    
    # Expected output schema
    output_schema: Optional[Dict[str, Any]] = None
    
    def validate_inputs(self, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate action arguments."""
        for input_def in self.inputs:
            value = args.get(input_def.name)
            is_valid, error_msg = input_def.validate(value)
            if not is_valid:
                return False, error_msg
        return True, None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to JSON."""
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "category": self.category,
            "risk_level": self.risk_level,
            "supported_platforms": self.supported_platforms,
            "requires_approval": self.requires_approval,
            "requires_agent_credentials": self.requires_agent_credentials,
            "requires_network": self.requires_network,
            "timeout_seconds": self.timeout_seconds,
            "inputs": [
                {
                    "name": inp.name,
                    "type": inp.type,
                    "required": inp.required,
                    "default": inp.default,
                    "description": inp.description,
                }
                for inp in self.inputs
            ],
            "idempotency_mode": self.idempotency.mode.value,
            "triggers_sca_rescan": self.triggers_sca_rescan,
            "wazuh_module": self.wazuh_module,
        }


class ActionRegistry:
    """Central registry of all C2F actions."""
    
    def __init__(self):
        self._actions: Dict[str, ActionCapability] = {}
        self._init_capabilities()
    
    def _init_capabilities(self) -> None:
        """Initialize all action definitions."""
        
        # Patching/Remediation Actions
        self.register(ActionCapability(
            id="package-update",
            label="Update Package",
            description="Install/upgrade a specific package via winget (Windows) or apt (Linux)",
            category="patching",
            risk_level="high",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            requires_agent_credentials=True,
            timeout_seconds=3600,
            inputs=[
                ActionInput(
                    name="package",
                    type="string",
                    required=True,
                    description="Package ID (Windows: winget ID format) or package name (Linux)",
                )
            ],
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                cache_key_pattern="package_installed:{package}:{agent_id}",
                recent_threshold_seconds=86400,  # 24 hours
            ),
            triggers_sca_rescan=True,
            wazuh_module="vulnerability_detector",
        ))
        
        self.register(ActionCapability(
            id="fleet-software-update",
            label="Fleet Software Update",
            description="Apply all pending OS/software updates",
            category="patching",
            risk_level="high",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            requires_agent_credentials=True,
            timeout_seconds=3600,
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                recent_threshold_seconds=3600,
            ),
            triggers_sca_rescan=True,
            wazuh_module="vulnerability_detector",
        ))

        self.register(ActionCapability(
            id="software-install-upgrade",
            label="Install/Upgrade Specific Software",
            description="Install/upgrade specific software package(s) on selected endpoints",
            category="patching",
            risk_level="high",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            requires_agent_credentials=True,
            timeout_seconds=3600,
            inputs=[
                ActionInput(
                    name="package",
                    type="string",
                    required=True,
                    description="Package ID (Windows: winget ID format) or package name (Linux)",
                ),
                ActionInput(
                    name="version",
                    type="string",
                    required=False,
                    description="Optional version specifier",
                ),
            ],
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                cache_key_pattern="package_installed:{package}:{agent_id}",
                recent_threshold_seconds=86400,  # 24 hours
            ),
            triggers_sca_rescan=True,
            wazuh_module="vulnerability_detector",
        ))

        self.register(ActionCapability(
            id="custom-os-command",
            label="Internal Global Shell Transport",
            description="Internal transport for executing shell payloads on selected endpoints",
            category="patching",
            risk_level="critical",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            requires_agent_credentials=True,
            timeout_seconds=1800,
            inputs=[
                ActionInput(
                    name="command",
                    type="string",
                    required=True,
                    description="Custom OS command to execute",
                ),
                ActionInput(
                    name="verify_kb",
                    type="string",
                    required=False,
                    description="Windows only: required KB that must be present after command (e.g., KB5075912)",
                ),
                ActionInput(
                    name="verify_min_build",
                    type="string",
                    required=False,
                    description="Windows only: minimum OS build required after command (e.g., 19045.6937)",
                ),
                ActionInput(
                    name="verify_stdout_contains",
                    type="string",
                    required=False,
                    description="Require command output to contain this text",
                ),
                ActionInput(
                    name="run_as_system",
                    type="boolean",
                    required=False,
                    description="Run under SYSTEM scheduled-task context (Windows only)",
                ),
            ],
            idempotency=IdempotencyRule(mode=IdempotencyMode.ALWAYS_RUN),
            triggers_sca_rescan=True,
            wazuh_module=None,
        ))

        self.register(ActionCapability(
            id="windows-os-update",
            label="Windows OS Security Update",
            description="Apply Windows OS/security updates with non-target update filtering",
            category="patching",
            risk_level="high",
            supported_platforms=["windows"],
            requires_approval=True,
            requires_agent_credentials=True,
            timeout_seconds=3600,
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                recent_threshold_seconds=1800,
            ),
            triggers_sca_rescan=True,
            wazuh_module="vulnerability_detector",
        ))
        
        # Forensics Actions
        self.register(ActionCapability(
            id="collect-memory",
            label="Collect Memory Dump",
            description="Capture process memory for forensics (requires 500MB+ free RAM)",
            category="forensics",
            risk_level="medium",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            timeout_seconds=900,
            inputs=[
                ActionInput(
                    name="process_id",
                    type="int",
                    required=False,
                    description="PID to capture (empty = all suspicious)",
                )
            ],
            idempotency=IdempotencyRule(mode=IdempotencyMode.ALWAYS_RUN),
        ))
        
        self.register(ActionCapability(
            id="threat-hunt-persistence",
            label="Threat Hunt: Persistence Mechanisms",
            description="Scan for persistence (scheduled tasks, WMI, services, autorun)",
            category="hunting",
            risk_level="low",
            supported_platforms=["windows", "linux"],
            timeout_seconds=600,
            inputs=[
                ActionInput(
                    name="include_signatures",
                    type="bool",
                    required=False,
                    default=True,
                    description="Verify digital signatures",
                )
            ],
            idempotency=IdempotencyRule(mode=IdempotencyMode.ALWAYS_RUN),
        ))
        
        self.register(ActionCapability(
            id="toc-scan",
            label="TOC Scan (ThreatHunter/OSQuery)",
            description="Run comprehensive threat-of-compromise scan",
            category="hunting",
            risk_level="low",
            supported_platforms=["windows", "linux"],
            timeout_seconds=900,
        ))
        
        # Containment Actions
        self.register(ActionCapability(
            id="kill-process",
            label="Kill Process",
            description="Terminate suspicious process by PID or name",
            category="remediation",
            risk_level="high",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            timeout_seconds=60,
            inputs=[
                ActionInput(
                    name="process_identifier",
                    type="string",
                    required=True,
                    description="Process PID or name",
                )
            ],
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                cache_key_pattern="process_killed:{process_identifier}:{agent_id}",
                recent_threshold_seconds=300,
            ),
        ))
        
        self.register(ActionCapability(
            id="firewall-drop",
            label="Firewall Drop Rule",
            description="Add firewall rule to block IP/port",
            category="remediation",
            risk_level="high",
            supported_platforms=["windows", "linux"],
            requires_approval=True,
            timeout_seconds=120,
            inputs=[
                ActionInput(name="ip_address", type="string", required=True),
                ActionInput(name="port", type="int", required=False),
                ActionInput(name="direction", type="string", required=False, enum_values=["inbound", "outbound"]),
            ],
            idempotency=IdempotencyRule(
                mode=IdempotencyMode.STATE_AWARE,
                cache_key_pattern="firewall_rule:{ip_address}:{port}:{agent_id}",
            ),
        ))
        
        # Verification Actions
        self.register(ActionCapability(
            id="endpoint-healthcheck",
            label="Endpoint Healthcheck",
            description="Verify connectivity, OS, agent version",
            category="verification",
            risk_level="low",
            supported_platforms=["windows", "linux"],
            timeout_seconds=60,
            idempotency=IdempotencyRule(mode=IdempotencyMode.ALWAYS_RUN),
        ))
        
        self.register(ActionCapability(
            id="sca-rescan",
            label="Rescan Compliance/SCA",
            description="Trigger Wazuh SCA module to refresh vulnerability scan",
            category="verification",
            risk_level="low",
            supported_platforms=["windows", "linux"],
            timeout_seconds=300,
            triggers_sca_rescan=True,
            wazuh_module="vulnerability_detector",
        ))
    
    def register(self, capability: ActionCapability) -> None:
        """Register an action capability."""
        self._actions[capability.id] = capability
    
    def get(self, action_id: str) -> Optional[ActionCapability]:
        """Get action capability by ID."""
        return self._actions.get(action_id)
    
    def list_all(self) -> Dict[str, ActionCapability]:
        """List all registered actions."""
        return self._actions.copy()
    
    def list_by_platform(self, platform: str) -> List[ActionCapability]:
        """Get actions supported on given platform."""
        return [
            cap for cap in self._actions.values()
            if platform in cap.supported_platforms
        ]
    
    def list_by_category(self, category: str) -> List[ActionCapability]:
        """Get actions in given category."""
        return [
            cap for cap in self._actions.values()
            if cap.category == category
        ]


# Global registry instance
action_registry = ActionRegistry()


def get_action_capability(action_id: str) -> Optional[ActionCapability]:
    """Get action capability from global registry."""
    return action_registry.get(action_id)


def validate_action_input(action_id: str, args: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Validate action arguments."""
    capability = get_action_capability(action_id)
    if not capability:
        return False, f"Unknown action: {action_id}"
    
    return capability.validate_inputs(args)
