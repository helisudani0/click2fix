import logging
import asyncio
import re
from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class ActionState(Enum):
    ALREADY_APPLIED = "already_applied"
    NEEDS_APPLICATION = "needs_application"
    PARTIAL = "partial"
    UNKNOWN = "unknown"

@dataclass
class IdempotencyCheckResult:
    action: str
    state: ActionState
    current_value: Optional[str]
    expected_value: str
    change_required: bool
    reason: str

class IdempotentActions:
    """Idempotency checking with state lookup for firewall and SELinux actions."""
    
    async def check_idempotency(
        self,
        action: str,
        target: str,
        expected_state: str,
        executor_func = None
    ) -> IdempotencyCheckResult:
        """
        Check if action is already applied (idempotent check).
        
        Args:
            action: "firewall-drop" or "selinux-enforce"
            target: Rule target (IP/port for firewall, context for SELinux)
            expected_state: Expected state (e.g., "DROP", "enforcing")
            executor_func: Async function to query system state
        
        Returns:
            IdempotencyCheckResult with current state and change requirement
        """
        if action == "firewall-drop":
            return await self._check_firewall_drop(target, expected_state, executor_func)
        elif action == "selinux-enforce":
            return await self._check_selinux_enforce(target, expected_state, executor_func)
        else:
            return IdempotencyCheckResult(
                action=action,
                state=ActionState.UNKNOWN,
                current_value=None,
                expected_value=expected_state,
                change_required=False,
                reason=f"Unknown action type: {action}"
            )
    
    async def _check_firewall_drop(
        self,
        target: str,
        expected_state: str,
        executor_func
    ) -> IdempotencyCheckResult:
        """
        Check firewall DROP rule idempotency.
        Parse iptables/firewalld output to detect existing rules.
        """
        try:
            # Query firewall state
            if executor_func:
                output = await executor_func("iptables-list")
            else:
                output = await self._query_firewall_rules()
            
            # Parse target from rule (e.g., "192.168.1.100" or "192.168.1.0/24:22")
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', target)
            if not ip_match:
                return IdempotencyCheckResult(
                    action="firewall-drop",
                    state=ActionState.UNKNOWN,
                    current_value=None,
                    expected_value=expected_state,
                    change_required=True,
                    reason="Could not parse target IP/CIDR"
                )
            
            target_ip = ip_match.group(1)
            
            # Check if rule exists in output
            rule_pattern = rf'{target_ip}.*(?:DROP|REJECT|DENY)'
            existing_rules = re.findall(rule_pattern, output, re.IGNORECASE)
            
            if existing_rules:
                # Rule already exists
                current_state = "DROP"
                return IdempotencyCheckResult(
                    action="firewall-drop",
                    state=ActionState.ALREADY_APPLIED,
                    current_value=current_state,
                    expected_value=expected_state,
                    change_required=False,
                    reason=f"Rule already exists for {target_ip}"
                )
            else:
                # Rule does not exist
                return IdempotencyCheckResult(
                    action="firewall-drop",
                    state=ActionState.NEEDS_APPLICATION,
                    current_value=None,
                    expected_value=expected_state,
                    change_required=True,
                    reason=f"No DROP rule found for {target_ip}"
                )
        
        except Exception as e:
            logger.error(f"Firewall idempotency check failed: {e}")
            return IdempotencyCheckResult(
                action="firewall-drop",
                state=ActionState.UNKNOWN,
                current_value=None,
                expected_value=expected_state,
                change_required=True,
                reason=f"Error checking firewall state: {str(e)}"
            )
    
    async def _check_selinux_enforce(
        self,
        target: str,
        expected_state: str,
        executor_func
    ) -> IdempotencyCheckResult:
        """
        Check SELinux enforcement idempotency.
        Check both global and file-specific contexts.
        """
        try:
            if executor_func:
                # Query SELinux current mode
                getenforce_output = await executor_func("getenforce")
            else:
                getenforce_output = await self._query_selinux_status()
            
            current_mode = getenforce_output.strip().lower()
            expected_mode = expected_state.lower()
            
            # Check global enforcement mode
            if current_mode == expected_mode:
                return IdempotencyCheckResult(
                    action="selinux-enforce",
                    state=ActionState.ALREADY_APPLIED,
                    current_value=current_mode,
                    expected_value=expected_state,
                    change_required=False,
                    reason=f"SELinux already in {current_mode} mode"
                )
            
            # Check if target is a file context
            if target and target != "global":
                if executor_func:
                    context_output = await executor_func(f"semanage fcontext -l | grep {target}")
                else:
                    context_output = await self._query_file_context(target)
                
                if context_output and expected_mode in context_output.lower():
                    return IdempotencyCheckResult(
                        action="selinux-enforce",
                        state=ActionState.ALREADY_APPLIED,
                        current_value=expected_mode,
                        expected_value=expected_state,
                        change_required=False,
                        reason=f"File context already set for {target}"
                    )
            
            return IdempotencyCheckResult(
                action="selinux-enforce",
                state=ActionState.NEEDS_APPLICATION,
                current_value=current_mode,
                expected_value=expected_state,
                change_required=True,
                reason=f"SELinux mode change required: {current_mode} -> {expected_mode}"
            )
        
        except Exception as e:
            logger.error(f"SELinux idempotency check failed: {e}")
            return IdempotencyCheckResult(
                action="selinux-enforce",
                state=ActionState.UNKNOWN,
                current_value=None,
                expected_value=expected_state,
                change_required=True,
                reason=f"Error checking SELinux state: {str(e)}"
            )
    
    async def _query_firewall_rules(self) -> str:
        """Query current firewall rules."""
        # Placeholder: actual implementation would call iptables/firewalld
        return ""
    
    async def _query_selinux_status(self) -> str:
        """Query current SELinux enforcement status."""
        # Placeholder: actual implementation would call getenforce
        return "enforcing"
    
    async def _query_file_context(self, target: str) -> str:
        """Query file-specific SELinux context."""
        # Placeholder: actual implementation would call semanage fcontext
        return ""
