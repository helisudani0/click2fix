import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from core.settings import SETTINGS


class ActionCapabilityResolver:
    """Resolves action capabilities and validates pre-execution requirements."""
    
    def __init__(self):
        self._action_cache = {}
    
    def get_action_capabilities(self, action_id: str) -> Dict[str, Any]:
        """Get capabilities for an action."""
        if action_id in self._action_cache:
            return self._action_cache[action_id]
        
        action = self._find_action(action_id)
        if not action:
            raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found")
        
        capabilities = action.get("capabilities", {})
        self._action_cache[action_id] = capabilities
        return capabilities
    
    def validate_action_prerequisites(
        self, 
        action_id: str, 
        agent_os: str, 
        args: List[str], 
        connector_status: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Validate all prerequisites for action execution."""
        errors = []
        
        # Get capabilities
        capabilities = self.get_action_capabilities(action_id)
        if not capabilities:
            errors.append(f"No capabilities defined for action '{action_id}'")
            return False, errors
        
        # Validate OS support
        supported_os = capabilities.get("supported_os", [])
        if supported_os and agent_os.lower() not in [os.lower() for os in supported_os]:
            errors.append(f"Action '{action_id}' not supported on OS: {agent_os}")
        
        # Validate required credentials
        requires_credentials = capabilities.get("requires_credentials", False)
        if requires_credentials:
            if agent_os.lower() == "windows":
                creds_configured = connector_status.get("connectors", {}).get("windows", {}).get("credentials_configured", False)
                if not creds_configured:
                    errors.append("Windows endpoint credentials not configured")
            elif agent_os.lower() == "linux":
                creds_configured = connector_status.get("connectors", {}).get("linux", {}).get("credentials_configured", False)
                if not creds_configured:
                    errors.append("Linux endpoint credentials not configured")
        
        # Validate arguments
        validation_errors = self._validate_arguments(action_id, args, capabilities)
        errors.extend(validation_errors)
        
        return len(errors) == 0, errors
    
    def resolve_preferred_channel(self, action_id: str, agent_os: str, connector_status: Dict[str, Any]) -> str:
        """Resolve the preferred execution channel for an action."""
        capabilities = self.get_action_capabilities(action_id)
        preferred_channel = capabilities.get("preferred_channel", "endpoint")
        
        # Check if preferred channel is available
        if preferred_channel == "manager_api":
            # Manager API is always available if Wazuh is reachable
            return "manager_api"
        
        elif preferred_channel == "endpoint":
            if agent_os.lower() == "windows":
                creds_configured = connector_status.get("connectors", {}).get("windows", {}).get("credentials_configured", False)
                if creds_configured:
                    return "endpoint"
            elif agent_os.lower() == "linux":
                creds_configured = connector_status.get("connectors", {}).get("linux", {}).get("credentials_configured", False)
                if creds_configured:
                    return "endpoint"
            # Fallback to active_response if endpoint not available
            return "active_response"
        
        elif preferred_channel == "active_response":
            # Active response is always available if enabled
            return "active_response"
        
        return "endpoint"  # Default fallback
    
    def get_timeout_seconds(self, action_id: str) -> int:
        """Get timeout for an action."""
        capabilities = self.get_action_capabilities(action_id)
        return capabilities.get("timeout_seconds", 120)
    
    def _find_action(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Find action configuration by ID."""
        cfg = SETTINGS.get("active_response", {}) if isinstance(SETTINGS, dict) else {}
        commands = cfg.get("commands", []) if isinstance(cfg, dict) else []
        
        for action in commands:
            if action.get("id") == action_id:
                return action
        return None
    
    def _validate_arguments(self, action_id: str, args: List[str], capabilities: Dict[str, Any]) -> List[str]:
        """Validate action arguments against capability requirements."""
        errors = []
        validation_rules = capabilities.get("validation", [])
        
        # Build argument mapping from action inputs
        action_config = self._find_action(action_id)
        if not action_config:
            return errors
        
        inputs = action_config.get("inputs", [])
        arg_map = {}
        for i, arg_value in enumerate(args):
            if i < len(inputs):
                field_name = inputs[i].get("name")
                if field_name:
                    arg_map[field_name] = arg_value
        
        # Validate each rule
        for rule in validation_rules:
            field = rule.get("field")
            field_type = rule.get("type")
            required = rule.get("required", False)
            description = rule.get("description", "")
            
            if field not in arg_map:
                if required:
                    errors.append(f"Required argument '{field}' missing: {description}")
                continue
            
            value = arg_map[field]
            field_errors = self._validate_field(field, value, field_type, rule)
            errors.extend(field_errors)
        
        return errors
    
    def _validate_field(self, field: str, value: Any, field_type: str, rule: Dict[str, Any]) -> List[str]:
        """Validate a single field value."""
        errors = []
        
        if field_type == "ip_address":
            try:
                ipaddress.ip_address(str(value))
            except ValueError:
                errors.append(f"Invalid IP address for '{field}': {value}")
        
        elif field_type == "integer":
            try:
                num = int(value)
                min_val = rule.get("min")
                max_val = rule.get("max")
                if min_val is not None and num < min_val:
                    errors.append(f"Value for '{field}' too small: {num} < {min_val}")
                if max_val is not None and num > max_val:
                    errors.append(f"Value for '{field}' too large: {num} > {max_val}")
            except ValueError:
                errors.append(f"Invalid integer for '{field}': {value}")
        
        elif field_type == "string":
            min_length = rule.get("min_length", 1)
            max_length = rule.get("max_length", 1000)
            if not isinstance(value, str):
                errors.append(f"Expected string for '{field}', got: {type(value).__name__}")
            elif len(value) < min_length:
                errors.append(f"String too short for '{field}': {len(value)} < {min_length}")
            elif len(value) > max_length:
                errors.append(f"String too long for '{field}': {len(value)} > {max_length}")
        
        elif field_type == "enum":
            values = rule.get("values", [])
            if str(value) not in [str(v) for v in values]:
                errors.append(f"Invalid value for '{field}': {value}. Must be one of: {values}")
        
        elif field_type == "file_path":
            # Basic path validation - could be enhanced with actual file system checks
            if not value or not isinstance(value, str):
                errors.append(f"Invalid file path for '{field}': {value}")
        
        elif field_type == "sha256_hash":
            if not re.match(r'^[a-fA-F0-9]{64}$', str(value)):
                errors.append(f"Invalid SHA256 hash for '{field}': {value}")
        
        elif field_type == "kb_number":
            kb_str = str(value).upper().replace("KB", "")
            if not kb_str.isdigit():
                errors.append(f"Invalid KB number for '{field}': {value}")
        
        return errors
    
    def get_action_capability_summary(self, action_id: str) -> Dict[str, Any]:
        """Get a summary of action capabilities for UI display."""
        capabilities = self.get_action_capabilities(action_id)
        
        return {
            "action_id": action_id,
            "supported_os": capabilities.get("supported_os", []),
            "preferred_channel": capabilities.get("preferred_channel", "endpoint"),
            "requires_credentials": capabilities.get("requires_credentials", False),
            "requires_network": capabilities.get("requires_network", False),
            "timeout_seconds": capabilities.get("timeout_seconds", 120),
            "validation_rules": capabilities.get("validation", []),
            "has_validation": len(capabilities.get("validation", [])) > 0
        }


# Global instance
capability_resolver = ActionCapabilityResolver()