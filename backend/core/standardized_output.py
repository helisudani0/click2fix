"""
Standardized JSON Output Schema Validator

All C2F actions must return a strict schema for consistency and integration.

Standard Output Format:
{
    "status": "SUCCESS|FAILED|SUCCESS_NO_CHANGE|PARTIAL",
    "exit_code": 0,
    "reboot_required": false,
    "matches_found": 0,
    "artifact_url": null,
    "stdout": "...",
    "stderr": "...",
    "metadata": {...},
    "error_message": null,
    "timestamp": "2026-02-17T00:00:00Z"
}
"""

import json
import logging
from typing import Any, Dict, Optional
from enum import Enum

from core.time_utils import utc_iso_now

logger = logging.getLogger(__name__)


class OutputStatus(str, Enum):
    """Standardized status values."""
    SUCCESS = "SUCCESS"
    SUCCESS_NO_CHANGE = "SUCCESS_NO_CHANGE"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    FAILED_SOURCE_UNAVAILABLE = "FAILED_SOURCE_UNAVAILABLE"
    FAILED_INSUFFICIENT_MEMORY = "FAILED_INSUFFICIENT_MEMORY"
    FAILED_REBOOT_INTERRUPTED = "FAILED_REBOOT_INTERRUPTED"


class StandardizedOutput:
    """Enforce and validate standardized JSON output."""
    
    REQUIRED_FIELDS = {
        "status",
        "exit_code",
        "reboot_required",
        "matches_found",
        "artifact_url",
        "stdout",
        "stderr",
        "metadata",
    }
    
    OPTIONAL_FIELDS = {"error_message", "timestamp"}
    
    FIELD_TYPES = {
        "status": str,
        "exit_code": int,
        "reboot_required": bool,
        "matches_found": int,
        "artifact_url": (str, type(None)),
        "stdout": str,
        "stderr": str,
        "metadata": dict,
        "error_message": (str, type(None)),
        "timestamp": str,
    }
    
    @classmethod
    def validate(cls, data: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate output conforms to schema.
        Returns: (is_valid, error_message)
        """
        if not isinstance(data, dict):
            return False, "Output must be a dictionary"
        
        # Check required fields
        missing = cls.REQUIRED_FIELDS - set(data.keys())
        if missing:
            return False, f"Missing required fields: {missing}"
        
        # Check field types
        for field, expected_type in cls.FIELD_TYPES.items():
            if field not in data:
                continue
            
            value = data[field]
            if not isinstance(value, expected_type):
                return False, f"Field '{field}' has wrong type: {type(value).__name__} (expected {expected_type})"
        
        # Validate status enum
        if data["status"] not in {s.value for s in OutputStatus}:
            return False, f"Invalid status: {data['status']}"
        
        # Validate exit_code range
        if not isinstance(data["exit_code"], int) or data["exit_code"] < -1 or data["exit_code"] > 32767:
            return False, "exit_code must be -1 to 32767"
        
        return True, None
    
    @classmethod
    def sanitize(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Force data into standardized schema, filling missing fields.
        """
        output = {
            "status": data.get("status", OutputStatus.FAILED.value),
            "exit_code": data.get("exit_code", -1),
            "reboot_required": bool(data.get("reboot_required", False)),
            "matches_found": int(data.get("matches_found", 0)),
            "artifact_url": data.get("artifact_url"),
            "stdout": str(data.get("stdout", "")),
            "stderr": str(data.get("stderr", "")),
            "metadata": data.get("metadata", {}),
            "error_message": data.get("error_message"),
            "timestamp": data.get("timestamp", utc_iso_now()),
        }
        
        # Ensure metadata is dict
        if not isinstance(output["metadata"], dict):
            output["metadata"] = {}
        
        return output
    
    @classmethod
    def to_json_string(cls, data: Dict[str, Any], pretty: bool = False) -> str:
        """Convert to JSON with UTF-8 encoding."""
        sanitized = cls.sanitize(data)
        if pretty:
            return json.dumps(sanitized, indent=2, ensure_ascii=False)
        else:
            return json.dumps(sanitized, ensure_ascii=False)
    
    @classmethod
    def from_json_string(cls, json_str: str) -> Optional[Dict[str, Any]]:
        """Parse JSON string with validation."""
        try:
            data = json.loads(json_str, strict=False)
            is_valid, error = cls.validate(data)
            if not is_valid:
                logger.warning(f"Invalid output schema: {error}")
                return cls.sanitize(data)
            return data
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            return None


class OutputWrapper:
    """Wrap action results in standardized output."""
    
    @staticmethod
    def success(
        stdout: str = "",
        stderr: str = "",
        reboot_required: bool = False,
        matches_found: int = 0,
        artifact_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create successful output."""
        return {
            "status": OutputStatus.SUCCESS.value,
            "exit_code": 0,
            "reboot_required": reboot_required,
            "matches_found": matches_found,
            "artifact_url": artifact_url,
            "stdout": stdout,
            "stderr": stderr,
            "metadata": metadata or {},
            "error_message": None,
            "timestamp": utc_iso_now(),
        }
    
    @staticmethod
    def success_no_change(
        stdout: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """State already matches target (idempotent)."""
        return {
            "status": OutputStatus.SUCCESS_NO_CHANGE.value,
            "exit_code": 0,
            "reboot_required": False,
            "matches_found": 0,
            "artifact_url": None,
            "stdout": stdout,
            "stderr": "",
            "metadata": metadata or {},
            "error_message": None,
            "timestamp": utc_iso_now(),
        }
    
    @staticmethod
    def failed(
        error_message: str,
        exit_code: int = 1,
        stdout: str = "",
        stderr: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create failed output."""
        return {
            "status": OutputStatus.FAILED.value,
            "exit_code": exit_code,
            "reboot_required": False,
            "matches_found": 0,
            "artifact_url": None,
            "stdout": stdout,
            "stderr": stderr,
            "metadata": metadata or {},
            "error_message": error_message,
            "timestamp": utc_iso_now(),
        }
    
    @staticmethod
    def source_unavailable(
        resource: str,
        stdout: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Package/resource not found in catalog."""
        return {
            "status": OutputStatus.FAILED_SOURCE_UNAVAILABLE.value,
            "exit_code": 404,
            "reboot_required": False,
            "matches_found": 0,
            "artifact_url": None,
            "stdout": stdout,
            "stderr": f"Source not available: {resource}",
            "metadata": metadata or {},
            "error_message": f"Source unavailable: {resource}",
            "timestamp": utc_iso_now(),
        }
    
    @staticmethod
    def insufficient_memory(
        available_mb: int,
        required_mb: int = 500,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Insufficient free memory for operation."""
        return {
            "status": OutputStatus.FAILED_INSUFFICIENT_MEMORY.value,
            "exit_code": -1,
            "reboot_required": False,
            "matches_found": 0,
            "artifact_url": None,
            "stdout": "",
            "stderr": f"Insufficient memory: {available_mb}MB < {required_mb}MB required",
            "metadata": metadata or {"available_mb": available_mb, "required_mb": required_mb},
            "error_message": f"Insufficient memory: {available_mb}MB available",
            "timestamp": utc_iso_now(),
        }
    
    @staticmethod
    def partial(
        matches_found: int,
        successful_count: int,
        failed_count: int,
        stdout: str = "",
        stderr: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Partial success (some items processed, some failed)."""
        return {
            "status": OutputStatus.PARTIAL.value,
            "exit_code": 1,
            "reboot_required": False,
            "matches_found": matches_found,
            "artifact_url": None,
            "stdout": stdout,
            "stderr": stderr,
            "metadata": {
                "successful": successful_count,
                "failed": failed_count,
                **(metadata or {}),
            },
            "error_message": f"Partial success: {successful_count} OK, {failed_count} failed",
            "timestamp": utc_iso_now(),
        }
