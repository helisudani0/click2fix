"""
Reboot Intelligence & Prevention

Features:
1. Exit Code 3010 detection (Windows Update requires reboot)
2. Pending reboot tracking & prevention
3. Restart loop prevention
4. UI state: PENDING_REBOOT
5. Automatic reboot scheduling
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from db.database import connect, reboot_requirements
from core.time_utils import utc_iso, utc_now_naive
from sqlalchemy import text

logger = logging.getLogger(__name__)


class RebootReason(str, Enum):
    """Why a reboot is needed."""
    PATCH_INSTALLED = "patch_installed"
    UPDATE_INSTALLED = "update_installed"
    PACKAGE_INSTALLED = "package_installed"
    SERVICE_RESTART = "service_restart"
    MANUAL = "manual"
    SYSTEM_UPDATE = "system_update"


class RebootStatus(str, Enum):
    """Reboot execution status."""
    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class RebootManager:
    """Manage endpoint reboots with safety checks."""
    
    def __init__(self):
        self.db = connect()
        self.min_interval_between_reboots = 3600  # 1 hour minimum
        self.max_consecutive_failures = 3
        self.reboot_grace_period = 300  # 5 min: don't let patches restart immediately
    
    async def check_exit_code_3010(
        self,
        exit_code: int,
        agent_id: str,
        execution_id: str,
        action_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Detect Windows exit code 3010 (reboot required).
        Records pending reboot requirement.
        
        Returns: (reboot_required, reason)
        """
        if exit_code != 3010:
            return False, None
        
        logger.info(f"Detected reboot requirement (3010) for agent {agent_id}")
        
        try:
            # Record pending reboot
            self.db.execute(
                text(
                    """
                    INSERT INTO reboot_requirements
                    (agent_id, execution_id, reboot_reason, status, prevent_until)
                    VALUES (:agent_id, :execution_id, :reason, :status, :prevent_until)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        status = :status,
                        prevent_until = :prevent_until
                    """
                ),
                {
                    "agent_id": agent_id,
                    "execution_id": execution_id,
                    "reason": RebootReason.UPDATE_INSTALLED.value,
                    "status": RebootStatus.PENDING.value,
                    "prevent_until": utc_now_naive() + timedelta(seconds=self.reboot_grace_period),
                },
            )
            self.db.commit()
            
            return True, "Reboot required - Windows Update exit code 3010"
        
        except Exception as e:
            logger.error(f"Error recording reboot requirement: {e}")
            return False, None
    
    async def can_execute_action(
        self,
        agent_id: str,
        action_id: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if agent can accept a new action before reboot.
        
        Prevents restart loops by blocking patches if reboot is pending.
        
        Returns: (can_execute, reason_if_blocked)
        """
        # Check for pending reboot
        reboot_status = self.db.execute(
            text(
                """
                SELECT status, prevent_until, reboot_reason FROM reboot_requirements
                WHERE agent_id = :agent_id AND status = 'PENDING'
                ORDER BY created_at DESC LIMIT 1
                """
            ),
            {"agent_id": agent_id},
        ).fetchone()
        
        if not reboot_status:
            return True, None
        
        status, prevent_until, reason = reboot_status
        
        # Check if still in grace period
        if prevent_until and utc_now_naive() < prevent_until:
            return False, f"Reboot pending ({reason}) - will complete within {(prevent_until - utc_now_naive()).seconds}s"
        
        # Reboot is past grace period, safe to proceed
        return True, None
    
    async def schedule_reboot(
        self,
        agent_id: str,
        scheduled_for: datetime,
        reason: RebootReason = RebootReason.PATCH_INSTALLED,
    ) -> bool:
        """Schedule future reboot."""
        try:
            self.db.execute(
                text(
                    """
                    INSERT INTO reboot_requirements
                    (agent_id, reboot_reason, status, scheduled_for)
                    VALUES (:agent_id, :reason, :status, :scheduled_for)
                    ON CONFLICT (agent_id) DO UPDATE SET
                        status = :status,
                        scheduled_for = :scheduled_for
                    """
                ),
                {
                    "agent_id": agent_id,
                    "reason": reason.value,
                    "status": RebootStatus.SCHEDULED.value,
                    "scheduled_for": scheduled_for,
                },
            )
            self.db.commit()
            logger.info(f"Reboot scheduled for {agent_id} at {scheduled_for}: {reason}")
            return True
        except Exception as e:
            logger.error(f"Error scheduling reboot: {e}")
            return False
    
    async def acknowledge_reboot(
        self,
        agent_id: str,
        acknowledged_by: str,
    ) -> bool:
        """Mark reboot as acknowledged by user."""
        try:
            self.db.execute(
                text(
                    """
                    UPDATE reboot_requirements
                    SET acknowledged_by = :acknowledged_by, status = :status
                    WHERE agent_id = :agent_id AND status = 'PENDING'
                    """
                ),
                {
                    "agent_id": agent_id,
                    "acknowledged_by": acknowledged_by,
                    "status": RebootStatus.SCHEDULED.value,
                },
            )
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error acknowledging reboot: {e}")
            return False
    
    async def handle_reboot_completion(
        self,
        agent_id: str,
    ) -> bool:
        """Mark reboot as completed."""
        try:
            self.db.execute(
                text(
                    """
                    UPDATE reboot_requirements
                    SET status = :status
                    WHERE agent_id = :agent_id
                    """
                ),
                {
                    "agent_id": agent_id,
                    "status": RebootStatus.COMPLETED.value,
                },
            )
            self.db.commit()
            logger.info(f"Reboot marked as completed for {agent_id}")
            return True
        except Exception as e:
            logger.error(f"Error marking reboot complete: {e}")
            return False
    
    async def get_pending_reboots(self) -> Dict[str, Any]:
        """Get all pending reboots across fleet."""
        try:
            rows = self.db.execute(
                text(
                    """
                    SELECT agent_id, reboot_reason, status, prevent_until, scheduled_for
                    FROM reboot_requirements
                    WHERE status IN ('PENDING', 'SCHEDULED')
                    ORDER BY created_at DESC
                    """
                )
            ).fetchall()
            
            return {
                "total": len(rows),
                "pending": [
                    {
                        "agent_id": row[0],
                        "reason": row[1],
                        "status": row[2],
                        "prevent_until": utc_iso(row[3]),
                        "scheduled_for": utc_iso(row[4]),
                    }
                    for row in rows
                ],
            }
        except Exception as e:
            logger.error(f"Error fetching pending reboots: {e}")
            return {"total": 0, "pending": []}
    
    def _detect_restart_loop(self, agent_id: str) -> bool:
        """Check if agent is in restart loop."""
        try:
            # Look for multiple reboots in last hour
            recent_reboots = self.db.execute(
                text(
                    """
                    SELECT COUNT(*) FROM reboot_requirements
                    WHERE agent_id = :agent_id 
                    AND status = 'COMPLETED'
                    AND created_at > NOW() - INTERVAL 1 HOUR
                    """
                ),
                {"agent_id": agent_id},
            ).scalar()
            
            return recent_reboots > self.max_consecutive_failures
        except Exception as e:
            logger.error(f"Error checking restart loop: {e}")
            return False


# Global reboot manager
reboot_manager = RebootManager()


def generate_reboot_detection_script(platform: str = "windows") -> str:
    """Generate script to detect and report reboot requirements."""
    
    if platform == "windows":
        return '''
$ErrorActionPreference = 'SilentlyContinue'

# Check Windows Update pending reboot
$rebootPending = $false
$rebootReasons = @()

# Method 1: Registry check
if (Test-Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired") {
    $rebootPending = $true
    $rebootReasons += "registry_reboot_required"
}

# Method 2: Component-based servicing
if (Get-Item "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending" -ErrorAction SilentlyContinue) {
    $rebootPending = $true
    $rebootReasons += "component_servicing_pending"
}

# Method 3: WMI check
$wmiCheck = Get-WmiObject -ClassName Win32_OperatingSystem
if ($wmiCheck.LastBootUpTime -and (Get-Date) -gt $wmiCheck.LastBootUpTime.AddDays(30)) {
    # System hasn't rebooted in 30+ days
    $rebootPending = $true
    $rebootReasons += "extended_uptime"
}

$output = @{
    "reboot_pending" = $rebootPending
    "reboot_reasons" = $rebootReasons
    "uptime_days" = [math]::Round(((Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime($wmiCheck.LastBootUpTime)).TotalDays, 1)
    "timestamp" = (Get-Date -Format 'o')
}

Write-Output (ConvertTo-Json $output -Compress)
'''
    
    elif platform == "linux":
        return '''#!/bin/bash
set -euo pipefail

reboot_pending=false
reboot_reasons=()

# Check if system requires reboot
if [ -f /var/run/reboot-required ]; then
    reboot_pending=true
    reboot_reasons+=("reboot_required_file")
fi

# Check systemd
if command -v systemctl &> /dev/null; then
    if systemctl is-system-running | grep -q "degraded"; then
        reboot_reasons+=("systemd_degraded")
    fi
fi

# Check pending kernel
if [ -f /boot/vmlinuz ]; then
    current_kernel=$(uname -r)
    latest_kernel=$(ls -t /boot/vmlinuz* 2>/dev/null | head -1 | sed 's/.*vmlinuz-//')
    if [ "$current_kernel" != "$latest_kernel" ]; then
        reboot_pending=true
        reboot_reasons+=("kernel_upgrade_pending")
    fi
fi

uptime_days=$(uptime -p | grep -oP '\\d+(?= days)' || echo "0")

cat <<EOF
{
    "reboot_pending": $reboot_pending,
    "reboot_reasons": [$(printf '"%s", ' "${reboot_reasons[@]}" | sed 's/, $//')]
    "uptime_days": $uptime_days,
    "timestamp": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
}
EOF
'''
    
    return ""
