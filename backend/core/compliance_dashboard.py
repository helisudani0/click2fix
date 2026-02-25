"""
Fleet Compliance Score Dashboard

Provides:
1. Overall compliance percentage
2. Per-agent patch status
3. Vulnerability trends
4. Reboot requirements
5. Remediation tracking
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from db.database import connect
from sqlalchemy import text

logger = logging.getLogger(__name__)


class ComplianceDashboard:
    """Generate fleet-wide compliance analytics."""
    
    def __init__(self):
        self.db = connect()
    
    async def get_compliance_score(self) -> Dict[str, Any]:
        """
        Calculate overall compliance score (0-100).
        
        Returns:
        {
            "compliance_score": 85,
            "total_agents": 50,
            "compliant_agents": 43,
            "agents_needing_patches": 7,
            "pending_reboots": 2,
            "vulnerable_count": 12,
            "remediated_count": 156,
        }
        """
        try:
            # Total agents
            total = self.db.execute(
                text("SELECT COUNT(*) FROM agent_state")
            ).scalar() or 0
            
            if total == 0:
                return {"compliance_score": 100, "total_agents": 0}
            
            # Agents without pending patches
            compliant = self.db.execute(
                text(
                    """
                    SELECT COUNT(*) FROM agent_state
                    WHERE has_pending_reboot = false
                    AND last_action_status NOT IN ('FAILED', 'PENDING')
                    """
                )
            ).scalar() or 0
            
            # Agents needing patches
            needing_patches = self.db.execute(
                text(
                    """
                    SELECT COUNT(DISTINCT agent_id) FROM execution_state
                    WHERE status IN ('PENDING', 'FAILED')
                    AND action_id LIKE '%patch%' OR action_id LIKE '%update%'
                    AND completed_at > NOW() - INTERVAL 7 DAY
                    """
                )
            ).scalar() or 0
            
            # Pending reboots
            pending_reboots = self.db.execute(
                text(
                    "SELECT COUNT(*) FROM reboot_requirements WHERE status = 'PENDING'"
                )
            ).scalar() or 0
            
            score = int((compliant / total) * 100) if total > 0 else 100
            
            return {
                "compliance_score": score,
                "total_agents": total,
                "compliant_agents": compliant,
                "agents_needing_patches": needing_patches,
                "pending_reboots": pending_reboots,
            }
        
        except Exception as e:
            logger.error(f"Error calculating compliance score: {e}")
            return {"compliance_score": 0, "error": str(e)}
    
    async def get_agent_compliance(self, agent_id: str) -> Dict[str, Any]:
        """Get compliance status for a specific agent."""
        try:
            # Agent state
            agent = self.db.execute(
                text(
                    """
                    SELECT agent_id, agent_name, platform, online_status,
                           has_pending_reboot, free_memory_mb, last_action_status
                    FROM agent_state WHERE agent_id = :agent_id
                    """
                ),
                {"agent_id": agent_id},
            ).fetchone()
            
            if not agent:
                return {"status": "UNKNOWN", "error": "Agent not found"}
            
            # Recent executions
            recent_execs = self.db.execute(
                text(
                    """
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN result = 'SUCCESS' THEN 1 ELSE 0 END) as successful
                    FROM execution_state
                    WHERE agent_id = :agent_id AND completed_at > NOW() - INTERVAL 30 DAY
                    """
                ),
                {"agent_id": agent_id},
            ).fetchone()
            
            total_actions = recent_execs[0] or 0
            successful_actions = recent_execs[1] or 0
            success_rate = int((successful_actions / total_actions) * 100) if total_actions > 0 else 0
            
            # Pending reboots
            pending_reboot = self.db.execute(
                text(
                    """
                    SELECT COUNT(*) FROM reboot_requirements
                    WHERE agent_id = :agent_id AND status IN ('PENDING', 'SCHEDULED')
                    """
                ),
                {"agent_id": agent_id},
            ).scalar() or 0
            
            return {
                "agent_id": agent[0],
                "agent_name": agent[1],
                "platform": agent[2],
                "status": agent[3],
                "pending_reboot": agent[4],
                "free_memory_mb": agent[5],
                "last_action_status": agent[6],
                "success_rate_percent": success_rate,
                "actions_30_day": total_actions,
                "pending_reboots": pending_reboot,
            }
        
        except Exception as e:
            logger.error(f"Error getting agent compliance: {e}")
            return {"error": str(e)}
    
    async def get_vulnerability_metrics(self) -> Dict[str, Any]:
        """Get vulnerability remediation metrics."""
        try:
            # Get vulnerability closure stats
            stats = self.db.execute(
                text(
                    """
                    SELECT 
                        COUNT(*) as total_vulnerabilities,
                        SUM(CASE WHEN state = 'closed' THEN 1 ELSE 0 END) as closed,
                        SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) as open
                    FROM vulnerability_local_closures
                    """
                )
            ).fetchone()
            
            total = stats[0] or 0
            closed = stats[1] or 0
            open_count = stats[2] or 0
            
            remediation_rate = int((closed / total) * 100) if total > 0 else 0
            
            return {
                "total_vulnerabilities": total,
                "remediated": closed,
                "still_vulnerable": open_count,
                "remediation_rate_percent": remediation_rate,
            }
        
        except Exception as e:
            logger.error(f"Error getting vulnerability metrics: {e}")
            return {"error": str(e)}
    
    async def get_fleet_topology(self) -> Dict[str, Any]:
        """Get fleet composition and distribution."""
        try:
            # Agents by platform
            by_platform = self.db.execute(
                text(
                    """
                    SELECT platform, COUNT(*) as count FROM agent_state
                    GROUP BY platform
                    """
                )
            ).fetchall()
            
            # Agents by status
            by_status = self.db.execute(
                text(
                    """
                    SELECT online_status, COUNT(*) as count FROM agent_state
                    GROUP BY online_status
                    """
                )
            ).fetchall()
            
            return {
                "by_platform": [
                    {"platform": row[0], "count": row[1]} for row in by_platform
                ],
                "by_status": [
                    {"status": row[0], "count": row[1]} for row in by_status
                ],
            }
        
        except Exception as e:
            logger.error(f"Error getting fleet topology: {e}")
            return {"error": str(e)}
    
    async def get_remediation_timeline(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get remediation activity over time."""
        try:
            rows = self.db.execute(
                text(
                    f"""
                    SELECT DATE(executed_at) as date, 
                           COUNT(*) as total,
                           SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful
                    FROM action_execution_history
                    WHERE executed_at > NOW() - INTERVAL {days} DAY
                    AND action_id LIKE '%patch%' OR action_id LIKE '%update%'
                    GROUP BY DATE(executed_at)
                    ORDER BY date ASC
                    """
                )
            ).fetchall()
            
            return [
                {
                    "date": str(row[0]),
                    "actions_attempted": row[1],
                    "actions_successful": row[2],
                }
                for row in rows
            ]
        
        except Exception as e:
            logger.error(f"Error getting remediation timeline: {e}")
            return []


# Global dashboard instance
compliance_dashboard = ComplianceDashboard()
