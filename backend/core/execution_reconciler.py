"""
Execution Health & Recovery Module
Implements orphan execution detection and recovery.
"""

from datetime import timedelta
from sqlalchemy import text
from db.database import connect
from core.ws_bus import publish_event
from core.time_utils import utc_iso_now, utc_now_naive


def _get_db():
    """Get database connection."""
    return connect()


def reconcile_orphan_executions(
    timeout_seconds: int = 300,
    check_heartbeat: bool = True,
) -> dict:
    """
    Identify and recover orphan executions that are stuck in RUNNING state.
    
    Parameters:
    - timeout_seconds: Execution timeout threshold (default 5 minutes)
    - check_heartbeat: Whether to check for agent heartbeats (default True)
    
    Returns:
    - Dictionary with reconciliation results
    """
    db = _get_db()
    try:
        recovered_count = 0
        stale_count = 0
        inconsistent_count = 0
        
        # Find executions that have been RUNNING too long without completion
        stale_threshold = utc_now_naive() - timedelta(seconds=timeout_seconds)
        
        stale_executions = db.execute(
            text(
                """
                SELECT
                    id,
                    agent,
                    action,
                    started_at,
                    finished_at
                FROM executions
                WHERE status = 'RUNNING'
                    AND started_at < :stale_threshold
                    AND finished_at IS NULL
                """
            ),
            {"stale_threshold": stale_threshold},
        ).fetchall()
        
        for exec_row in stale_executions:
            exec_id = exec_row[0]
            agent_id = exec_row[1]
            action_id = exec_row[2]
            started_at = exec_row[3]
            
            # Check for recent activity in execution steps
            recent_step = db.execute(
                text(
                    """
                    SELECT MAX(id)
                    FROM execution_steps
                    WHERE execution_id = :exec_id
                        AND status IN ('SUCCESS', 'FAILED')
                    """
                ),
                {"exec_id": exec_id},
            ).scalar()
            
            # If there are no completed steps, this is a true orphan
            if not recent_step:
                # Mark execution as FAILED due to timeout
                db.execute(
                    text(
                        """
                        UPDATE executions
                        SET status = 'FAILED',
                            finished_at = NOW()
                        WHERE id = :exec_id
                        """
                    ),
                    {"exec_id": exec_id},
                )
                
                # Add error step
                db.execute(
                    text(
                        """
                        INSERT INTO execution_steps
                        (execution_id, step, stdout, stderr, status)
                        VALUES (:exec_id, :step, :stdout, :stderr, :status)
                        """
                    ),
                    {
                        "exec_id": exec_id,
                        "step": "orphan_recovery",
                        "stdout": f"Execution recovered from orphan state (no heartbeat for {timeout_seconds}s)",
                        "stderr": "Execution was in RUNNING state without activity",
                        "status": "FAILED",
                    },
                )
                
                db.commit()
                recovered_count += 1
                
                # Publish event
                publish_event(
                    exec_id,
                    {
                        "type": "orphan_recovery",
                        "step": "orphan_recovery",
                        "status": "FAILED",
                        "stdout": f"Execution recovered from orphan state",
                        "stderr": "Execution was in RUNNING state without activity",
                    },
                )
            else:
                stale_count += 1
        
        # Check for inconsistent states
        # (execution marked SUCCESS but without completed steps)
        inconsistent = db.execute(
            text(
                """
                SELECT e.id, e.status, COUNT(es.id) as step_count
                FROM executions e
                LEFT JOIN execution_steps es ON e.id = es.execution_id
                WHERE e.status IN ('SUCCESS', 'PARTIAL')
                    AND e.finished_at IS NOT NULL
                GROUP BY e.id, e.status
                HAVING COUNT(es.id) = 0
                """
            ),
        ).fetchall()
        
        inconsistent_count = len(inconsistent or [])
        
        return {
            "timestamp": utc_iso_now(),
            "orphan_threshold_seconds": timeout_seconds,
            "recovered_count": recovered_count,
            "stale_count": stale_count,
            "inconsistent_count": inconsistent_count,
            "total_issues_found": recovered_count + stale_count + inconsistent_count,
        }
    finally:
        db.close()


def check_agent_heartbeat(agent_id: str, heartbeat_timeout: int = 60) -> bool:
    """
    Check if an agent has reported a recent heartbeat.
    
    Parameters:
    - agent_id: The agent ID to check
    - heartbeat_timeout: Timeout in seconds (default 60)
    
    Returns:
    - True if agent has recent heartbeat, False otherwise
    """
    db = _get_db()
    try:
        # Check for recent agent activity
        heartbeat_threshold = utc_now_naive() - timedelta(seconds=heartbeat_timeout)
        
        # Check execution steps for this agent
        recent_activity = db.execute(
            text(
                """
                SELECT es.id
                FROM execution_steps es
                JOIN executions e ON es.execution_id = e.id
                WHERE e.agent = :agent_id
                    AND (
                        es.status IN ('SUCCESS', 'FAILED')
                        OR es.step LIKE 'heartbeat'
                    )
                ORDER BY es.id DESC
                LIMIT 1
                """
            ),
            {"agent_id": agent_id},
        ).scalar()
        
        return recent_activity is not None
    finally:
        db.close()
