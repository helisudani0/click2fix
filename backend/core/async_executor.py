"""
Async executor wrapper: Bridges endpoint_executor (sync) to async task queue.

This module provides:
1. Async wrapper for synchronous endpoint execution
2. Integration with Celery task queue
3. State tracking & idempotency
4. Wazuh feedback loop integration
5. Reboot intelligence
"""

import asyncio
import json
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple
import logging

from core.task_queue import (
    ExecutionContext,
    ActionStatus,
    ExecutionStatus,
    ActionResult,
    execute_action_async,
    execute_bulk_action_async,
    state_manager,
)
from core.action_schema_registry import (
    get_action_capability,
    validate_action_input,
    IdempotencyMode,
)
from core.settings import SETTINGS
from core.time_utils import utc_iso, utc_iso_now, utc_now_naive
from db.database import connect, execution_state, agent_state, reboot_requirements, action_idempotency_cache
from sqlalchemy import text


logger = logging.getLogger(__name__)


class AsyncExecutor:
    """Async execution engine with state tracking."""
    
    def __init__(self):
        self.db = connect()
    
    async def validate_prerequisites(
        self,
        action_id: str,
        agent_ids: List[str],
        args: Dict[str, Any],
    ) -> Tuple[bool, Optional[str]]:
        """Pre-flight validation."""
        # Validate action exists and schema
        capability = get_action_capability(action_id)
        if not capability:
            return False, f"Unknown action: {action_id}"
        
        # Validate inputs
        is_valid, error_msg = validate_action_input(action_id, args)
        if not is_valid:
            return False, error_msg
        
        # Check agent states for reboot prevention
        if action_id.startswith("package-") or action_id in {
            "fleet-software-update",
            "windows-os-update",
            "patch-windows",
            "patch-linux",
            "software-install-upgrade",
        }:
            for agent_id in agent_ids:
                has_pending_reboot = self.db.execute(
                    text(
                        """
                        SELECT has_pending_reboot FROM agent_state
                        WHERE agent_id = :agent_id
                        """
                    ),
                    {"agent_id": agent_id},
                ).scalar()
                
                prevent_until = self.db.execute(
                    text(
                        """
                        SELECT prevent_until FROM reboot_requirements
                        WHERE agent_id = :agent_id AND status = 'PENDING'
                        ORDER BY prevent_until DESC LIMIT 1
                        """
                    ),
                    {"agent_id": agent_id},
                ).scalar()
                
                if has_pending_reboot:
                    if prevent_until and utc_now_naive() < prevent_until:
                        return False, f"Agent {agent_id} has pending reboot until {prevent_until}"
        
        return True, None
    
    async def check_idempotency(
        self,
        action_id: str,
        agent_id: str,
        args: Dict[str, Any],
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if action should be skipped due to idempotency."""
        capability = get_action_capability(action_id)
        if not capability or capability.idempotency.mode == IdempotencyMode.ALWAYS_RUN:
            return False, None  # Not idempotent, should run
        
        # Build cache key
        cache_key = capability.idempotency.cache_key_pattern
        if cache_key:
            cache_key = cache_key.format(
                agent_id=agent_id,
                **args
            )
        else:
            cache_key = f"{action_id}:{agent_id}:{json.dumps(sorted(args.items()))}"
        
        # Check cache
        cached = self.db.execute(
            text(
                """
                SELECT action_state, result_data, last_execution_time FROM action_idempotency_cache
                WHERE cache_key = :cache_key AND expires_at > NOW()
                """
            ),
            {"cache_key": cache_key},
        ).fetchone()
        
        if cached:
            if cached[0] == "applied":  # Already successfully applied
                result_data = json.loads(cached[1]) if cached[1] else {}
                logger.info(f"Skipping idempotent action: {action_id} on {agent_id}")
                return True, result_data  # Skip execution
        
        return False, None  # Not cached, should run
    
    async def execute_action(
        self,
        action_id: str,
        agent_ids: List[str],
        args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        timeout_seconds: Optional[int] = None,
        approval_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Execute action across multiple agents with full state tracking.
        
        Returns:
        {
            execution_ids: List[str],
            status: str,
            results: [{agent_id, status, result, exit_code, reboot_required, ...}],
        }
        """
        execution_batch_id = str(uuid.uuid4())
        
        # Pre-flight checks
        is_valid, error_msg = await self.validate_prerequisites(action_id, agent_ids, args)
        if not is_valid:
            return {
                "execution_ids": [],
                "status": "FAILED",
                "error": error_msg,
                "timestamp": utc_iso_now(),
            }
        
        # Get action capability
        capability = get_action_capability(action_id)
        timeout = timeout_seconds or capability.timeout_seconds
        ttl = timeout + 300  # 5 min grace period
        
        # Check idempotency for each agent
        execution_ids = []
        results = []
        
        for agent_id in agent_ids:
            is_idempotent, cached_result = await self.check_idempotency(action_id, agent_id, args)
            
            if is_idempotent and cached_result:
                # Idempotent result
                results.append({
                    "agent_id": agent_id,
                    "status": ExecutionStatus.SUCCESS_NO_CHANGE.value,
                    "result": ActionResult.SUCCESS_NO_CHANGE.value,
                    "exit_code": 0,
                    "reboot_required": False,
                    "matches_found": 0,
                    "artifact_url": None,
                    "timestamp": utc_iso_now(),
                    "cached": True,
                    "metadata": cached_result,
                })
                continue
            
            # Generate execution ID
            exec_id = f"{execution_batch_id}:{agent_id}"
            execution_ids.append(exec_id)
            
            # Queue async task
            task = execute_action_async.apply_async(
                kwargs={
                    "execution_id": exec_id,
                    "action_id": action_id,
                    "agent_id": agent_id,
                    "agent_name": context.get("agent_name", "") if context else "",
                    "platform": context.get("platform", "") if context else "",
                    "action_args": args,
                    "ttl_seconds": ttl,
                    "metadata": {"batch_id": execution_batch_id, "approval_id": approval_id},
                },
                countdown=0,
                expires=timeout,
            )
            
            # Save initial state
            expires_at = utc_now_naive() + timedelta(seconds=ttl)
            self.db.execute(
                text(
                    """
                    INSERT INTO execution_state
                    (execution_id, action_id, agent_id, status, created_at, expires_at)
                    VALUES (:execution_id, :action_id, :agent_id, :status, :created_at, :expires_at)
                    ON CONFLICT (execution_id) DO UPDATE SET status = :status
                    """
                ),
                {
                    "execution_id": exec_id,
                    "action_id": action_id,
                    "agent_id": agent_id,
                    "status": ExecutionStatus.QUEUED.value,
                    "created_at": utc_now_naive(),
                    "expires_at": expires_at,
                },
            )
        
        self.db.commit()
        
        return {
            "execution_batch_id": execution_batch_id,
            "execution_ids": execution_ids,
            "status": "QUEUED",
            "agent_count": len(agent_ids),
            "timestamp": utc_iso_now(),
        }
    
    async def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a single execution."""
        # Try Redis first (fresh state)
        state = state_manager.get_state(execution_id)
        if state:
            return state
        
        # Fall back to database
        row = self.db.execute(
            text(
                """
                SELECT execution_id, action_id, agent_id, status, result, exit_code,
                       reboot_required, matches_found, artifact_url, stdout, stderr,
                       error_message, metadata, created_at, completed_at
                FROM execution_state
                WHERE execution_id = :execution_id
                """
            ),
            {"execution_id": execution_id},
        ).fetchone()
        
        if not row:
            return None
        
        return {
            "execution_id": row[0],
            "action_id": row[1],
            "agent_id": row[2],
            "status": row[3],
            "result": row[4],
            "exit_code": row[5],
            "reboot_required": row[6],
            "matches_found": row[7],
            "artifact_url": row[8],
            "stdout": row[9],
            "stderr": row[10],
            "error_message": row[11],
            "metadata": json.loads(row[12]) if row[12] else {},
            "created_at": utc_iso(row[13]),
            "completed_at": utc_iso(row[14]),
        }
    
    async def record_execution_result(
        self,
        execution_id: str,
        result: Dict[str, Any],
        agent_id: str,
        action_id: str,
    ) -> None:
        """Record final execution result and update idempotency cache."""
        # Update execution_state
        self.db.execute(
            text(
                """
                UPDATE execution_state
                SET status = :status, result = :result, exit_code = :exit_code,
                    reboot_required = :reboot_required, matches_found = :matches_found,
                    artifact_url = :artifact_url, stdout = :stdout, stderr = :stderr,
                    error_message = :error_message, metadata = :metadata, completed_at = NOW()
                WHERE execution_id = :execution_id
                """
            ),
            {
                "execution_id": execution_id,
                "status": result.get("status", ExecutionStatus.COMPLETED.value),
                "result": result.get("result", ActionResult.SUCCESS.value),
                "exit_code": result.get("exit_code", 0),
                "reboot_required": result.get("reboot_required", False),
                "matches_found": result.get("matches_found", 0),
                "artifact_url": result.get("artifact_url"),
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "error_message": result.get("error_message"),
                "metadata": json.dumps(result.get("metadata", {})),
            },
        )
        
        # Update idempotency cache if successful
        if result.get("result") == ActionResult.SUCCESS.value:
            capability = get_action_capability(action_id)
            if capability and capability.idempotency.mode != IdempotencyMode.ALWAYS_RUN:
                cache_key = capability.idempotency.cache_key_pattern
                if not cache_key:
                    cache_key = f"{action_id}:{agent_id}"
                
                expires_at = utc_now_naive() + timedelta(
                    seconds=capability.idempotency.recent_threshold_seconds
                )
                
                self.db.execute(
                    text(
                        """
                        INSERT INTO action_idempotency_cache
                        (cache_key, action_id, agent_id, execution_id, action_state, result_data, last_execution_time, expires_at)
                        VALUES (:cache_key, :action_id, :agent_id, :execution_id, :action_state, :result_data, :last_execution_time, :expires_at)
                        ON CONFLICT (cache_key) DO UPDATE SET
                            action_state = :action_state,
                            result_data = :result_data,
                            last_execution_time = :last_execution_time,
                            expires_at = :expires_at
                        """
                    ),
                    {
                        "cache_key": cache_key,
                        "action_id": action_id,
                        "agent_id": agent_id,
                        "execution_id": execution_id,
                        "action_state": "applied",
                        "result_data": json.dumps(result),
                        "last_execution_time": utc_now_naive(),
                        "expires_at": expires_at,
                    },
                )
        
        # Update agent_state
        self.db.execute(
            text(
                """
                INSERT INTO agent_state (agent_id, last_action_status, last_action_time)
                VALUES (:agent_id, :last_action_status, :last_action_time)
                ON CONFLICT (agent_id) DO UPDATE SET
                    last_action_status = :last_action_status,
                    last_action_time = :last_action_time
                """
            ),
            {
                "agent_id": agent_id,
                "last_action_status": result.get("status"),
                "last_action_time": utc_now_naive(),
            },
        )
        
        # If reboot required, create reboot_requirement
        if result.get("reboot_required"):
            self.db.execute(
                text(
                    """
                    INSERT INTO reboot_requirements
                    (agent_id, execution_id, reboot_reason, status)
                    VALUES (:agent_id, :execution_id, :reboot_reason, 'PENDING')
                    ON CONFLICT (agent_id) DO NOTHING
                    """
                ),
                {
                    "agent_id": agent_id,
                    "execution_id": execution_id,
                    "reboot_reason": "action_executed",
                },
            )
        
        self.db.commit()


# Global async executor instance
async_executor = AsyncExecutor()
