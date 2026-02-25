"""
WebSocket-based real-time execution streaming

Replaces static logs with live execution feedback.

Events streamed:
- execution_started
- step_output (stdout/stderr)
- execution_completed
- error
- reboot_required
"""

import asyncio
import json
import logging
from typing import Any, Dict, Optional, Set
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect
import redis.asyncio as redis
from core.time_utils import utc_iso_now

logger = logging.getLogger(__name__)


class StreamEventType(str, Enum):
    """WebSocket event types."""
    EXECUTION_STARTED = "execution_started"
    STEP_OUTPUT = "step_output"
    EXECUTION_COMPLETED = "execution_completed"
    AGENT_CONNECTED = "agent_connected"
    AGENT_DISCONNECTED = "agent_disconnected"
    ERROR = "error"
    WARNING = "warning"
    REBOOT_REQUIRED = "reboot_required"
    VERIFICATION_STARTED = "verification_started"
    VERIFICATION_COMPLETE = "verification_complete"


class ExecutionStreamManager:
    """Manage WebSocket connections for real-time execution streams."""
    
    def __init__(self):
        self.active_streams: Dict[str, Set[WebSocket]] = {}  # execution_id -> set of WebSockets
        self.redis: Optional[redis.Redis] = None
        self.pubsub: Optional[redis.client.PubSub] = None
    
    async def init_redis(self) -> None:
        """Initialize Redis for pub/sub."""
        try:
            from core.task_queue import _get_redis_url
            url = _get_redis_url()
            self.redis = await redis.from_url(url, decode_responses=True)
            logger.info("WebSocket stream Redis initialized")
        except Exception as e:
            logger.error(f"Failed to init Redis for streaming: {e}")
    
    async def connect_stream(self, execution_id: str, websocket: WebSocket) -> None:
        """Register a WebSocket for execution stream updates."""
        await websocket.accept()
        
        if execution_id not in self.active_streams:
            self.active_streams[execution_id] = set()
        
        self.active_streams[execution_id].add(websocket)
        logger.info(f"WebSocket connected: {execution_id} ({len(self.active_streams[execution_id])} total)")
        
        try:
            # Hook into Redis channel for this execution
            if self.redis:
                channel = f"execution:stream:{execution_id}"
                pubsub = self.redis.pubsub()
                await pubsub.subscribe(channel)
                
                # Listen for messages
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            event = json.loads(message["data"])
                            await websocket.send_json(event)
                        except Exception as e:
                            logger.error(f"Error sending event: {e}")
                            break
            else:
                # Fallback: send keepalive
                await websocket.send_json({
                    "type": StreamEventType.WARNING.value,
                    "message": "Real-time streaming unavailable (Redis offline)",
                    "timestamp": utc_iso_now(),
                })
        
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected: {execution_id}")
        except Exception as e:
            logger.error(f"Stream error: {e}")
        
        finally:
            if execution_id in self.active_streams:
                self.active_streams[execution_id].discard(websocket)
                if not self.active_streams[execution_id]:
                    del self.active_streams[execution_id]
    
    async def publish_event(
        self,
        execution_id: str,
        event_type: StreamEventType,
        data: Dict[str, Any],
    ) -> None:
        """Publish event to all connected streams."""
        if not self.redis:
            return
        
        event = {
            "type": event_type.value,
            "timestamp": utc_iso_now(),
            "execution_id": execution_id,
            **data,
        }
        
        try:
            channel = f"execution:stream:{execution_id}"
            await self.redis.publish(channel, json.dumps(event))
        except Exception as e:
            logger.error(f"Error publishing event: {e}")
    
    async def publish_output(
        self,
        execution_id: str,
        agent_id: str,
        stdout: str = "",
        stderr: str = "",
    ) -> None:
        """Stream execution output."""
        await self.publish_event(
            execution_id,
            StreamEventType.STEP_OUTPUT,
            {
                "agent_id": agent_id,
                "stdout": stdout,
                "stderr": stderr,
            },
        )
    
    async def publish_execution_started(
        self,
        execution_id: str,
        action_id: str,
        agent_ids: list,
    ) -> None:
        """Signal execution start."""
        await self.publish_event(
            execution_id,
            StreamEventType.EXECUTION_STARTED,
            {
                "action_id": action_id,
                "agent_count": len(agent_ids),
                "agent_ids": agent_ids,
            },
        )
    
    async def publish_execution_completed(
        self,
        execution_id: str,
        status: str,
        result: Dict[str, Any],
    ) -> None:
        """Signal execution completion."""
        await self.publish_event(
            execution_id,
            StreamEventType.EXECUTION_COMPLETED,
            {
                "status": status,
                "result": result,
            },
        )
    
    async def publish_reboot_required(
        self,
        execution_id: str,
        agent_id: str,
        reason: str,
    ) -> None:
        """Notify of pending reboot."""
        await self.publish_event(
            execution_id,
            StreamEventType.REBOOT_REQUIRED,
            {
                "agent_id": agent_id,
                "reason": reason,
            },
        )


# Global stream manager
stream_manager = ExecutionStreamManager()


async def init_stream_manager():
    """Initialize streaming on app startup."""
    await stream_manager.init_redis()


class StreamLogger:
    """Stream execution output as it happens."""
    
    def __init__(self, execution_id: str):
        self.execution_id = execution_id
    
    async def log_output(self, agent_id: str, stdout: str = "", stderr: str = ""):
        """Stream output chunk."""
        await stream_manager.publish_output(
            self.execution_id, agent_id, stdout, stderr
        )
    
    async def log_error(self, message: str, agent_id: Optional[str] = None):
        """Stream error message."""
        await stream_manager.publish_event(
            self.execution_id,
            StreamEventType.ERROR,
            {
                "message": message,
                "agent_id": agent_id,
            },
        )
    
    async def log_warning(self, message: str, agent_id: Optional[str] = None):
        """Stream warning message."""
        await stream_manager.publish_event(
            self.execution_id,
            StreamEventType.WARNING,
            {
                "message": message,
                "agent_id": agent_id,
            },
        )


def create_stream_logger(execution_id: str) -> StreamLogger:
    """Create a logger for this execution."""
    return StreamLogger(execution_id)
