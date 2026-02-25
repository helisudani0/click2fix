import asyncio
import logging
import json
from typing import Set, Callable, Any, Optional
from dataclasses import asdict, dataclass
from datetime import datetime
import weakref

logger = logging.getLogger(__name__)

@dataclass
class BusMessage:
    """Standardized WebSocket bus message."""
    message_type: str  # "task_update", "execution_progress", "forensics", "error"
    agent_id: str
    payload: dict
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

class WebSocketBus:
    """Central event bus for real-time task updates to frontend."""
    
    def __init__(self):
        self._subscribers: Set[Callable] = set()
        self._weak_subscribers = weakref.WeakSet()
        self._lock = asyncio.Lock()
        self._message_queue = asyncio.Queue()
    
    async def subscribe(self, callback: Callable[[BusMessage], None]) -> None:
        """
        Subscribe callback to all bus messages.
        
        Args:
            callback: Async function(BusMessage) -> None
        """
        async with self._lock:
            self._subscribers.add(callback)
            logger.debug(f"Subscriber added. Total: {len(self._subscribers)}")
    
    async def unsubscribe(self, callback: Callable) -> None:
        """Unsubscribe callback from bus."""
        async with self._lock:
            self._subscribers.discard(callback)
    
    async def publish(self, message: BusMessage) -> None:
        """
        Publish message to all subscribers.
        
        Args:
            message: BusMessage instance to broadcast
        """
        await self._message_queue.put(message)
    
    async def _broadcast(self, message: BusMessage) -> None:
        """Internal broadcast to all active subscribers."""
        if not self._subscribers:
            logger.debug(f"No subscribers for {message.message_type}")
            return
        
        tasks = []
        for callback in list(self._subscribers):
            try:
                if asyncio.iscoroutinefunction(callback):
                    tasks.append(callback(message))
                else:
                    callback(message)
            except Exception as e:
                logger.error(f"Subscriber callback error: {e}")
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def start_broadcaster(self) -> None:
        """Start background task to broadcast queued messages."""
        while True:
            try:
                message = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)
                await self._broadcast(message)
                self._message_queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Broadcaster error: {e}")
                await asyncio.sleep(1)
    
    async def publish_task_update(
        self,
        agent_id: str,
        status: str,
        task_id: str,
        details: Optional[dict] = None
    ) -> None:
        """Publish task status update."""
        message = BusMessage(
            message_type="task_update",
            agent_id=agent_id,
            payload={
                "task_id": task_id,
                "status": status,
                "details": details or {}
            }
        )
        await self.publish(message)
    
    async def publish_execution_progress(
        self,
        agent_id: str,
        task_id: str,
        step: int,
        total_steps: int,
        current_action: str,
        output: Optional[str] = None
    ) -> None:
        """Publish execution progress for real-time terminal display."""
        message = BusMessage(
            message_type="execution_progress",
            agent_id=agent_id,
            payload={
                "task_id": task_id,
                "step": step,
                "total_steps": total_steps,
                "current_action": current_action,
                "output": output or ""
            }
        )
        await self.publish(message)
    
    async def publish_forensics(
        self,
        agent_id: str,
        task_id: str,
        forensic_data: dict
    ) -> None:
        """Publish forensic collection results."""
        message = BusMessage(
            message_type="forensics",
            agent_id=agent_id,
            payload={
                "task_id": task_id,
                "forensic_data": forensic_data
            }
        )
        await self.publish(message)
    
    async def publish_error(
        self,
        agent_id: str,
        task_id: str,
        error_message: str,
        error_code: Optional[str] = None
    ) -> None:
        """Publish error event."""
        message = BusMessage(
            message_type="error",
            agent_id=agent_id,
            payload={
                "task_id": task_id,
                "error_message": error_message,
                "error_code": error_code or "UNKNOWN"
            }
        )
        await self.publish(message)

# Global singleton instance
_ws_bus: Optional[WebSocketBus] = None

def get_ws_bus() -> WebSocketBus:
    """Get or create global WebSocket bus."""
    global _ws_bus
    if _ws_bus is None:
        _ws_bus = WebSocketBus()
    return _ws_bus
