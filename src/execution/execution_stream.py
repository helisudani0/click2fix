import asyncio
import logging
from typing import Optional, Dict, Any
from src.websocket.ws_bus import get_ws_bus, BusMessage
from src.standardized_output import ExecutionResult, create_success_result, create_failure_result

logger = logging.getLogger(__name__)

class ExecutionStream:
    """Streamed task execution with real-time WebSocket updates."""
    
    def __init__(self, agent_id: str, task_id: str):
        self.agent_id = agent_id
        self.task_id = task_id
        self.ws_bus = get_ws_bus()
        self.step_count = 0
        self.total_steps = 1
    
    async def execute_with_stream(
        self,
        executor_func,
        total_steps: int = 1,
        **executor_kwargs
    ) -> ExecutionResult:
        """
        Execute task with streaming progress to WebSocket.
        
        Args:
            executor_func: Async function to execute, must accept 'stream' kwarg
            total_steps: Expected number of steps for progress calculation
            **executor_kwargs: Additional arguments for executor_func
        
        Returns:
            ExecutionResult from standardized_output schema
        """
        self.total_steps = total_steps
        
        try:
            # Publish task start
            await self.ws_bus.publish_task_update(
                agent_id=self.agent_id,
                status="executing",
                task_id=self.task_id,
                details={"started_at": await self._get_timestamp()}
            )
            
            # Execute with stream callback
            result = await executor_func(
                stream=self.stream_output,
                **executor_kwargs
            )
            
            # Ensure result is ExecutionResult type
            if not isinstance(result, ExecutionResult):
                result = create_success_result(
                    agent_id=self.agent_id,
                    command_executed=str(executor_func.__name__),
                    output=str(result),
                    return_code=0
                )
            
            # Publish completion
            await self.ws_bus.publish_task_update(
                agent_id=self.agent_id,
                status="completed",
                task_id=self.task_id,
                details={
                    "result_status": result.status,
                    "return_code": result.return_code
                }
            )
            
            return result
        
        except Exception as e:
            logger.error(f"ExecutionStream error: {e}", exc_info=True)
            
            # Publish error
            await self.ws_bus.publish_error(
                agent_id=self.agent_id,
                task_id=self.task_id,
                error_message=str(e),
                error_code="EXECUTION_ERROR"
            )
            
            return create_failure_result(
                agent_id=self.agent_id,
                command_executed="stream_execution",
                error_message=str(e),
                return_code=1
            )
    
    async def stream_output(
        self,
        action: str,
        output: Optional[str] = None,
        step: Optional[int] = None
    ) -> None:
        """
        Stream action/output to WebSocket and increment progress.
        
        Args:
            action: Current action description
            output: Command output/response text
            step: Optional explicit step number (auto-increments if not provided)
        """
        if step is None:
            self.step_count += 1
        else:
            self.step_count = step
        
        await self.ws_bus.publish_execution_progress(
            agent_id=self.agent_id,
            task_id=self.task_id,
            step=self.step_count,
            total_steps=self.total_steps,
            current_action=action,
            output=output
        )
        
        logger.debug(f"[{self.agent_id}/{self.task_id}] {action}")
    
    async def stream_forensics(self, forensic_data: Dict[str, Any]) -> None:
        """Stream forensic collection results."""
        await self.ws_bus.publish_forensics(
            agent_id=self.agent_id,
            task_id=self.task_id,
            forensic_data=forensic_data
        )
    
    @staticmethod
    async def _get_timestamp() -> str:
        from datetime import datetime
        return datetime.utcnow().isoformat()
