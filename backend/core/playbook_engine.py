import json
import os
import asyncio
import shlex
from core.ws_bus import publish
from core.active_response import run_command
from db.database import connect
from sqlalchemy import text
from core.settings import SETTINGS
from core.time_utils import utc_now_naive


PLAYBOOK_PATH = (
    SETTINGS.get("playbooks_path")
    if isinstance(SETTINGS, dict) and SETTINGS.get("playbooks_path")
    else "./playbooks"
)


class PlaybookEngine:

    def load(self, name):
        path = os.path.join(PLAYBOOK_PATH, name)
        with open(path) as f:
            return json.load(f)

    def execute(self, playbook, agent_id):
        results = []

        for task in playbook["tasks"]:
            cmd = self._translate_task(task, agent_id)
            out = run_command(cmd)
            if isinstance(cmd, list):
                command_text = " ".join(shlex.quote(str(part)) for part in cmd)
            else:
                command_text = str(cmd)

            results.append({
                "task": task,
                "command": command_text,
                "result": out
            })

        return results

    def _translate_task(self, task, agent_id):
        t = task["type"]

        if t == "script_run":
            raise Exception("script_run task type is disabled for security reasons")

        if t == "file_delete":
            target_path = str(task.get("path") or "").strip()
            if not target_path:
                raise Exception("file_delete requires a path")
            return ["rm", "-f", target_path]

        if t == "process_kill":
            process_name = str(task.get("name") or "").strip()
            if not process_name:
                raise Exception("process_kill requires a process name")
            return ["pkill", "-f", process_name]

        if t == "patch_install":
            return ["apt-get", "upgrade", "-y"]

        raise Exception(f"Unknown task type: {t}")
    
    def execute_step(self, step, agent):
        """Execute a single step - implement based on your step structure"""
        # This method was referenced but not defined
        cmd = self._translate_task(step, agent)
        return run_command(cmd)
    
    async def run(self, playbook, agent, approval_id, approved_by):
        db = connect()
        start = utc_now_naive()

        result = db.execute(
            text(
                """
                INSERT INTO executions
                (approval_id, agent, playbook, status, approved_by, started_at)
                VALUES (:approval_id, :agent, :playbook, :status, :approved_by, :started_at)
                RETURNING id
                """
            ),
            {
                "approval_id": approval_id,
                "agent": agent,
                "playbook": playbook["name"],
                "status": "RUNNING",
                "approved_by": approved_by,
                "started_at": start,
            },
        )

        execution_id = result.scalar()
        db.commit()

        try:
            for step in playbook["steps"]:
                try:
                    # Publish step start event
                    await publish(execution_id, {
                        "type": "step_start",
                        "step": step["id"]
                    })

                    result = self.execute_step(step, agent)

                    db.execute(
                        text(
                            """
                            INSERT INTO execution_steps
                            (execution_id, step, stdout, status)
                            VALUES (:execution_id, :step, :stdout, :status)
                            """
                        ),
                        {
                            "execution_id": execution_id,
                            "step": step["id"],
                            "stdout": str(result),
                            "status": "SUCCESS",
                        },
                    )
                    
                    db.commit()

                    # Publish step success event
                    await publish(execution_id, {
                        "type": "step_done",
                        "step": step["id"],
                        "stdout": str(result)
                    })

                except Exception as e:
                    db.execute(
                        text(
                            """
                            INSERT INTO execution_steps
                            (execution_id, step, stderr, status)
                            VALUES (:execution_id, :step, :stderr, :status)
                            """
                        ),
                        {
                            "execution_id": execution_id,
                            "step": step["id"],
                            "stderr": str(e),
                            "status": "FAILED",
                        },
                    )

                    db.execute(
                        text(
                            """
                            UPDATE executions SET status='FAILED', finished_at=:finished_at WHERE id=:id
                            """
                        ),
                        {"finished_at": utc_now_naive(), "id": execution_id},
                    )

                    db.commit()

                    # Publish step failed event
                    await publish(execution_id, {
                        "type": "step_failed",
                        "step": step["id"],
                        "error": str(e)
                    })
                    
                    return

            # All steps succeeded
            db.execute(
                text(
                    """
                    UPDATE executions SET status='SUCCESS', finished_at=:finished_at
                    WHERE id=:id
                    """
                ),
                {"finished_at": utc_now_naive(), "id": execution_id},
            )

            db.commit()

            # Publish success event
            await publish(execution_id, {
                "type": "finished",
                "status": "SUCCESS"
            })

        finally:
            db.close()
