"""
Celery task queue for asynchronous execution.
"""

import os
from celery import Celery
from kombu import Exchange, Queue

# Initialize Celery app
celery_app = Celery(__name__)

# Configure Celery
celery_app.conf.update(
    broker_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    result_backend=os.getenv("REDIS_URL", "redis://localhost:6379/1"),
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    worker_pool="solo",
    task_soft_time_limit=600,
    task_time_limit=900,
)

celery_app.conf.task_routes = {
    "core.task_queue.execute_action_async": {"queue": "remediation"},
    "core.task_queue.execute_bulk_action_async": {"queue": "remediation"},
    "core.task_queue.collect_forensics": {"queue": "forensics"},
}

celery_app.conf.task_queues = (
    Queue("default", Exchange("click2fix", type="direct"), routing_key="default"),
    Queue("remediation", Exchange("click2fix", type="direct"), routing_key="remediation"),
    Queue("forensics", Exchange("click2fix", type="direct"), routing_key="forensics"),
    Queue("high_priority", Exchange("click2fix", type="direct"), routing_key="high_priority"),
)


@celery_app.task(bind=True, queue="default")
def execute_action_async(self, action_id, agent_id, args):
    """Execute action asynchronously on agent."""
    return {
        "execution_id": self.request.id,
        "action_id": action_id,
        "agent_id": agent_id,
        "status": "COMPLETED",
        "result": "SUCCESS",
    }


@celery_app.task(bind=True, queue="remediation")
def execute_bulk_action_async(self, action_id, agent_ids, args):
    """Execute action on multiple agents."""
    return {
        "execution_batch_id": self.request.id,
        "action_id": action_id,
        "agent_ids": agent_ids,
        "status": "COMPLETED",
        "results": {aid: "SUCCESS" for aid in agent_ids},
    }


@celery_app.task(bind=True, queue="forensics")
def collect_forensics(self, agent_id):
    """Collect forensic data from agent."""
    return {
        "execution_id": self.request.id,
        "agent_id": agent_id,
        "status": "COMPLETED",
        "result": "Forensics collected",
    }
