"""
Closed-loop remediation verification via Wazuh API.

Behavior:
1. For eligible remediation actions, trigger a batched agent restart (sca-rescan equivalent).
2. Poll SCA state with exponential backoff.
3. Verify scan freshness by comparing post-trigger timestamps against pre-trigger scan data.
4. Return per-target verification evidence for execution logging.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from core.action_schema_registry import get_action_capability
from core.settings import SETTINGS
from core.time_utils import utc_iso
from core.wazuh_client import WazuhClient

logger = logging.getLogger(__name__)

_DEFAULT_VERIFY_ACTIONS = {
    "patch-windows",
    "windows-os-update",
    "fleet-software-update",
    "patch-linux",
    "package-update",
    "software-install-upgrade",
    "custom-os-command",
}
_SCAN_TIMESTAMP_KEYS = (
    "last_scan",
    "end_scan",
    "scan_time",
    "updated_at",
    "timestamp",
    "start_scan",
)


def _cfg(path: str, default: Any = None) -> Any:
    node = SETTINGS if isinstance(SETTINGS, dict) else {}
    for key in path.split("."):
        if not isinstance(node, dict):
            return default
        node = node.get(key)
        if node is None:
            return default
    return node


def _to_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if value is None:
        return default
    return bool(value)


def _extract_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload.get("data", {})
        if isinstance(data, dict):
            items = data.get("affected_items")
            if isinstance(items, list):
                return [i for i in items if isinstance(i, dict)]
        items = payload.get("affected_items") or payload.get("items")
        if isinstance(items, list):
            return [i for i in items if isinstance(i, dict)]
    if isinstance(payload, list):
        return [i for i in payload if isinstance(i, dict)]
    return []


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except Exception:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return utc_iso(value)


def _extract_last_scan_timestamp(items: List[Dict[str, Any]]) -> tuple[Optional[datetime], Optional[str]]:
    latest: Optional[datetime] = None
    source_key: Optional[str] = None
    for item in items:
        if not isinstance(item, dict):
            continue
        candidates = [item]
        for nested_key in ("policy", "scan", "summary", "metadata"):
            nested = item.get(nested_key)
            if isinstance(nested, dict):
                candidates.append(nested)
        for candidate in candidates:
            for key in _SCAN_TIMESTAMP_KEYS:
                parsed = _parse_timestamp(candidate.get(key))
                if parsed is None:
                    continue
                if latest is None or parsed > latest:
                    latest = parsed
                    source_key = key
    return latest, source_key


class PostActionVerificationLoop:
    def __init__(self, client: WazuhClient | None = None):
        self.client = client or WazuhClient()
        self.enabled = _to_bool(_cfg("verification.post_action.enabled", True), True)
        self.initial_delay_seconds = max(
            1, _to_int(_cfg("verification.post_action.initial_delay_seconds", 5), 5)
        )
        self.max_delay_seconds = max(
            self.initial_delay_seconds,
            _to_int(_cfg("verification.post_action.max_delay_seconds", 60), 60),
        )
        self.max_attempts = max(
            1, _to_int(_cfg("verification.post_action.max_attempts", 6), 6)
        )
        self.restart_batch_size = max(
            1, _to_int(_cfg("verification.post_action.restart_batch_size", 25), 25)
        )
        self.max_parallel_checks = max(
            1, _to_int(_cfg("verification.post_action.max_parallel_checks", 20), 20)
        )
        configured = _cfg("verification.post_action.actions", None)
        if isinstance(configured, list):
            self.allowed_actions = {
                str(item).strip().lower() for item in configured if str(item).strip()
            }
        else:
            self.allowed_actions = set(_DEFAULT_VERIFY_ACTIONS)
        self.include_capability_triggers = _to_bool(
            _cfg("verification.post_action.include_capability_triggers", False),
            False,
        )

    def should_verify(self, action_id: str) -> bool:
        aid = str(action_id or "").strip().lower()
        if not aid or not self.enabled:
            return False
        if aid in self.allowed_actions:
            return True
        if not self.include_capability_triggers:
            return False
        capability = get_action_capability(aid)
        return bool(capability and capability.triggers_sca_rescan)

    def _chunked_agent_ids(self, agent_ids: List[str]) -> List[List[str]]:
        size = max(1, int(self.restart_batch_size or 1))
        return [agent_ids[i : i + size] for i in range(0, len(agent_ids), size)]

    def _trigger_sca_rescan(self, agent_ids: Iterable[str]) -> Dict[str, Any]:
        ordered_ids: List[str] = []
        seen = set()
        for aid in agent_ids or []:
            raw = str(aid or "").strip()
            if not raw or raw in seen:
                continue
            seen.add(raw)
            ordered_ids.append(raw)
        if not ordered_ids:
            return {
                "ok": False,
                "batched": False,
                "error": "no_valid_agents",
                "triggered_agents": [],
                "failed_agents": [],
            }

        batches = self._chunked_agent_ids(ordered_ids)
        triggered_agents: List[str] = []
        failed_agents: List[Dict[str, str]] = []
        batch_errors: List[str] = []
        batch_responses: List[Dict[str, Any]] = []

        for batch in batches:
            if not batch:
                continue
            try:
                response = self.client.restart_agents(batch)
                batch_responses.append(
                    {
                        "batch": batch,
                        "ok": True,
                        "response": response,
                    }
                )
                triggered_agents.extend(batch)
                continue
            except Exception as batch_exc:
                batch_responses.append(
                    {
                        "batch": batch,
                        "ok": False,
                        "error": str(batch_exc),
                    }
                )
                batch_errors.append(str(batch_exc))

            # Degrade gracefully to per-agent retries for only the failed batch.
            for agent_id in batch:
                try:
                    self.client.restart_agents([agent_id])
                    triggered_agents.append(agent_id)
                except Exception as single_exc:
                    failed_agents.append(
                        {
                            "agent_id": agent_id,
                            "error": str(single_exc),
                        }
                    )

        triggered_set = []
        seen_triggered = set()
        for aid in triggered_agents:
            if aid in seen_triggered:
                continue
            seen_triggered.add(aid)
            triggered_set.append(aid)

        return {
            "ok": len(failed_agents) == 0 and len(triggered_set) == len(ordered_ids),
            "batched": len(batches) > 1,
            "batch_size": self.restart_batch_size,
            "attempted_batches": len(batches),
            "batch_results": batch_responses,
            "error": " | ".join(batch_errors) if batch_errors else "",
            "triggered_agents": triggered_set,
            "failed_agents": failed_agents,
        }

    def _check_sca_state(
        self,
        agent_id: str,
        baseline_last_scan: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        try:
            payload = self.client.get_agent_sca(agent_id, limit=5)
            items = _extract_items(payload)
            last_scan_ts, last_scan_source = _extract_last_scan_timestamp(items)
            sca_items_present = bool(items)
            fresh = True
            if baseline_last_scan is not None:
                fresh = bool(last_scan_ts and last_scan_ts > baseline_last_scan)
            ready = sca_items_present and fresh
            return {
                "ok": True,
                "ready": ready,
                "sca_items_present": sca_items_present,
                "fresh": fresh,
                "items": len(items),
                "last_scan": _format_timestamp(last_scan_ts),
                "last_scan_source": last_scan_source,
                "baseline_last_scan": _format_timestamp(baseline_last_scan),
            }
        except Exception as exc:
            return {
                "ok": False,
                "ready": False,
                "sca_items_present": False,
                "fresh": False if baseline_last_scan is not None else True,
                "error": str(exc),
                "baseline_last_scan": _format_timestamp(baseline_last_scan),
            }

    def verify_targets(
        self,
        action_id: str,
        execution_id: int | str | None,
        target_rows: Iterable[Dict[str, Any]],
    ) -> Dict[str, Any]:
        aid = str(action_id or "").strip().lower()
        if not self.should_verify(aid):
            return {
                "skipped": True,
                "reason": f"action_not_eligible:{aid or 'unknown'}",
            }

        rows = [row for row in (target_rows or []) if isinstance(row, dict)]
        successful_agents: List[str] = []
        seen = set()
        for row in rows:
            if not row.get("ok"):
                continue
            agent_id = str(row.get("agent_id") or "").strip()
            if not agent_id or agent_id in seen:
                continue
            seen.add(agent_id)
            successful_agents.append(agent_id)

        if not successful_agents:
            return {
                "skipped": True,
                "reason": "no_successful_targets",
            }

        per_target_by_agent: Dict[str, Dict[str, Any]] = {}
        baseline_by_agent: Dict[str, Optional[datetime]] = {}
        for agent_id in successful_agents:
            pre_check = self._check_sca_state(agent_id)
            pre_scan_ts = _parse_timestamp(pre_check.get("last_scan"))
            baseline_by_agent[agent_id] = pre_scan_ts
            per_target_by_agent[agent_id] = {
                "agent_id": agent_id,
                "rescan_triggered": False,
                "pre_scan_last_scan": pre_check.get("last_scan"),
                "checks": [],
                "status": "trigger_failed",
            }

        trigger = self._trigger_sca_rescan(successful_agents)
        triggered_agents = trigger.get("triggered_agents") or []
        failed_agents = trigger.get("failed_agents") or []
        failed_map = {
            str(item.get("agent_id") or "").strip(): str(item.get("error") or "")
            for item in failed_agents
            if isinstance(item, dict)
        }

        for agent_id in successful_agents:
            target = per_target_by_agent[agent_id]
            if agent_id in triggered_agents:
                target["rescan_triggered"] = True
                target["status"] = "pending_verify"
            else:
                target["status"] = "trigger_failed"
                target["trigger_error"] = failed_map.get(agent_id) or str(trigger.get("error") or "")

        pending = [aid_value for aid_value in successful_agents if aid_value in triggered_agents]
        delay = self.initial_delay_seconds

        for attempt in range(1, self.max_attempts + 1):
            if not pending:
                break
            time.sleep(delay)
            next_pending: List[str] = []
            check_by_agent: Dict[str, Dict[str, Any]] = {}
            workers = max(1, min(self.max_parallel_checks, len(pending)))

            if workers == 1:
                for agent_id in pending:
                    baseline = baseline_by_agent.get(agent_id)
                    check_by_agent[agent_id] = self._check_sca_state(
                        agent_id,
                        baseline_last_scan=baseline,
                    )
            else:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {
                        pool.submit(
                            self._check_sca_state,
                            agent_id,
                            baseline_by_agent.get(agent_id),
                        ): agent_id
                        for agent_id in pending
                    }
                    for fut in as_completed(futures):
                        agent_id = futures[fut]
                        try:
                            check_by_agent[agent_id] = fut.result()
                        except Exception as exc:
                            check_by_agent[agent_id] = {
                                "ok": False,
                                "ready": False,
                                "sca_items_present": False,
                                "fresh": False,
                                "error": str(exc),
                                "baseline_last_scan": _format_timestamp(
                                    baseline_by_agent.get(agent_id)
                                ),
                            }

            for agent_id in pending:
                check = check_by_agent.get(agent_id) or {
                    "ok": False,
                    "ready": False,
                    "sca_items_present": False,
                    "fresh": False,
                    "error": "missing_check_result",
                    "baseline_last_scan": _format_timestamp(baseline_by_agent.get(agent_id)),
                }
                check["attempt"] = attempt
                check["delay_seconds"] = delay
                target = per_target_by_agent[agent_id]
                target["checks"].append(check)
                if check.get("ready"):
                    target["status"] = "verified"
                    target["post_scan_last_scan"] = check.get("last_scan")
                else:
                    next_pending.append(agent_id)
            pending = next_pending
            if pending:
                delay = min(self.max_delay_seconds, max(delay * 2, delay + 1))

        for agent_id in pending:
            per_target_by_agent[agent_id]["status"] = "timeout"

        per_target = [per_target_by_agent[agent_id] for agent_id in successful_agents]
        verified_count = sum(1 for row in per_target if row.get("status") == "verified")
        timeout_count = sum(1 for row in per_target if row.get("status") == "timeout")
        trigger_failed_count = sum(1 for row in per_target if row.get("status") == "trigger_failed")
        ok = timeout_count == 0 and trigger_failed_count == 0 and verified_count == len(per_target)

        result = {
            "skipped": False,
            "action_id": aid,
            "execution_id": execution_id,
            "strategy": "batched_sca_rescan_with_exponential_backoff_and_freshness_check",
            "initial_delay_seconds": self.initial_delay_seconds,
            "max_delay_seconds": self.max_delay_seconds,
            "max_attempts": self.max_attempts,
            "restart_batch_size": self.restart_batch_size,
            "max_parallel_checks": self.max_parallel_checks,
            "trigger": {
                "ok": bool(trigger.get("ok")),
                "batched": bool(trigger.get("batched")),
                "triggered": len(triggered_agents),
                "failed": len(failed_agents),
            },
            "summary": {
                "targets": len(per_target),
                "verified": verified_count,
                "timed_out": timeout_count,
                "trigger_failed": trigger_failed_count,
            },
            "targets": per_target,
            "ok": ok,
        }
        logger.info(
            "Post-action verification complete action=%s execution=%s summary=%s",
            aid,
            execution_id,
            result["summary"],
        )
        return result


def run_post_action_verification(
    client: WazuhClient,
    action_id: str,
    execution_id: int | str | None,
    target_rows: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    verifier = PostActionVerificationLoop(client=client)
    return verifier.verify_targets(action_id, execution_id, target_rows)
