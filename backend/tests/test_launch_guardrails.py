from __future__ import annotations

import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.launch_guardrails import register_launch, reset_launch_guardrails_state, should_emit_burst  # noqa: E402


def test_register_launch_counts_recent_events_per_actor_and_type():
    reset_launch_guardrails_state()

    assert register_launch("execution.global_shell_launch", actor="alice", window_seconds=300) == 1
    assert register_launch("execution.global_shell_launch", actor="alice", window_seconds=300) == 2
    assert register_launch("execution.global_shell_launch", actor="bob", window_seconds=300) == 1
    assert register_launch("execution.fleet_remediation_launch", actor="alice", window_seconds=300) == 1


def test_should_emit_burst_uses_expected_thresholds():
    assert should_emit_burst(3) is True
    assert should_emit_burst(5) is True
    assert should_emit_burst(10) is True
    assert should_emit_burst(2) is False
    assert should_emit_burst(4) is False
