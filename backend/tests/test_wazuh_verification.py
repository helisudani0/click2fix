from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.wazuh_verification import derive_verification_state  # noqa: E402


def test_derive_verification_state_marks_scan_lag_as_pending():
    state = derive_verification_state(
        {
            "skipped": False,
            "ok": False,
            "summary": {
                "targets": 1,
                "verified": 0,
                "timed_out": 1,
                "trigger_failed": 0,
            },
        }
    )

    assert state["pending"] is True
    assert state["step_status"] == "PENDING"
    assert state["execution_status"] == "PENDING_VERIFICATION"


def test_derive_verification_state_marks_trigger_failures_as_failed():
    state = derive_verification_state(
        {
            "skipped": False,
            "ok": False,
            "summary": {
                "targets": 1,
                "verified": 0,
                "timed_out": 0,
                "trigger_failed": 1,
            },
        }
    )

    assert state["pending"] is False
    assert state["step_status"] == "FAILED"
    assert state["execution_status"] is None
