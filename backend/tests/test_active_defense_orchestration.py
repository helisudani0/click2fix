from __future__ import annotations

import os
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault(
    "JWT_SECRET",
    "active-defense-test-secret-0123456789abcdef0123456789abcdef",
)
os.environ.setdefault("SECURITY_ENFORCE_STRONG_JWT", "false")

from core.active_defense import (  # noqa: E402
    build_contextual_approval_policy,
    build_incident_score,
    interpret_semantic_search,
    predict_alert_storm,
)


def test_build_contextual_approval_policy_requires_dual_authorization_for_critical_fleet_block():
    policy = build_contextual_approval_policy(
        "hash-blocklist",
        target_count=42,
        incident_priority="critical",
    )

    assert policy.get("handshake_required") is True
    assert policy.get("dual_authorization_required") is True
    assert policy.get("requirements") == [{"role": "admin", "count": 2}]


def test_build_contextual_approval_policy_requires_dual_authorization_for_run_as_system_shell():
    policy = build_contextual_approval_policy(
        "custom-os-command",
        target_count=1,
        context={"run_as_system": True},
    )

    assert policy.get("handshake_required") is True
    assert policy.get("dual_authorization_required") is True
    assert policy.get("requirements") == [{"role": "admin", "count": 2}]


def test_build_incident_score_emphasizes_blast_radius_and_tactical_depth():
    score = build_incident_score(
        agents=["TSPLLP129", "LAPTOP-9GQ8LUGU"],
        tactics=["execution", "persistence", "credential access"],
        alert_count=8,
        identities=["alice"],
        iocs=["ip:1.2.3.4"],
    )

    assert int(score.get("score") or 0) >= 70
    assert score.get("priority") in {"high", "critical"}
    assert score.get("breakdown", {}).get("mitre_stage_count") == 3


def test_interpret_semantic_search_extracts_time_window_and_powershell_terms():
    parsed = interpret_semantic_search("Show me all agents running unauthorized PowerShell in the last hour")

    assert parsed.get("enabled") is True
    assert "powershell" in str(parsed.get("query") or "").lower()
    assert parsed.get("start")


def test_predict_alert_storm_recommends_suppression_on_acceleration():
    prediction = predict_alert_storm(
        [
            {"hour": "2026-03-20T09:00:00Z", "count": 40},
            {"hour": "2026-03-20T10:00:00Z", "count": 75},
            {"hour": "2026-03-20T11:00:00Z", "count": 140},
        ]
    )

    assert prediction.get("storm_predicted") is True
    assert prediction.get("recommend_suppression") is True
    assert prediction.get("recommended_rule_level") == 3
