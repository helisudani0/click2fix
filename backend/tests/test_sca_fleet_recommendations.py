from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.agents import (  # noqa: E402
    _build_fleet_action_plan,
    _dedupe_fleet_recommendations,
    _recommend_failed_checks,
)


def test_recommend_failed_checks_fills_missing_recommendation_text():
    policies = [
        {
            "policy_id": "cis-win",
            "policy_name": "CIS Windows",
            "checks": [
                {
                    "id": "15896",
                    "title": "Ensure firewall is enabled",
                    "description": "Firewall must be active.",
                    "remediation": "",
                    "result": "failed",
                }
            ],
        }
    ]

    rows = _recommend_failed_checks(
        policies,
        context={"vulnerabilities_critical": 1, "alerts_high": 0, "fim_events": 0, "mitre_tactics": []},
        limit=10,
    )

    assert rows
    rec = str(rows[0].get("recommendation") or "").strip()
    assert rec
    assert rec != "-"


def test_recommend_failed_checks_maps_to_attack_tactics():
    policies = [
        {
            "policy_id": "cis-win",
            "policy_name": "CIS Windows",
            "checks": [
                {
                    "id": "20001",
                    "title": "Detect brute force logon attempts",
                    "description": "Alert when brute force authentication failures are observed.",
                    "remediation": "",
                    "result": "failed",
                }
            ],
        }
    ]

    rows = _recommend_failed_checks(
        policies,
        context={"vulnerabilities_critical": 0, "alerts_high": 2, "fim_events": 0, "mitre_tactics": ["Credential Access"]},
        limit=10,
    )

    assert rows
    tactics = [str(item).lower() for item in (rows[0].get("matched_tactics") or [])]
    assert "credential access" in tactics


def test_dedupe_fleet_recommendations_collapses_equivalent_controls():
    rows = [
        {
            "agent_id": "002",
            "policy_name": "CIS Windows 10",
            "policy_id": "cis-win10",
            "check_id": "15896",
            "title": "Ensure firewall is enabled",
            "recommendation": "Restrict exposed network services and enforce firewall baseline rules.",
            "matched_categories": ["network"],
            "priority_score": 39.5,
        },
        {
            "agent_id": "002",
            "policy_name": "CIS Windows 11",
            "policy_id": "cis-win11",
            "check_id": "26060",
            "title": "Ensure firewall is enabled",
            "recommendation": "Restrict exposed network services and enforce firewall baseline rules.",
            "matched_categories": ["network"],
            "priority_score": 39.5,
        },
    ]

    deduped = _dedupe_fleet_recommendations(rows)

    assert len(deduped) == 1
    assert int(deduped[0].get("duplicate_count") or 0) == 2
    assert "CIS Windows 11" in (deduped[0].get("related_policies") or [])


def test_build_fleet_action_plan_groups_by_focus_area():
    rows = [
        {
            "fleet_rank": 1,
            "agent_id": "002",
            "priority": "critical",
            "priority_score": 39.5,
            "reason": "Control area match: network",
            "recommendation": "Restrict exposed network services and enforce firewall baseline rules.",
            "matched_categories": ["network"],
        },
        {
            "fleet_rank": 2,
            "agent_id": "003",
            "priority": "high",
            "priority_score": 35.0,
            "reason": "Control area match: network",
            "recommendation": "Restrict exposed network services and enforce firewall baseline rules.",
            "matched_categories": ["network"],
        },
    ]

    plan = _build_fleet_action_plan(rows, limit=5)

    assert plan
    assert plan[0]["focus_area"] == "network"
    assert plan[0]["focus_label"] == "Network Exposure"
    assert int(plan[0]["impacted_agents"]) == 2
