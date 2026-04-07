from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core import playbook_generator as playbook_gen  # noqa: E402


def test_normalize_ai_steps_rejects_unknown_actions_by_default():
    actions = {"endpoint-healthcheck": {"id": "endpoint-healthcheck"}}
    raw_steps = [
        {"id": "step_1", "action": "custom-remediate-script", "args": {"foo": "bar"}, "reason": "draft"},
    ]

    normalized = playbook_gen._normalize_ai_steps(raw_steps, actions)

    assert normalized == []


def test_normalize_ai_steps_allows_unknown_actions_in_prompt_mode():
    actions = {"endpoint-healthcheck": {"id": "endpoint-healthcheck"}}
    raw_steps = [
        {"id": "step_1", "action": "Custom-Remediate.Script", "args": {"foo": "bar"}, "reason": "draft"},
    ]

    normalized = playbook_gen._normalize_ai_steps(
        raw_steps,
        actions,
        allow_unknown_actions=True,
    )

    assert len(normalized) == 1
    assert normalized[0]["action"] == "custom-remediate.script"
    assert normalized[0]["args"] == {"foo": "bar"}


def test_heuristic_steps_prefer_healthcheck_safe_fallback():
    alert = {
        "rule_id": 100001,
        "rule_description": "Application error event",
        "rule_level": 3,
        "raw_json": {},
    }
    actions = {
        "firewall-drop": {"id": "firewall-drop"},
        "endpoint-healthcheck": {"id": "endpoint-healthcheck"},
    }

    steps = playbook_gen._heuristic_steps(alert, [], actions)

    assert len(steps) == 1
    assert steps[0]["action"] == "endpoint-healthcheck"


def test_generate_playbook_prompt_returns_unmapped_actions(monkeypatch):
    monkeypatch.setattr(
        playbook_gen,
        "_collect_actions",
        lambda: {"endpoint-healthcheck": {"id": "endpoint-healthcheck"}},
    )

    monkeypatch.setattr(
        playbook_gen,
        "_ai_generate_steps_from_prompt",
        lambda **_kwargs: {
            "name": "Prompt Playbook",
            "description": "AI prompt result",
            "analysis": "ok",
            "confidence": "high",
            "steps": [
                {
                    "id": "step_1",
                    "action": "custom-remediate.script",
                    "args": {"policy": "tighten"},
                    "reason": "Not in catalog but needed",
                }
            ],
            "unmapped_actions": ["custom-remediate.script"],
        },
    )

    out = playbook_gen.generate_playbook(
        alert_id=None,
        case_id=None,
        use_ai=True,
        ai_prompt="Harden endpoint policies",
        ai_config={"provider": "openai", "api_key": "test-key", "enabled": True},
    )

    assert out["source"]["generation_mode"] == "ai_prompt"
    assert out["source"]["unmapped_actions"] == ["custom-remediate.script"]
    assert out["steps"][0]["action"] == "custom-remediate.script"


def test_collect_actions_includes_virtual_global_shell(monkeypatch):
    monkeypatch.setattr(
        playbook_gen,
        "list_actions",
        lambda: [{"id": "endpoint-healthcheck", "label": "Endpoint Healthcheck"}],
    )

    actions = playbook_gen._collect_actions()

    assert "endpoint-healthcheck" in actions
    assert "global-shell" in actions
    assert actions["global-shell"]["id"] == "global-shell"
