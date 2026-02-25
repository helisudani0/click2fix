from typing import Dict, List

from core.settings import SETTINGS


def _normalize_requirements(reqs: List[Dict]) -> List[Dict]:
    normalized: List[Dict] = []
    for req in reqs or []:
        role = req.get("role")
        count = req.get("count", 1)
        if not role:
            continue
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 1
        normalized.append({"role": role, "count": max(1, count)})
    return normalized


def get_policy(action_id: str) -> Dict:
    cfg = SETTINGS.get("approval_policy", {}) if isinstance(SETTINGS, dict) else {}
    default_cfg = cfg.get("default", {}) if isinstance(cfg, dict) else {}
    actions_cfg = cfg.get("actions", {}) if isinstance(cfg, dict) else {}

    policy = dict(default_cfg) if isinstance(default_cfg, dict) else {}
    action_specific = actions_cfg.get(action_id, {}) if isinstance(actions_cfg, dict) else {}
    policy.update(action_specific)

    requirements = _normalize_requirements(
        policy.get("requirements") or policy.get("required") or []
    )
    if not requirements:
        requirements = [{"role": "admin", "count": 1}]

    return {
        "requirements": requirements,
        "justification_required": bool(policy.get("justification_required", False)),
    }
