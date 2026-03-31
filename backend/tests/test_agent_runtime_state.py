from __future__ import annotations

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core import agent_runtime_state as state_store  # noqa: E402


class _MissingTableDB:
    def execute(self, *_args, **_kwargs):
        raise RuntimeError('relation "agent_runtime_state" does not exist')

    def commit(self):
        return None

    def close(self):
        return None


def test_missing_agent_runtime_state_table_is_non_fatal(monkeypatch):
    monkeypatch.setattr(state_store, "connect", lambda: _MissingTableDB())

    assert state_store.get_agent_state(
        state_kind=state_store.STATE_SCA_BASELINE,
        agent_id="group:default",
        tenant_id=1,
    ) is None

    assert state_store.find_any_agent_state(
        state_kind=state_store.STATE_SCA_BASELINE,
        agent_id="group:default",
    ) is None

    payload = state_store.upsert_agent_state(
        state_kind=state_store.STATE_SCA_BASELINE,
        agent_id="group:default",
        tenant_id=1,
        value={"baseline": {"checks": 0}},
        updated_by="qa",
    )
    assert payload == {"baseline": {"checks": 0}}

    # No exception when table is absent.
    state_store.clear_agent_runtime_state(
        state_kind=state_store.STATE_SCA_BASELINE,
        agent_id="group:default",
        tenant_id=1,
    )
