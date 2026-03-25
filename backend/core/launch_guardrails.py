from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


_LOCK = threading.Lock()
_RECENT_LAUNCHES: dict[str, deque[float]] = defaultdict(deque)
_BURST_THRESHOLDS = {3, 5, 10}


def register_launch(event_type: str, *, actor: str | None, window_seconds: int = 900) -> int:
    key = f"{str(event_type or '').strip().lower()}:{str(actor or 'unknown').strip().lower() or 'unknown'}"
    now = time.time()
    safe_window = max(60, int(window_seconds))
    cutoff = now - safe_window
    with _LOCK:
        bucket = _RECENT_LAUNCHES[key]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(now)
        return len(bucket)


def should_emit_burst(count: int) -> bool:
    return int(count or 0) in _BURST_THRESHOLDS


def reset_launch_guardrails_state() -> None:
    with _LOCK:
        _RECENT_LAUNCHES.clear()
