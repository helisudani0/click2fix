from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from typing import Any, Callable


logger = logging.getLogger(__name__)


def _as_text(value: Any) -> str:
    text = str(value or "").strip()
    return text


def _alert_id(alert: dict[str, Any]) -> str | None:
    for key in ("id", "_id", "alert_id"):
        raw = alert.get(key)
        if raw is None or isinstance(raw, (dict, list)):
            continue
        token = _as_text(raw)
        if token:
            return token
    return None


class AlertStreamProcessor:
    """
    Shared in-process alert stream.

    - One background fetch loop for all websocket subscribers.
    - Push API for synchronous paths (thread-safe via run_coroutine_threadsafe).
    - Dedup by alert id with bounded seen-id cache.
    """

    def __init__(
        self,
        *,
        history_size: int = 200,
        seen_cache_size: int = 20000,
        queue_size: int = 500,
    ):
        self._history = deque(maxlen=max(20, int(history_size)))
        self._seen_cache_size = max(200, int(seen_cache_size))
        self._seen_ids: set[str] = set()
        self._seen_order = deque(maxlen=self._seen_cache_size)
        self._queue_size = max(20, int(queue_size))

        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._state_lock = asyncio.Lock()

        self._fetcher: Callable[[int], list[dict[str, Any]]] | None = None
        self._fetch_limit = 200
        self._poll_seconds = 1.0
        self._poll_task: asyncio.Task | None = None

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread_lock = threading.Lock()

    async def start(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        fetcher: Callable[[int], list[dict[str, Any]]],
        poll_seconds: float = 1.0,
        fetch_limit: int = 200,
    ) -> None:
        safe_poll = max(0.2, float(poll_seconds))
        safe_limit = max(10, int(fetch_limit))
        with self._thread_lock:
            self._loop = loop
            self._fetcher = fetcher
            self._poll_seconds = safe_poll
            self._fetch_limit = safe_limit

        if self._poll_task and not self._poll_task.done():
            return
        self._poll_task = asyncio.create_task(self._poll_loop(), name="alert-stream-poller")

    async def stop(self) -> None:
        task = self._poll_task
        self._poll_task = None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def subscribe(self, *, snapshot_limit: int = 40) -> tuple[asyncio.Queue[dict[str, Any]], list[dict[str, Any]]]:
        safe_snapshot_limit = max(0, int(snapshot_limit))
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        async with self._state_lock:
            self._subscribers.add(queue)
            if safe_snapshot_limit <= 0:
                snapshot: list[dict[str, Any]] = []
            else:
                snapshot = list(self._history)[-safe_snapshot_limit:]
        return queue, snapshot

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._state_lock:
            self._subscribers.discard(queue)

    async def publish(self, alert: dict[str, Any]) -> bool:
        if not isinstance(alert, dict):
            return False
        aid = _alert_id(alert)
        if not aid:
            return False

        payload = dict(alert)
        async with self._state_lock:
            if aid in self._seen_ids:
                return False
            self._seen_ids.add(aid)
            self._seen_order.append(aid)
            if len(self._seen_ids) > self._seen_cache_size:
                while len(self._seen_order) > self._seen_cache_size // 2:
                    stale = self._seen_order.popleft()
                    self._seen_ids.discard(stale)
            self._history.append(payload)
            subscribers = list(self._subscribers)

        for queue in subscribers:
            self._enqueue(queue, payload)
        return True

    async def publish_many(self, alerts: list[dict[str, Any]]) -> None:
        rows = [item for item in (alerts or []) if isinstance(item, dict)]
        # Source pulls are newest-first; stream should emit oldest-first.
        for alert in reversed(rows):
            await self.publish(alert)

    def publish_from_thread(self, alert: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            running = asyncio.get_running_loop()
            if running is loop:
                running.create_task(self.publish(alert))
                return
        except RuntimeError:
            pass
        try:
            asyncio.run_coroutine_threadsafe(self.publish(alert), loop)
        except Exception:
            return

    def publish_many_from_thread(self, alerts: list[dict[str, Any]]) -> None:
        rows = [item for item in (alerts or []) if isinstance(item, dict)]
        if not rows:
            return
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        try:
            running = asyncio.get_running_loop()
            if running is loop:
                running.create_task(self.publish_many(rows))
                return
        except RuntimeError:
            pass
        try:
            asyncio.run_coroutine_threadsafe(self.publish_many(rows), loop)
        except Exception:
            return

    def _enqueue(self, queue: asyncio.Queue[dict[str, Any]], payload: dict[str, Any]) -> None:
        try:
            queue.put_nowait(payload)
            return
        except asyncio.QueueFull:
            pass
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass

    async def _poll_loop(self) -> None:
        while True:
            try:
                async with self._state_lock:
                    has_subscribers = bool(self._subscribers)
                if not has_subscribers:
                    await asyncio.sleep(self._poll_seconds)
                    continue
                fetcher = self._fetcher
                if fetcher is not None:
                    rows = await asyncio.to_thread(fetcher, self._fetch_limit)
                    if isinstance(rows, list) and rows:
                        await self.publish_many(rows)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("Alert stream poll failed: %s", exc)
            await asyncio.sleep(self._poll_seconds)


_ALERT_STREAM = AlertStreamProcessor()


async def start_alert_stream(
    *,
    loop: asyncio.AbstractEventLoop,
    fetcher: Callable[[int], list[dict[str, Any]]],
    poll_seconds: float = 1.0,
    fetch_limit: int = 200,
) -> None:
    await _ALERT_STREAM.start(
        loop=loop,
        fetcher=fetcher,
        poll_seconds=poll_seconds,
        fetch_limit=fetch_limit,
    )


async def stop_alert_stream() -> None:
    await _ALERT_STREAM.stop()


async def subscribe_alerts(
    *,
    snapshot_limit: int = 40,
) -> tuple[asyncio.Queue[dict[str, Any]], list[dict[str, Any]]]:
    return await _ALERT_STREAM.subscribe(snapshot_limit=snapshot_limit)


async def unsubscribe_alerts(queue: asyncio.Queue[dict[str, Any]]) -> None:
    await _ALERT_STREAM.unsubscribe(queue)


def publish_alert(alert: dict[str, Any]) -> None:
    _ALERT_STREAM.publish_from_thread(alert)


def publish_alert_batch(alerts: list[dict[str, Any]]) -> None:
    _ALERT_STREAM.publish_many_from_thread(alerts)
