import asyncio
import json
import logging
import os
import uuid
from concurrent.futures import Future
from typing import Any, Dict, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)

channels: Dict[int, list] = {}
_main_loop: Optional[asyncio.AbstractEventLoop] = None
_redis_loop: Optional[asyncio.AbstractEventLoop] = None
_redis_client: Optional[redis.Redis] = None
_redis_pubsub: Optional[redis.client.PubSub] = None
_redis_task: Optional[asyncio.Task] = None
_redis_channel = os.getenv("C2F_WS_REDIS_CHANNEL", "c2f:ws_bus")
_source_id = os.getenv("C2F_WS_SOURCE_ID", uuid.uuid4().hex)


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """
    Register the app's primary asyncio loop so we can safely publish from
    threadpool workers (sync endpoints / background execution).
    """
    global _main_loop
    _main_loop = loop
    # Auto-bootstrap Redis fanout once we know the app loop, even if the
    # caller still uses the legacy set_main_loop-only startup path.
    if not _redis_url():
        return
    coro = init_redis(loop)
    try:
        running = asyncio.get_running_loop()
        if running is loop:
            running.create_task(coro, name="ws-bus-redis-init")
            return
    except RuntimeError:
        pass
    _schedule_on_loop(loop, coro)


def _redis_url() -> str:
    url = os.getenv("C2F_WS_REDIS_URL") or os.getenv("REDIS_URL") or ""
    return str(url).strip()


async def init_redis(loop: asyncio.AbstractEventLoop) -> bool:
    """
    Enable Redis-backed fanout for execution events so multiple workers/instances
    can publish to the same WebSocket subscribers.
    """
    global _redis_client, _redis_pubsub, _redis_task, _redis_loop
    if _redis_client:
        return True

    url = _redis_url()
    if not url:
        return False

    try:
        _redis_client = redis.from_url(url, decode_responses=True)
        _redis_pubsub = _redis_client.pubsub()
        await _redis_pubsub.subscribe(_redis_channel)
        _redis_loop = loop
        _redis_task = loop.create_task(_redis_listener(), name="ws-bus-redis")
        logger.info("WS bus Redis enabled channel=%s", _redis_channel)
        return True
    except Exception as exc:
        logger.warning("WS bus Redis init failed: %s", exc)
        _redis_client = None
        _redis_pubsub = None
        _redis_loop = None
        return False


async def close_redis() -> None:
    global _redis_task, _redis_pubsub, _redis_client, _redis_loop
    task = _redis_task
    _redis_task = None
    if task:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass
    if _redis_pubsub:
        try:
            await _redis_pubsub.close()
        except Exception:
            pass
    if _redis_client:
        try:
            await _redis_client.close()
        except Exception:
            pass
    _redis_pubsub = None
    _redis_client = None
    _redis_loop = None


async def subscribe(execution_id: int, ws):
    channels.setdefault(execution_id, []).append(ws)


async def publish(execution_id: int, message: Dict[str, Any]):
    # Send to all subscribers; drop dead sockets to avoid leaking memory.
    subscribers = list(channels.get(execution_id, []) or [])
    for ws in subscribers:
        try:
            await ws.send_json(message)
        except Exception:
            try:
                channels.get(execution_id, []).remove(ws)
            except Exception:
                pass


async def _publish_redis(execution_id: int, message: Dict[str, Any]) -> None:
    if not _redis_client:
        return
    payload = {
        "execution_id": int(execution_id),
        "payload": message,
        "source_id": _source_id,
    }
    try:
        await _redis_client.publish(_redis_channel, json.dumps(payload, separators=(",", ":"), ensure_ascii=True))
    except Exception:
        return


async def _redis_listener() -> None:
    if _redis_pubsub is None:
        return
    while True:
        try:
            async for message in _redis_pubsub.listen():
                if message.get("type") != "message":
                    continue
                raw = message.get("data")
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except Exception:
                    continue
                if data.get("source_id") == _source_id:
                    continue
                execution_id = data.get("execution_id")
                payload = data.get("payload")
                if not execution_id or not isinstance(payload, dict):
                    continue
                try:
                    await publish(int(execution_id), payload)
                except Exception:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("WS bus Redis listener error: %s", exc)
            await asyncio.sleep(1.0)


def _schedule_on_loop(loop: asyncio.AbstractEventLoop, coro) -> Optional[Future]:
    try:
        return asyncio.run_coroutine_threadsafe(coro, loop)
    except Exception:
        return None


def _schedule_redis_publish(execution_id: int, message: Dict[str, Any]) -> None:
    if not _redis_client or not _redis_loop or not _redis_loop.is_running():
        return
    coro = _publish_redis(execution_id, message)
    try:
        running = asyncio.get_running_loop()
        if running is _redis_loop:
            running.create_task(coro)
            return
    except RuntimeError:
        pass
    _schedule_on_loop(_redis_loop, coro)


def publish_event(execution_id: int | None, message: Dict[str, Any]) -> None:
    """
    Fire-and-forget publish for both async and sync contexts.

    Key behavior:
    - If called from the main loop, schedule a task.
    - If called from a threadpool worker, schedule onto the main loop (if known).
    - As a last resort, run an ad-hoc loop (best-effort).

    Note: WebSocket objects are bound to the main loop; sending from a separate
    loop will fail. That's why we prefer scheduling onto `_main_loop`.
    """
    if not execution_id or not isinstance(message, dict):
        return

    eid = int(execution_id)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(publish(eid, message))
        _schedule_redis_publish(eid, message)
        return
    except RuntimeError:
        pass

    if _main_loop and _main_loop.is_running():
        _schedule_on_loop(_main_loop, publish(eid, message))
        _schedule_redis_publish(eid, message)
        return

    # Fallback: best-effort (may not work for WS sends, but avoids silent drops
    # during early startup / tests).
    try:
        asyncio.run(publish(eid, message))
    except Exception:
        return


async def unsubscribe(execution_id: int, ws):
    try:
        channels.get(execution_id, []).remove(ws)
    except Exception:
        return
