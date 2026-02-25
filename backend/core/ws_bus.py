import asyncio
from concurrent.futures import Future
from typing import Any, Dict, Optional

channels: Dict[int, list] = {}
_main_loop: Optional[asyncio.AbstractEventLoop] = None


def set_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """
    Register the app's primary asyncio loop so we can safely publish from
    threadpool workers (sync endpoints / background execution).
    """
    global _main_loop
    _main_loop = loop


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


def _schedule_on_loop(loop: asyncio.AbstractEventLoop, coro) -> Optional[Future]:
    try:
        return asyncio.run_coroutine_threadsafe(coro, loop)
    except Exception:
        return None


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
    if not execution_id:
        return

    eid = int(execution_id)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(publish(eid, message))
        return
    except RuntimeError:
        pass

    if _main_loop and _main_loop.is_running():
        _schedule_on_loop(_main_loop, publish(eid, message))
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
