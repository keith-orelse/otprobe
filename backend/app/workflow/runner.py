"""In-process asyncio job runner (single API worker by design; see ARCHITECTURE §6)."""

from __future__ import annotations

import asyncio
import logging
from typing import Coroutine

log = logging.getLogger("otprobe.runner")


class JobRunner:
    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}

    def submit(self, key: str, coro: Coroutine) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(coro, name=key)
        self._tasks[key] = task

        def _done(t: asyncio.Task) -> None:
            self._tasks.pop(key, None)
            if not t.cancelled() and t.exception() is not None:
                log.error("job %s crashed", key, exc_info=t.exception())

        task.add_done_callback(_done)
        return task

    def cancel(self, key: str) -> bool:
        task = self._tasks.get(key)
        if task is None:
            return False
        task.cancel()
        return True

    def active(self) -> list[str]:
        return list(self._tasks)

    def is_running(self, key: str) -> bool:
        return key in self._tasks

    async def wait_idle(self, timeout: float = 30.0) -> None:
        if self._tasks:
            await asyncio.wait_for(asyncio.gather(*self._tasks.values(), return_exceptions=True), timeout)

    async def shutdown(self) -> None:
        for t in list(self._tasks.values()):
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks.values(), return_exceptions=True)
