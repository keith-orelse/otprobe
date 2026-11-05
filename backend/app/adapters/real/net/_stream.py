"""One short TCP exchange for the OT plugins: connect, write vetted frames, read replies, close. Callers hold the
gate permit; ``guard`` is checked on every frame before it is written (read-only enforcement)."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Callable


class WriteAttemptBlocked(Exception):
    """A frame that is not on the plugin's read-only allow-list was about to be sent. Nothing was written."""


class Exchange:
    def __init__(self, ip: str, port: int, timeout_sec: float, guard: Callable[[bytes], bool]) -> None:
        self.ip, self.port, self.timeout, self.guard = ip, port, timeout_sec, guard
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.sent: list[bytes] = []

    async def __aenter__(self) -> "Exchange":
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(self.ip, self.port), self.timeout)
        return self

    async def __aexit__(self, *exc) -> None:
        if self.writer is not None:
            self.writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(self.writer.wait_closed(), 1.0)

    async def send(self, frame: bytes) -> None:
        if not self.guard(frame):
            raise WriteAttemptBlocked(f"refused to send a non-allow-listed frame ({frame[:16].hex()}...)")
        self.sent.append(frame)
        self.writer.write(frame)
        await self.writer.drain()

    async def read_exactly(self, n: int) -> bytes:
        return await asyncio.wait_for(self.reader.readexactly(n), self.timeout)
