"""Simulated delays. Every visible wait in the POC goes through here so SPEED_FACTOR scales it."""

from __future__ import annotations

import asyncio


class Pacer:
    def __init__(self, speed_factor: float) -> None:
        self.speed_factor = speed_factor

    def scaled(self, seconds: float) -> float:
        return max(0.0, seconds * self.speed_factor)

    async def sleep(self, seconds: float) -> None:
        delay = self.scaled(seconds)
        if delay > 0:
            await asyncio.sleep(delay)
        else:
            await asyncio.sleep(0)
