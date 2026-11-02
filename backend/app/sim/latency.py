"""Deterministic simulated latency (SEED) scaled by SPEED_FACTOR."""

from __future__ import annotations

import random

from app.core.pacing import Pacer


class SimLatency:
    def __init__(self, seed: int, pacer: Pacer) -> None:
        self.seed, self.pacer = seed, pacer

    def jitter(self, key: str, base: float, spread: float = 0.2) -> float:
        rnd = random.Random(f"{self.seed}:{key}")
        return max(0.0, base * (1 + rnd.uniform(-spread, spread)))

    async def wait(self, key: str, base_sec: float, spread: float = 0.2) -> float:
        delay = self.jitter(key, base_sec, spread)
        await self.pacer.sleep(delay)
        return delay
