"""OTProbe telemetry simulator: a SEPARATE process standing in for the plant's MQTT publishers.

Every interval it reads the publishers' physical state (online, injected overrides) from /sim/v1 and publishes
deterministic readings (SEED) through the in-process broker: temperature, pressure and PLC status.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random

import httpx

log = logging.getLogger("otprobe.telemetry-sim")

API = os.environ.get("OTPROBE_API_URL", "http://127.0.0.1:8000").rstrip("/")
TOKEN = os.environ.get("SIM_SERVICE_TOKEN", "change-me-sim-token")
INTERVAL = float(os.environ.get("TELEMETRY_INTERVAL_SEC", "5"))
SEED = int(os.environ.get("SEED", "42"))
PLC_EVERY = 2   # PLC status every 2 intervals (10 s by default)


def reading(topic: str, tick: int, override: float | None) -> dict | None:
    rnd = random.Random(f"{SEED}:{topic}:{tick}")
    kind = topic.rsplit("/", 1)[-1]
    if kind == "temperature":
        value = override if override is not None else round(42.5 + rnd.uniform(-1.5, 1.5), 1)
        return {"temperature": value, "unit": "C"}
    if kind == "pressure":
        value = override if override is not None else round(4.2 + rnd.uniform(-0.2, 0.2), 2)
        return {"pressure": value, "unit": "bar"}
    if kind == "status":
        if tick % PLC_EVERY:
            return None
        return {"mode": "RUN", "cycleMs": 12, "cpuLoad": 20 + rnd.randint(0, 8)}
    return None


async def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    headers = {"X-Sim-Token": TOKEN}
    log.info("telemetry-sim publishing to %s every %.1fs (seed %d)", API, INTERVAL, SEED)
    tick = 0
    async with httpx.AsyncClient(timeout=10, headers=headers) as client:
        while True:
            try:
                sources = (await client.get(f"{API}/sim/v1/telemetry/sources")).json()
                for src in sources:
                    if not src["online"]:
                        continue
                    for topic in src["topics"]:
                        payload = reading(topic, tick, src.get("override"))
                        if payload is not None:
                            await client.post(f"{API}/sim/v1/mqtt/publish",
                                              json={"clientId": src["clientId"], "topic": topic, "payload": payload})
            except httpx.HTTPError as exc:
                log.warning("cannot reach OTProbe: %s", exc)
            tick += 1
            await asyncio.sleep(INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
