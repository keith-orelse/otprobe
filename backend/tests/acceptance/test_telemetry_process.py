"""MQTT telemetry end to end with the SEPARATE telemetry simulator process publishing through the broker."""

from __future__ import annotations

import pytest

from tests.conftest import Harness, LiveServer, spawn_telemetry_sim
from tests.flows import fault

pytestmark = pytest.mark.acceptance


async def test_telemetry_simulator_and_threshold(db_path, tmp_path):
    import httpx
    async with LiveServer(db_path) as srv:
        async with httpx.AsyncClient(base_url=srv.url, timeout=30) as client:
            h = await Harness(srv.app, client).login("operator")
            await h.discover(["192.168.10.0/24"])
            proc = spawn_telemetry_sim(srv.url, tmp_path / "telemetry.log", interval=0.2)
            try:
                topics = await h.wait_for("/telemetry/topics", lambda t: len(t) == 3 and all(
                    x["messages"] >= 2 for x in t), timeout=15)
                by = {t["topic"]: t for t in topics}
                temp = by["factory/line1/sensor01/temperature"]
                assert 40 <= temp["lastPayload"]["temperature"] <= 45 and temp["lastPayload"]["unit"] == "C"
                assert by["factory/line1/plc01/status"]["lastPayload"]["mode"] == "RUN"
                assert all(t["assetId"] for t in topics)   # attributed via broker client IP -> asset
                assert by["factory/line1/plc01/status"]["assetName"] == "plc-01"
                await fault(h, "dev-ts01", "sensor_value_override", params={"value": 97.0})
                found = await h.wait_for("/findings", lambda d: any(
                    f["ruleId"] == "TEL-TEMP-002" for f in d["items"]), timeout=10)
                assert any(f["severity"] == "CRITICAL" for f in found["items"])
                await fault(h, "dev-ts01", "sensor_value_override", enabled=False)
                await h.wait_for("/findings", lambda d: d["total"] > 0 and all(
                    f["status"] == "RESOLVED" for f in d["items"] if f["source"] == "TELEMETRY"), timeout=10)
            finally:
                proc.terminate()
                proc.wait(5)
