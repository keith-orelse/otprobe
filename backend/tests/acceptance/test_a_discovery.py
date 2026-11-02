"""A: discovery shows devices progressively; assets merged by MAC; sensors found only via ARP."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import uvicorn

from app.main import create_app
from tests.conftest import BOTH_SUBNETS, free_port, make_settings

pytestmark = pytest.mark.acceptance
SENSORS = {"192.168.10.20", "192.168.10.21"}


async def test_progressive_discovery_events(h):
    q, _ = h.ctx.hub.subscribe()
    job = await h.discover()
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    h.ctx.hub.unsubscribe(q)
    assert job["status"] == "COMPLETED" and job["progress"] == 100 and job["devicesFound"] == 9
    progress = [e.data["progress"] for e in events if e.type == "discovery.progress"]
    assert progress == [10, 30, 60, 100]
    found = [e for e in events if e.type == "discovery.device_found"]
    assert len(found) == 9 and len({e.data["mac"] for e in found}) == 9
    # devices arrive one by one during the ARP phase, i.e. before the 30% milestone
    idx_30 = next(i for i, e in enumerate(events) if e.type == "discovery.progress" and e.data["progress"] == 30)
    assert all(events.index(e) < idx_30 for e in found)
    counts = [e.data["devicesFound"] for e in found]
    assert counts == sorted(counts) and counts[0] == 1 and counts[-1] == 9
    assert [s["name"] for s in job["steps"]] == ["VALIDATE", "ARP", "ICMP", "SNMP", "MERGE"]
    assert "SAFE MODE for 192.168.10.0/24" in job["steps"][0]["detail"]


async def test_merge_by_mac_and_ip_change(discovered):
    h = discovered
    before = {a["mac"]: a["id"] for a in await h.assets()}
    assert len(before) == 9
    job2 = await h.discover()
    assert job2["newAssets"] == 0 and job2["rogueCount"] == 0
    assert {a["mac"]: a["id"] for a in await h.assets()} == before

    h.ctx.extras["world"].update_state("dev-ews02", lambda st: None)
    from app.models import SimDevice
    with h.ctx.db.session() as s:
        s.get(SimDevice, "dev-ews02").ip = "192.168.20.15"
    await h.discover(["192.168.20.0/24"])
    after = {a["mac"]: a for a in await h.assets()}
    moved = after["00:1A:2B:3C:20:14"]
    assert moved["id"] == before["00:1A:2B:3C:20:14"] and moved["ip"] == "192.168.20.15"
    audit = await h.get("/audit-events", params={"action": "ASSET_IP_CHANGED"})
    assert audit["items"][0]["details"] == {"from": "192.168.20.14", "to": "192.168.20.15", "mac": "00:1A:2B:3C:20:14"}


async def test_sensors_found_only_via_arp(discovered):
    h = discovered
    for a in await h.assets():
        if a["ip"] in SENSORS:
            assert a["discoveredBy"] == ["ARP"]
            fields = await h.get(f"/assets/{a['id']}/fields")
            by_path = {(f["path"], f["source"]): f for f in fields}
            assert by_path[("network.mac", "ARP")]["stage"] == "DISCOVERY"
            assert by_path[("reachability.icmp", "ICMP")]["value"] == "BLOCKED"
            assert not any(f["source"] == "SNMP" for f in fields)
            detail = await h.get(f"/assets/{a['id']}")
            assert detail["status"] == "ONLINE"
            assert any("No ICMP reply does not mean the device is offline" in n for n in detail["notes"])
        else:
            assert "ARP" in a["discoveredBy"] and len(a["discoveredBy"]) > 1


async def test_discovery_alone_yields_only_discovery_fields(discovered):
    h = discovered
    ews = await h.asset_by_ip("192.168.20.13")
    paths = {f["path"] for f in await h.get(f"/assets/{ews['id']}/fields")}
    assert paths == {"network.ip", "network.mac", "reachability.icmp", "reachability.rtt_ms"}
    assert ews["hostname"] is None and ews["os"] is None and ews["eligibility"] == "UNKNOWN"
    switch = await h.asset_by_ip("192.168.20.1")
    assert switch["sysName"] == "industrial-switch-01" and switch["hostname"] is None
    assert {f["source"] for g in switch["groups"].values() for f in g} == {"ARP", "ICMP", "SNMP"}


async def test_rogue_device_on_rediscovery(discovered):
    h = discovered
    h.ctx.extras["world"].inject_rogue()
    job = await h.discover(["192.168.20.0/24"])
    assert job["rogueCount"] == 1 and job["newAssets"] == 1
    rogue = next(a for a in await h.assets() if a["isRogue"])
    assert rogue["mac"] == "DE:AD:BE:EF:20:66" and rogue["ip"] == "192.168.20.66"
    ev = (await h.get("/audit-events", params={"action": "ROGUE_DEVICE_DETECTED"}))["items"]
    assert ev[0]["entityId"] == rogue["id"]


async def test_offline_device_marked_after_discovery(discovered):
    h = discovered
    h.ctx.extras["world"].set_power("dev-plc02", False)
    await h.discover(["192.168.10.0/24"])
    plc2 = await h.asset_by_ip("192.168.10.11")
    assert plc2["status"] == "OFFLINE"


async def test_sse_stream_over_http(db_path):
    """Real HTTP + SSE through uvicorn (loopback only), as the console consumes it."""
    port = free_port()
    app = create_app(make_settings(db_path, speed_factor=0.02))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.02)
    base = f"http://127.0.0.1:{port}/api/v1"
    found, statuses = [], []
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            login = await client.post(f"{base}/auth/login", json={"username": "operator", "password": "operator-demo"})
            client.headers["Authorization"] = f"Bearer {login.json()['accessToken']}"
            ticket = (await client.post(f"{base}/auth/stream-ticket")).json()["ticket"]
            params = {"topics": "discovery", "ticket": ticket}
            async with client.stream("GET", f"{base}/events/stream", params=params) as stream:
                assert stream.headers["content-type"].startswith("text/event-stream")
                r = await client.post(f"{base}/discovery/jobs", json={"targets": BOTH_SUBNETS},
                                      headers={"Idempotency-Key": "sse-test"})
                assert r.status_code == 202
                event = None
                async for line in stream.aiter_lines():
                    if line.startswith("event:"):
                        event = line.split(":", 1)[1].strip()
                    elif line.startswith("data:"):
                        data = json.loads(line.split(":", 1)[1])
                        if event == "discovery.device_found":
                            found.append(data["data"]["ip"])
                        if event == "discovery.status":
                            statuses.append(data["data"]["status"])
                            if data["data"]["status"] == "COMPLETED":
                                break
    finally:
        server.should_exit = True
        await task
    assert len(found) == 9 and statuses[-1] == "COMPLETED"
