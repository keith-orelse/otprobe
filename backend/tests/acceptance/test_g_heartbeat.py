"""G: break heartbeat -> agent STALE then OFFLINE; restore -> ONLINE (separate agent process, real HTTP)."""

from __future__ import annotations

import pytest

from tests.flows import approve, deploy, precheck, prepared, request_deployment

pytestmark = pytest.mark.acceptance


async def test_heartbeat_loss_and_recovery(live):
    h, _proc = live
    await prepared(h)
    dep = await request_deployment(h, "192.168.20.13")
    await approve(h, dep)
    await precheck(h, dep["id"])
    done = await deploy(h, dep["id"])
    assert done["status"] == "COMPLETED"
    agent_path = f"/agents/{done['agentId']}"
    await h.wait_for(agent_path, lambda a: a["status"] == "ONLINE")

    await h.login("admin")
    await h.post("/demo/devices/dev-ews01/faults", {"fault": "heartbeat_blocked", "enabled": True}, expect=200)
    stale = await h.wait_for(agent_path, lambda a: a["status"] != "ONLINE", timeout=10)
    assert stale["status"] == "STALE" and stale["missedHeartbeats"] >= 3
    offline = await h.wait_for(agent_path, lambda a: a["status"] == "OFFLINE", timeout=10)
    assert offline["missedHeartbeats"] >= 6 and offline["secondsSinceHeartbeat"] >= 3

    await h.post("/demo/devices/dev-ews01/faults", {"fault": "heartbeat_blocked", "enabled": False}, expect=200)
    back = await h.wait_for(agent_path, lambda a: a["status"] == "ONLINE", timeout=10)
    assert back["missedHeartbeats"] == 0

    events = (await h.get("/audit-events", params={"entityId": done["agentId"], "limit": 100}))["items"]
    assert events and all(e["entityId"] == done["agentId"] for e in events)   # filter really applied
    sequence = [e["action"] for e in reversed(events)]
    assert sequence.index("AGENT_STALE") < sequence.index("AGENT_OFFLINE") < sequence.index("AGENT_RECOVERED")
    assert {e["actorName"] for e in events if e["action"] in ("AGENT_STALE", "AGENT_OFFLINE")} == {"heartbeat-watchdog"}
    assert (await h.asset_by_ip("192.168.20.13"))["agentState"] == "ONLINE"
    control = (await h.get("/audit-events", params={"action": "DEMO_CONTROL_APPLIED"}))["items"]
    assert control[0]["actorName"] == "admin"

    await h.login("operator")
    r = await h.post("/demo/devices/dev-ews01/faults", {"fault": "heartbeat_blocked", "enabled": True})
    assert r.status_code == 403   # simulation controls are admin only


async def test_agent_runtime_restart_resumes_without_reenrolling(live, tmp_path):
    """Killing the separate agent process makes the agent STALE/OFFLINE while the API keeps running; restarting it
    reuses the credential saved on the (simulated) host disk."""
    from tests.conftest import spawn_agent_runtime

    h, proc = live
    await prepared(h)
    dep = await request_deployment(h, "192.168.20.13")
    await approve(h, dep)
    await precheck(h, dep["id"])
    done = await deploy(h, dep["id"])
    agent_path = f"/agents/{done['agentId']}"
    await h.wait_for(agent_path, lambda a: a["status"] == "ONLINE")

    proc.terminate()
    proc.wait(5)
    await h.wait_for(agent_path, lambda a: a["status"] == "OFFLINE", timeout=15)
    assert (await h.get("/health"))["status"] == "ok"

    url = str(h.client.base_url).rstrip("/")
    proc2 = spawn_agent_runtime(url, tmp_path / "agent-runtime-2.log")
    try:
        await h.wait_for(agent_path, lambda a: a["status"] == "ONLINE", timeout=15)
    finally:
        proc2.terminate()
        proc2.wait(5)
    issued = (await h.get("/audit-events", params={"action": "AGENT_CREDENTIAL_ISSUED"}))["total"]
    assert issued == 1
