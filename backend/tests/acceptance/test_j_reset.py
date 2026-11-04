"""J: Reset POC (confirmed) restores seed state; the audit log survives; discovery history is optional."""

from __future__ import annotations

import pytest

from tests.flows import as_admin, assess, deployed_agent, set_config

pytestmark = pytest.mark.acceptance


async def test_reset_restores_seed_state(live):
    h, _proc = live
    asset_id, agent_id = await deployed_agent(h)
    await assess(h, asset_id)
    await set_config(h, "dev-ews01", "firewall", "disabled")
    await as_admin(h, "post", "/demo/devices/dev-ews02/faults", {"fault": "device_offline"})
    await as_admin(h, "post", "/demo/rogue", expect=201)
    audit_before = (await h.get("/audit-events"))["total"]

    assert (await h.post("/demo/reset", {"confirm": "RESET"})).status_code == 403          # operator
    r = await as_admin(h, "post", "/demo/reset", {"confirm": "yes"}, expect=422)
    assert r.json()["type"].endswith("confirmation-required")
    result = (await as_admin(h, "post", "/demo/reset", {"confirm": "RESET"}, expect=200)).json()
    assert result["agentsRevoked"] == 1 and result["cleared"]["assets"] == 5
    assert result["discoveryHistory"].startswith("kept")

    assert (await h.get("/assets"))["total"] == 0
    assert (await h.get("/agents"))["total"] == 0 and (await h.get("/findings"))["total"] == 0
    assert (await h.get("/deployments"))["total"] == 0 and (await h.get("/assessments"))["total"] == 0
    jobs = (await h.get("/discovery/jobs"))["items"]
    assert len(jobs) == 1                                                                  # history kept
    audit = await h.get("/audit-events")
    assert audit["total"] > audit_before and audit["items"][0]["action"] == "POC_RESET"
    assert (await h.get("/audit-events/verify"))["valid"] is True

    world = h.ctx.extras["world"]
    ews = world.device("dev-ews01")
    assert ews.state["firewall"]["state"] == "enabled" and "agent" not in ews.state.get("files", {})
    assert ews.faults == {} and world.device("dev-ews02").online
    assert world.device("dev-rogue-1") is None

    job = await h.discover(["192.168.20.0/24"])                       # archived history is not a rogue baseline
    assert job["newAssets"] == 5 and job["rogueCount"] == 0

    result = (await as_admin(h, "post", "/demo/reset", {"confirm": "RESET", "clearDiscoveryHistory": True})).json()
    assert result["discoveryHistory"] == "cleared" and (await h.get("/discovery/jobs"))["total"] == 0


async def test_reset_refuses_while_workflows_run(discovered):
    h = discovered
    ews = await h.asset_by_ip("192.168.20.13")
    await h.post(f"/assets/{ews['id']}/probes", expect=202)
    r = await as_admin(h, "post", "/demo/reset", {"confirm": "RESET"}, expect=None)
    if r.status_code == 409:   # probe still running: refused unless forced
        assert r.json()["type"].endswith("workflows-running")
        r = await as_admin(h, "post", "/demo/reset", {"confirm": "RESET", "force": True}, expect=200)
    assert r.status_code == 200
