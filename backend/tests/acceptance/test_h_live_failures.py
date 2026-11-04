"""H rows that need the separate agent process: enrollment failure (11), agent crash (13)."""

from __future__ import annotations

import pytest

from tests.conftest import live_stack
from tests.flows import approve, deploy, deployed_agent, fault, precheck, prepared, remove_agent, request_deployment

pytestmark = pytest.mark.acceptance


async def test_row11_enrollment_failure(db_path, tmp_path):
    async with live_stack(db_path, tmp_path, enrollment_timeout_sec=2.0) as (h, _p):
        await prepared(h)
        await fault(h, "dev-ews01", "enrollment_failure")
        dep = await request_deployment(h, "192.168.20.13")
        await approve(h, dep)
        await precheck(h, dep["id"])
        done = await deploy(h, dep["id"])
        assert done["status"] == "FAILED" and done["failureCode"] == "ENROLLMENT_FAILED"
        agent = await h.get(f"/agents/{done['agentId']}")
        assert agent["status"] == "ERROR"
        rejected = (await h.get("/audit-events", params={"action": "ENROLLMENT_TOKEN_REJECTED"}))["total"]
        assert rejected >= 1
        assert (await h.get("/audit-events", params={"action": "AGENT_ENROLLMENT_FAILED"}))["total"] == 1
        # recovery: remove the half-installed agent, then deploy again
        await fault(h, "dev-ews01", "enrollment_failure", False)
        removal = await remove_agent(h, agent["id"])
        assert removal["status"] == "COMPLETED"
        retry = (await h.post(f"/deployments/{dep['id']}/retry", expect=201)).json()
        await approve(h, retry)
        await precheck(h, retry["id"])
        assert (await deploy(h, retry["id"]))["status"] == "COMPLETED"


async def test_row13_agent_crash_and_restart(live):
    h, _proc = live
    asset_id, agent_id = await deployed_agent(h)
    await fault(h, "dev-ews01", "agent_crashed")
    await h.wait_for(f"/agents/{agent_id}", lambda a: a["status"] == "OFFLINE", timeout=15)
    probe = await h.probe("192.168.20.13")   # agentless view of the crash
    running = next(r for r in probe["results"] if r["protocol"] == "WMI")["data"]["services.running"]
    assert "OTProbeAgent" not in running
    agent = await h.get(f"/agents/{agent_id}")
    assert agent["actions"]["restart"]["enabled"] is True
    r = await h.client.post(f"/api/v1/agents/{agent_id}/restart")
    assert r.status_code == 200, r.text
    await h.wait_for(f"/agents/{agent_id}", lambda a: a["status"] == "ONLINE", timeout=15)
    assert (await h.get("/audit-events", params={"action": "AGENT_SERVICE_RESTARTED"}))["total"] == 1
