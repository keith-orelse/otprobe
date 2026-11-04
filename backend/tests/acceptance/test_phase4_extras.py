"""Phase 4 supporting behaviour: agentless findings, rogue finding, risk acceptance, RBAC, scheduler, timeout."""

from __future__ import annotations

import pytest

from tests.conftest import live_stack
from tests.flows import assess, deployed_agent

pytestmark = pytest.mark.acceptance


async def test_agentless_probe_raises_unsupported_os_finding(discovered):
    h = discovered
    probe = await h.probe("192.168.20.14")
    evaluate = next(s for s in probe["steps"] if s["name"] == "EVALUATE")
    assert evaluate["status"] == "OK" and "1 fail" in evaluate["detail"]
    f = (await h.get("/findings", params={"ruleId": "WIN-OS-001"}))["items"]
    assert len(f) == 1 and f[0]["source"] == "AGENTLESS" and f[0]["severity"] == "HIGH"
    assert f[0]["observed"] == "Windows 10 Enterprise" and f[0]["assetName"] == "eng-ws-02"
    plc = await h.probe("192.168.10.10")
    assert next(s for s in plc["steps"] if s["name"] == "EVALUATE")["status"] == "SKIPPED"
    ews1 = await h.probe("192.168.20.13")   # agentless sees no unauthorized software -> no false finding
    assert (await h.get("/findings", params={"assetId": ews1["assetId"]}))["total"] == 0


async def test_rogue_device_finding_and_authorize(discovered):
    h = discovered
    h.ctx.extras["world"].inject_rogue()
    await h.discover(["192.168.20.0/24"])
    f = (await h.get("/findings", params={"ruleId": "NET-ROGUE-001"}))["items"][0]
    assert f["status"] == "OPEN" and f["severity"] == "HIGH" and f["source"] == "DISCOVERY"
    r = await h.post(f"/assets/{f['assetId']}/authorize", {"reason": "New HMI panel CHG-1042"})
    assert r.status_code == 403
    await h.login("admin")
    await h.post(f"/assets/{f['assetId']}/authorize", {"reason": "New HMI panel CHG-1042"}, expect=200)
    assert (await h.get(f"/findings/{f['id']}"))["status"] == "RESOLVED"
    assert (await h.get(f"/assets/{f['assetId']}"))["isRogue"] is False


async def test_accept_risk_is_admin_only_with_reason(discovered):
    h = discovered
    await h.probe("192.168.20.14")
    f = (await h.get("/findings", params={"ruleId": "WIN-OS-001"}))["items"][0]
    assert f["actions"]["acceptRisk"] == {"enabled": False, "reason": "Only an admin can accept risk"}
    r = await h.post(f"/findings/{f['id']}/accept-risk", {"reason": "Vendor tool needs Win10 until upgrade"})
    assert r.status_code == 403
    await h.login("admin")
    r = await h.post(f"/findings/{f['id']}/accept-risk", {"reason": "no"})
    assert r.status_code == 422
    ok = await h.post(f"/findings/{f['id']}/accept-risk", {"reason": "Vendor tool needs Win10 until upgrade"},
                      expect=200)
    assert ok.json()["status"] == "ACCEPTED_RISK" and ok.json()["acceptedBy"] == "admin"
    await h.probe("192.168.20.14")   # still failing: stays accepted
    assert (await h.get(f"/findings/{f['id']}"))["status"] == "ACCEPTED_RISK"
    back = await h.post(f"/findings/{f['id']}/revoke-acceptance", {"reason": "Upgrade cancelled"}, expect=200)
    assert back.json()["status"] == "OPEN"


async def test_assessment_needs_agent_and_operator(discovered):
    h = discovered
    await h.probe("192.168.20.13")
    a = await h.asset_by_ip("192.168.20.13")
    assert a["compliance"]["runAction"] == {"enabled": False, "reason": "Deep assessment needs an enrolled agent"}
    r = await h.post(f"/assets/{a['id']}/assessments")
    assert r.status_code == 409
    await h.login("approver")
    assert (await h.post(f"/assets/{a['id']}/assessments")).status_code == 403


async def test_scheduler_and_timeout(db_path, tmp_path):
    async with live_stack(db_path, tmp_path, assessment_interval_sec=2.0, assessment_timeout_sec=1.5) as (h, _p):
        asset_id, _ = await deployed_agent(h)
        sched = await h.wait_for("/assessments", lambda d: any(
            r["trigger"] == "SCHEDULED" and r["status"] == "EVALUATED" for r in d["items"]), timeout=20)
        assert sched["items"][0]["requestedBy"] == "assessment-scheduler"
        detail = await h.get(f"/assets/{asset_id}")
        assert detail["compliance"]["nextAssessmentAt"] is not None
        dash = await h.get("/dashboard/summary")
        assert dash["monitoring"][0]["agentStatus"] == "ONLINE" and dash["monitoring"][0]["score"] == 75.0
        findings_before = (await h.get("/findings"))["total"]

        h.ctx.sim_control.set_fault("dev-ews01", "assessment_timeout", {}, "test")
        await h.wait_for(f"/assets/{asset_id}", lambda a: a["compliance"]["runAction"]["enabled"], timeout=10)
        run = await assess(h, asset_id, until=("TIMED_OUT", "EVALUATED"))
        assert run["status"] == "TIMED_OUT" and "no evidence received" in run["error"]
        assert (await h.get("/findings"))["total"] == findings_before
