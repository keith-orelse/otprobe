"""I: rollback completes; agent REMOVED; credential revoked (heartbeat with the old credential rejected); all history
remains. Also: rollback failure (failure matrix row 15) and its admin retry."""

from __future__ import annotations

import pytest

from tests.flows import assess, deployed_agent, fault, remove_agent

pytestmark = pytest.mark.acceptance


async def test_rollback_keeps_history_and_revokes(live):
    h, _proc = live
    asset_id, agent_id = await deployed_agent(h)
    run = await assess(h, asset_id)
    assert run["status"] == "EVALUATED"
    credential = h.ctx.extras["world"].device("dev-ews01").state["files"]["agent_identity"]["credential"]
    before = {p: (await h.get(p))["total"] for p in ("/assessments", "/findings", "/deployments", "/audit-events")}
    hb_before = (await h.get(f"/agents/{agent_id}/heartbeats"))["total"]

    # requester cannot approve own removal either
    await h.login("operator")
    rem = (await h.post(f"/agents/{agent_id}/removals", {"purpose": "End of POC"}, expect=201)).json()
    assert (await h.post(f"/approvals/{rem['approval']['id']}/approve")).status_code == 403
    await h.login("approver")
    await h.post(f"/approvals/{rem['approval']['id']}/approve", expect=200)
    await h.login("operator")
    await h.post(f"/removals/{rem['id']}/start", expect=202)
    done = await h.wait_for(f"/removals/{rem['id']}", lambda r: r["status"] in ("COMPLETED", "FAILED"))
    assert done["status"] == "COMPLETED"
    assert [(s["name"], s["status"]) for s in done["steps"]] == [(n, "OK") for n in (
        "STOP_ASSESSMENTS", "CONNECT", "STOP_AGENT", "UNINSTALL", "REVOKE_IDENTITY", "REMOVE_TEMP_FILES",
        "VALIDATE_DEVICE", "ROLLBACK_COMPLETED")]

    agent = await h.get(f"/agents/{agent_id}")
    assert agent["status"] == "REMOVED" and agent["revokedAt"] and agent["removedAt"]
    asset = await h.get(f"/assets/{asset_id}")
    assert asset["agentState"] == "REMOVED" and asset["deployAgent"]["enabled"] is True
    dev = h.ctx.extras["world"].device("dev-ews01")
    assert "agent" not in dev.state["files"] and not any(s["name"] == "OTProbeAgent" for s in dev.state["services"])

    hb = {"seq": 999, "agentTime": "2026-11-04T10:00:00Z"}
    r = await h.client.post(f"/api/v1/agents/{agent_id}/heartbeat", json=hb,
                            headers={"Authorization": f"Bearer {credential}"})
    assert r.status_code == 401 and r.json()["type"].endswith("agent-credential-revoked")

    after = {p: (await h.get(p))["total"] for p in ("/assessments", "/findings", "/deployments", "/audit-events")}
    assert all(after[p] >= before[p] for p in before) and after["/audit-events"] > before["/audit-events"]
    assert (await h.get(f"/agents/{agent_id}/heartbeats"))["total"] >= hb_before
    assert (await h.get(f"/assessments/{run['id']}"))["status"] == "EVALUATED"
    events = (await h.get("/audit-events", params={"entityId": agent_id, "limit": 200}))["items"]
    actions = [e["action"] for e in events]
    assert {"AGENT_REMOVAL_STARTED", "AGENT_CREDENTIAL_REVOKED", "AGENT_REMOVED"} <= set(actions)
    assert (await h.get("/audit-events/verify"))["valid"] is True


async def test_rollback_failure_then_retry(live):
    h, _proc = live
    _, agent_id = await deployed_agent(h)
    await fault(h, "dev-ews01", "rollback_failure")
    failed = await remove_agent(h, agent_id)
    assert failed["status"] == "FAILED" and failed["failureCode"] == "UNINSTALL_FAILED"
    assert failed["failureDetail"] == "Uninstall failed (exit code 1603)"
    agent = await h.get(f"/agents/{agent_id}")
    assert agent["status"] == "ERROR" and agent["revokedAt"]   # identity revoked anyway (compensation)
    assert failed["actions"]["retry"] == {"enabled": False, "reason": "Only an admin can retry"}
    await fault(h, "dev-ews01", "rollback_failure", False)
    await h.login("admin")
    await h.post(f"/removals/{failed['id']}/retry", expect=202)
    done = await h.wait_for(f"/removals/{failed['id']}", lambda r: r["status"] in ("COMPLETED", "FAILED"))
    assert done["status"] == "COMPLETED"
    assert (await h.get(f"/agents/{agent_id}"))["status"] == "REMOVED"
    assert (await h.get("/audit-events", params={"action": "ROLLBACK_FAILED"}))["total"] == 1
