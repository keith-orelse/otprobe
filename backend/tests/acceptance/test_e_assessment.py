"""E: the first deep assessment on eng-ws-01 yields mixed PASS/FAIL/WARNING/UNKNOWN from data-driven rules, and
findings are created. Evidence is collected by the separate agent process and evaluated server-side."""

from __future__ import annotations

import pytest

from tests.flows import assess, deployed_agent

pytestmark = pytest.mark.acceptance


async def test_first_deep_assessment(live):
    h, _proc = live
    asset_id, agent_id = await deployed_agent(h)
    asset = await h.get(f"/assets/{asset_id}")
    assert asset["compliance"]["runAction"]["enabled"] is True

    run = await assess(h, asset_id)
    assert run["status"] == "EVALUATED" and run["source"] == "DEEP_AGENT" and run["agentId"] == agent_id
    status = {r["ruleId"]: r["status"] for r in run["results"]}
    assert {"PASS", "FAIL", "WARNING", "UNKNOWN"} == set(status.values())
    assert status["WIN-PATCH-001"] == "FAIL" and status["WIN-ADM-001"] == "FAIL"
    assert status["WIN-SW-001"] == "WARNING" and status["WIN-USB-001"] == "UNKNOWN"
    assert status["WIN-FW-001"] == "PASS" and status["AGT-HEALTH-001"] == "PASS"
    assert run["score"] == 75.0 and run["counts"] == {"pass": 7, "fail": 2, "warning": 1, "unknown": 1}
    patch = next(r for r in run["results"] if r["ruleId"] == "WIN-PATCH-001")
    assert patch["observed"] == 2 and patch["expected"] == "0 missing updates" and patch["severity"] == "HIGH"
    assert run["evidence"]["collectors"]["usb"].startswith("error:")

    findings = (await h.get("/findings", params={"assetId": asset_id, "source": "DEEP_AGENT"}))["items"]
    by_rule = {f["ruleId"]: f for f in findings}
    assert set(by_rule) == {"WIN-PATCH-001", "WIN-SW-001", "WIN-ADM-001"}
    assert by_rule["WIN-PATCH-001"]["severity"] == "HIGH" and by_rule["WIN-PATCH-001"]["status"] == "OPEN"
    assert by_rule["WIN-SW-001"]["resultStatus"] == "WARNING" and by_rule["WIN-SW-001"]["severity"] == "MEDIUM"
    assert by_rule["WIN-SW-001"]["observed"] == ["RemoteTool Demo"]   # only the offending items

    uploads = (await h.get("/audit-events", params={"action": "ASSESSMENT_EVIDENCE_UPLOADED"}))["items"]
    assert uploads[0]["actorName"].startswith("agent:") and uploads[0]["correlationId"] == run["correlationId"]

    compare = await h.get(f"/assets/{asset_id}/comparison")
    rows = {r["capability"]: r for r in compare["rows"]}
    assert rows["Applications"]["agentless"]["level"] == "Partial" and rows["Applications"]["deep"]["level"] == "Full"
    assert "RemoteTool Demo" in rows["Applications"]["deep"]["detail"]
    assert rows["Firewall"]["agentless"]["level"] == "Available" and rows["Firewall"]["deep"]["level"] == "Detailed"
    assert rows["Local administrators"]["agentless"]["level"] == "Not collected"
    assert rows["Local administrators"]["deep"]["level"] == "Collected"
    assert rows["Security policies"]["agentless"]["level"] == "Limited"
    assert rows["Continuous monitoring"]["deep"]["level"] == "Yes" and rows["Heartbeat"]["deep"]["level"] == "Yes"
    assert rows["Heartbeat"]["agentless"]["level"] == "N/A"

    detail = await h.get(f"/assets/{asset_id}")
    assert detail["compliance"]["score"] == 75.0 and detail["compliance"]["openFindings"] == 3
    deep_fields = [f for g in detail["groups"].values() for f in g if f["source"] == "DEEP_AGENT"]
    assert any(f["path"] == "local_admins.enabled_count" and f["stage"] == "DEEP" for f in deep_fields)
