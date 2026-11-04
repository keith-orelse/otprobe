"""F: disable the firewall on eng-ws-01 and reassess: WIN-FW-001 PASS->FAIL, a drift event and an OPEN HIGH finding
(visible via GET /api/v1/findings and in the audit log). Re-enable: RESOLVED. Regress again: REOPENED."""

from __future__ import annotations

import pytest

from tests.flows import assess, deployed_agent, set_config

pytestmark = pytest.mark.acceptance


def fw(run: dict) -> dict:
    return next(r for r in run["results"] if r["ruleId"] == "WIN-FW-001")


async def test_firewall_drift_lifecycle(live):
    h, _proc = live
    asset_id, _ = await deployed_agent(h)
    first = await assess(h, asset_id)
    assert fw(first)["status"] == "PASS"

    await set_config(h, "dev-ews01", "firewall", "disabled")
    second = await assess(h, asset_id)
    assert fw(second)["status"] == "FAIL" and fw(second)["previousStatus"] == "PASS"
    assert second["previousRunId"] == first["id"]
    assert [(d["ruleId"], d["fromStatus"], d["toStatus"], d["before"], d["after"]) for d in second["driftEvents"]] == [
        ("WIN-FW-001", "PASS", "FAIL", "enabled", "disabled")]
    assert {"path": "firewall.state", "before": "enabled", "after": "disabled"} in [
        {k: c[k] for k in ("path", "before", "after")} for c in second["evidenceChanges"]]

    found = (await h.get("/findings", params={"ruleId": "WIN-FW-001", "assetId": asset_id}))["items"]
    assert len(found) == 1
    finding = found[0]
    assert finding["status"] == "OPEN" and finding["severity"] == "HIGH" and finding["observed"] == "disabled"
    drift_audit = (await h.get("/audit-events", params={"action": "CONFIGURATION_DRIFT_DETECTED"}))["items"]
    assert len(drift_audit) == 1 and drift_audit[0]["entityId"] == finding["id"]
    assert drift_audit[0]["details"]["ruleId"] == "WIN-FW-001" and drift_audit[0]["details"]["to"] == "FAIL"
    detail = await h.get(f"/findings/{finding['id']}")
    assert detail["driftEvents"][0]["runId"] == second["id"]
    assert (await h.get("/drift-events", params={"assetId": asset_id}))["total"] == 1

    await set_config(h, "dev-ews01", "firewall", "enabled")
    third = await assess(h, asset_id)
    assert fw(third)["status"] == "PASS" and third["driftEvents"] == []
    resolved = await h.get(f"/findings/{finding['id']}")
    assert resolved["status"] == "RESOLVED" and resolved["resolvedAt"]

    await set_config(h, "dev-ews01", "firewall", "disabled")
    fourth = await assess(h, asset_id)
    assert fw(fourth)["status"] == "FAIL" and len(fourth["driftEvents"]) == 1
    reopened = await h.get(f"/findings/{finding['id']}")
    assert reopened["status"] == "REOPENED" and reopened["reopenCount"] == 1
    assert [(e["fromStatus"], e["toStatus"]) for e in reopened["events"]] == [
        (None, "OPEN"), ("OPEN", "RESOLVED"), ("RESOLVED", "REOPENED")]
    actions = [e["action"] for e in (await h.get("/audit-events", params={"entityId": finding["id"]}))["items"]]
    for name in ("FINDING_OPENED", "FINDING_RESOLVED", "FINDING_REOPENED", "CONFIGURATION_DRIFT_DETECTED"):
        assert name in actions
    # still deduplicated: one finding per asset + rule
    assert (await h.get("/findings", params={"ruleId": "WIN-FW-001"}))["total"] == 1
