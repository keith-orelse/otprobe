"""H: each failure scenario in docs/FAILURE_MATRIX.md behaves as documented: resulting state, message, audit
event and recovery. Rows 12 (heartbeat) and 14 (assessment timeout) are covered in test_g / test_phase4_extras."""

from __future__ import annotations

import pytest

from tests.flows import approve, as_admin, deploy, fault, precheck, publish, request_deployment

pytestmark = pytest.mark.acceptance
EWS = "192.168.20.13"


async def audit_count(h, action: str) -> int:
    return (await h.get("/audit-events", params={"action": action}))["total"]


async def approved_deployment(h) -> dict:
    await h.probe(EWS)
    dep = await request_deployment(h, EWS)
    await approve(h, dep)
    await h.login("operator")
    return dep


async def test_row01_device_offline(discovered):
    h = discovered
    await fault(h, "dev-ews02", "device_offline")
    probe = await h.probe("192.168.20.14")
    assert probe["status"] == "FAILED" and probe["error"] == "Device not reachable by ARP or ICMP"
    assert (await h.asset_by_ip("192.168.20.14"))["status"] == "OFFLINE"
    assert await audit_count(h, "ASSET_UNREACHABLE") >= 1
    await fault(h, "dev-ews02", "device_offline", False)
    assert (await h.probe("192.168.20.14"))["status"] == "COMPLETED"


@pytest.mark.parametrize("name,check,message,event", [
    ("winrm_disabled", "WINRM_AVAILABLE", "WinRM service is disabled on target (5986 refused by service)",
     "WINRM_DISABLED"),
    ("winrm_refused", "WINRM_AVAILABLE", "Connection refused on 192.168.20.13:5986", "WINRM_CONNECTION_REFUSED"),
    ("winrm_timeout", "WINRM_AVAILABLE", "WinRM connection timed out after 5 s", "WINRM_TIMEOUT"),
    ("winrm_bad_credentials", "AUTHENTICATION",
     "Authentication failed for profile OT-WINDOWS-INSTALLER (demo\\agent-installer)", "WINRM_AUTH_FAILED"),
    ("winrm_bad_certificate", "AUTHENTICATION",
     "TLS certificate validation failed: certificate not trusted (CN=eng-ws-01-selfsigned)", "WINRM_TLS_INVALID"),
])
async def test_rows02_06_winrm_failures(discovered, name, check, message, event):
    h = discovered
    dep = await approved_deployment(h)
    await fault(h, "dev-ews01", name)
    pre = await precheck(h, dep["id"])
    assert pre["status"] == "PRECHECK_FAILED"
    result = {c["check"]: c for c in pre["precheck"]}[check]
    assert result["status"] == "FAIL" and result["detail"] == message
    assert pre["actions"]["deploy"]["enabled"] is False
    assert await audit_count(h, event) == 1 and await audit_count(h, "PRECHECK_FAILED") == 1
    await fault(h, "dev-ews01", name, False)                       # recovery
    assert (await precheck(h, dep["id"]))["status"] == "PRECHECK_PASSED"


async def test_row07_icmp_blocked(discovered):
    h = discovered
    await fault(h, "dev-ews01", "icmp_blocked")
    probe = await h.probe(EWS)
    icmp = next(s for s in probe["steps"] if s["name"] == "ICMP")
    assert icmp["detail"] == "BLOCKED: no ICMP reply. This does not mean the device is offline."
    assert probe["status"] == "COMPLETED" and (await h.asset_by_ip(EWS))["status"] == "ONLINE"
    assert await audit_count(h, "ICMP_BLOCKED_OBSERVED") == 1


async def test_row08_snmp_timeout(discovered):
    h = discovered
    await fault(h, "dev-sw01", "snmp_timeout")
    job = await h.discover(["192.168.20.0/24"])
    assert job["status"] == "COMPLETED"
    probe = await h.probe("192.168.20.1")
    snmp = next(s for s in probe["steps"] if s["name"] == "SNMP")
    assert probe["status"] == "PARTIAL" and snmp["status"] == "FAILED"
    assert snmp["detail"] == "SNMPv3 request timed out (profile OT-SNMPV3-RO). Identity fields not refreshed"
    assert await audit_count(h, "SNMP_TIMEOUT") == 1
    assert (await h.asset_by_ip("192.168.20.1"))["sysName"] == "industrial-switch-01"   # earlier data kept


async def test_row09_checksum_mismatch(discovered):
    h = discovered
    dep = await approved_deployment(h)
    await precheck(h, dep["id"])
    await fault(h, "dev-ews01", "package_checksum_mismatch")
    done = await deploy(h, dep["id"])
    assert done["status"] == "FAILED" and done["failureCode"] == "HASH_MISMATCH"
    assert done["failureDetail"].startswith("Package hash mismatch: expected")
    assert done["agentId"] is None and await audit_count(h, "DEPLOY_HASH_FAIL") == 1


async def test_row10_install_failure(discovered):
    h = discovered
    dep = await approved_deployment(h)
    await precheck(h, dep["id"])
    await fault(h, "dev-ews01", "install_failure")
    done = await deploy(h, dep["id"])
    assert done["status"] == "FAILED" and done["failureCode"] == "INSTALL_FAILED"
    assert done["failureDetail"] == "Agent installer failed (exit code 1603). Installer rolled back"
    assert await audit_count(h, "DEPLOY_INSTALL_FAIL") == 1
    dev = h.ctx.extras["world"].device("dev-ews01")
    assert "agent" not in dev.state["files"]
    await fault(h, "dev-ews01", "install_failure", False)
    retry = (await h.post(f"/deployments/{dep['id']}/retry", expect=201)).json()
    assert retry["status"] == "PENDING_APPROVAL" and retry["retryOfId"] == dep["id"]


async def test_row16_plc_offline(h_fast):
    h = h_fast
    await h.discover(["192.168.10.0/24"])
    await publish(h, "plc01", "factory/line1/plc01/status", {"mode": "RUN", "cycleMs": 12})
    await fault(h, "dev-plc01", "plc_offline")
    await publish(h, "plc01", "factory/line1/plc01/status", {"mode": "RUN"}, expect=409)   # publisher is down
    found = await h.wait_for("/findings", lambda d: any(f["ruleId"] == "TEL-PLC-001" for f in d["items"]),
                             timeout=10)
    f = next(x for x in found["items"] if x["ruleId"] == "TEL-PLC-001")
    assert f["status"] == "OPEN" and f["severity"] == "HIGH" and f["source"] == "TELEMETRY"
    assert str(f["observed"]).startswith("no message for")
    assert await audit_count(h, "TELEMETRY_THRESHOLD_EXCEEDED") == 1
    assert (await h.probe("192.168.10.10"))["status"] == "FAILED"
    await fault(h, "dev-plc01", "plc_offline", False)
    await publish(h, "plc01", "factory/line1/plc01/status", {"mode": "RUN", "cycleMs": 12})
    assert (await h.get(f"/findings/{f['id']}"))["status"] == "RESOLVED"


async def test_row17_sensor_temperature(discovered):
    h = discovered
    topic = "factory/line1/sensor01/temperature"
    await publish(h, "sensor01", topic, {"temperature": 42.5, "unit": "C"})
    assert (await h.get("/findings", params={"source": "TELEMETRY"}))["total"] == 0
    await publish(h, "sensor01", topic, {"temperature": 97.0, "unit": "C"})
    by_rule = {f["ruleId"]: f for f in (await h.get("/findings", params={"source": "TELEMETRY"}))["items"]}
    assert by_rule["TEL-TEMP-001"]["resultStatus"] == "WARNING" and by_rule["TEL-TEMP-001"]["severity"] == "MEDIUM"
    assert by_rule["TEL-TEMP-002"]["resultStatus"] == "FAIL" and by_rule["TEL-TEMP-002"]["severity"] == "CRITICAL"
    assert by_rule["TEL-TEMP-002"]["observed"] == 97.0
    events = (await h.get("/audit-events", params={"action": "TELEMETRY_THRESHOLD_EXCEEDED"}))["items"]
    assert any("(sensor01) reported 97.0 C on factory/line1/sensor01/temperature" in e["details"]["message"]
               for e in events)
    await publish(h, "sensor01", topic, {"temperature": 43.0, "unit": "C"})
    assert {f["status"] for f in (await h.get("/findings", params={"source": "TELEMETRY"}))["items"]} == {"RESOLVED"}
    topics = {t["topic"]: t for t in await h.get("/telemetry/topics")}
    assert topics[topic]["assetName"] == "192.168.10.20" and topics[topic]["messages"] == 3   # not probed yet
    await h.probe("192.168.10.20")   # probing reveals the MQTT client id, used as the display name
    assert {t["topic"]: t for t in await h.get("/telemetry/topics")}[topic]["assetName"] == "sensor01"


async def test_row18_inject_rogue(discovered):
    h = discovered
    r = await as_admin(h, "post", "/demo/rogue", expect=201)
    assert r.json()["ip"] == "192.168.20.66"
    await h.discover(["192.168.20.0/24"])
    f = (await h.get("/findings", params={"ruleId": "NET-ROGUE-001"}))["items"][0]
    assert f["status"] == "OPEN" and await audit_count(h, "ROGUE_DEVICE_DETECTED") == 1
    await as_admin(h, "post", f"/assets/{f['assetId']}/authorize", {"reason": "Known HMI panel"})
    assert (await h.get(f"/findings/{f['id']}"))["status"] == "RESOLVED"


async def test_simulation_controls_are_admin_only(discovered):
    h = discovered
    r = await h.post("/demo/devices/dev-ews01/faults", {"fault": "device_offline"})
    assert r.status_code == 403
    r = await h.post("/demo/reset", {"confirm": "RESET"})
    assert r.status_code == 403
    r = await as_admin(h, "post", "/demo/devices/dev-ews01/faults", {"fault": "nope"}, expect=422)
    assert "Available:" in r.json()["detail"]
