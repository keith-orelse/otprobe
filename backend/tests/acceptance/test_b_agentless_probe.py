"""B: agentless probe on eng-ws-01 shows ICMP/ARP/WinRM/WMI steps and per-field sources; classification."""

import pytest

pytestmark = pytest.mark.acceptance


async def test_eng_ws_01_probe(discovered):
    h = discovered
    probe = await h.probe("192.168.20.13")
    assert probe["status"] == "COMPLETED"
    steps = {s["name"]: s for s in probe["steps"]}
    assert [s["name"] for s in probe["steps"]][:4] == ["ICMP", "ARP", "WINRM", "WMI"]
    for name in ("ICMP", "ARP", "WINRM", "WMI", "COLLECT", "CLASSIFY"):
        assert steps[name]["status"] == "OK", steps[name]
    assert [st["name"] for st in steps["WINRM"]["data"]["stages"]] == [
        "CONNECTING", "TCP_OK", "TLS_VALIDATED", "AUTH_OK", "SESSION_CREATED"]
    assert {r["protocol"] for r in probe["results"]} == {"ICMP", "ARP", "WinRM", "WMI"}

    cls = probe["classification"]
    assert cls["type"] == "Windows Engineering Workstation"
    assert 80 <= cls["confidence"] < 100
    signals = {e["signal"] for e in cls["evidence"]}
    assert {"Windows OS", "WinRM available", "Engineering software detected", "Hostname pattern"} <= signals
    assert probe["eligibility"] == "ELIGIBLE"

    asset = await h.asset_by_ip("192.168.20.13")
    assert asset["hostname"] == "eng-ws-01" and asset["os"] == "Windows 11 Enterprise 24H2 (26100.2314)"
    groups = asset["groups"]
    for group in ("Identity", "Network", "Hardware", "OS", "Software", "Services", "Firewall", "Antivirus",
                  "Patch status"):
        assert groups.get(group), group
    sources = {f["path"]: (f["source"], f["stage"], f["sourceLabel"]) for g in groups.values() for f in g}
    assert sources["os.build"] == ("WMI", "AGENTLESS", "WMI/CIM (Demo)")
    assert sources["services.winrm.available"][0] == "WinRM"
    assert sources["network.mac"][0] == "ARP" and sources["reachability.icmp"][0] == "ICMP"
    software = next(f for f in groups["Software"] if f["path"] == "software.installed")["value"]
    assert "RemoteTool Demo" not in {a["name"] for a in software}  # per-user install: invisible agentless
    rel = {(r["peerName"], r["port"]) for r in asset["relationships"]}
    assert ("plc-01", 102) in rel


async def test_probe_with_wrong_credentials_is_partial(discovered):
    h = discovered
    await h.probe("192.168.20.13")
    h.ctx.extras["world"].set_fault("dev-ews01", "winrm_bad_credentials")
    probe = await h.probe("192.168.20.13")
    steps = {s["name"]: s for s in probe["steps"]}
    assert probe["status"] == "PARTIAL"
    assert steps["WINRM"]["status"] == "FAILED"
    assert "Authentication failed for profile OT-WINDOWS-READONLY" in steps["WINRM"]["detail"]
    assert [st["name"] for st in steps["WINRM"]["data"]["stages"]][-1] == "AUTH_OK"
    assert steps["WMI"]["status"] == "SKIPPED"


async def test_unreachable_device_probe_fails(discovered):
    h = discovered
    h.ctx.extras["world"].set_power("dev-ews02", False)
    probe = await h.probe("192.168.20.14")
    assert probe["status"] == "FAILED" and probe["error"] == "Device not reachable by ARP or ICMP"
    asset = await h.asset_by_ip("192.168.20.14")
    assert asset["status"] == "OFFLINE"


@pytest.mark.parametrize("ip,expected_type,eligibility", [
    ("192.168.20.14", "Windows Engineering Workstation", "ELIGIBLE"),
    ("192.168.20.139", "SCADA Server", "REVIEW_REQUIRED"),
    ("192.168.20.149", "Historian (Linux Server)", "NOT_SUPPORTED"),
    ("192.168.20.1", "Industrial Switch", "NOT_ELIGIBLE"),
    ("192.168.10.20", "Sensor", "NOT_ELIGIBLE"),
])
async def test_classification_and_eligibility_matrix(discovered, ip, expected_type, eligibility):
    probe = await discovered.probe(ip)
    assert probe["status"] == "COMPLETED"
    assert probe["classification"]["type"] == expected_type
    assert probe["eligibility"] == eligibility
    if expected_type == "Sensor":
        asset = await discovered.asset_by_ip(ip)
        assert asset["level"] == "0"
