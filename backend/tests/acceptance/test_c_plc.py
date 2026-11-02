"""C: PLC-01 shows agentless data; Deploy Agent is disabled with the stated reason."""

import pytest

pytestmark = pytest.mark.acceptance
REASON = "Traditional PLCs are handled agentless/read-only in this POC."


async def test_plc_01(discovered):
    h = discovered
    probe = await h.probe("192.168.10.10")
    assert probe["status"] == "COMPLETED"
    steps = {s["name"]: s for s in probe["steps"]}
    assert steps["SNMP"]["status"] == "OK" and "mode RUN, firmware V2.9" in steps["SNMP"]["detail"]
    assert steps["WINRM"]["status"] == "SKIPPED" and "Safe mode" in steps["WINRM"]["detail"]
    asset = await h.asset_by_ip("192.168.10.10")
    fields = {f["path"]: f for g in asset["groups"].values() for f in g}
    assert fields["plc.mode"]["value"] == "RUN" and fields["plc.mode"]["source"] == "SNMP"
    assert fields["firmware.version"]["value"] == "V2.9"
    assert fields["hardware.vendor"]["value"] == "Siemens-style (demo data)"
    assert "S7-1500 Demo" in fields["hardware.model"]["value"]
    assert fields["hardware.vendor"]["sourceLabel"] == "SNMP (Demo)"
    assert asset["type"] == "PLC" and asset["level"] == "1"
    assert asset["deployAgent"] == {"enabled": False, "reason": REASON}
    assert asset["agentless"]["enabled"] is True
    assert asset["eligibility"] == "NOT_ELIGIBLE"
