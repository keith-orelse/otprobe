"""OT device classification from plugin evidence (rules/classification.yaml). A controller that also answers Modbus
must stay a PLC; a Modbus-only device is a Modbus Device."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.engines.classification import classify
from app.rules.book import RuleBook

BOOK = RuleBook.load(Settings().rules_dir)


@pytest.mark.parametrize("doc, expected", [
    ({"ot": {"protocols": ["enip", "modbus"], "device_type": "Programmable Logic Controller"},
      "hardware": {"vendor": "Rockwell Automation/Allen-Bradley"}, "firmware": {"version": "33.011"}}, "PLC"),
    ({"ot": {"protocols": ["modbus", "s7"]}, "plc": {"product_code": "6ES7 214-1AG40-0XB0"},
      "firmware": {"version": "V4.5.2"}, "hardware": {"vendor": "Siemens", "model": "S7-1200"}}, "PLC"),
    ({"ot": {"protocols": ["modbus"]}, "hardware": {"vendor": "Schneider Electric"}}, "Modbus Device"),
    ({"ot": {"protocols": ["bacnet"]}, "firmware": {"version": "3.1"}}, "BACnet Controller"),
    ({"http": {"title": "Login"}}, None),
], ids=["enip+modbus PLC", "S7+modbus PLC", "modbus meter", "bacnet", "web only"])
def test_ot_classification(doc, expected):
    c = classify(doc, BOOK)
    assert (c.type if c else None) == expected


# Arcon test, 2026-11-12: a Windows server whose WinRM did not answer, with IIS and an OPC UA discovery service.
ARCON_SERVER = {"ot": {"protocols": ["opcua"]}, "network": {"open_ports": [80, 135, 139, 445, 3389, 4840]},
                "http": {"title": "IIS Windows Server"}}


def test_windows_server_with_opcua_discovery_is_not_a_modbus_device():
    c = classify(ARCON_SERVER, BOOK)
    assert c.type == "Windows Host"
    from app.engines.classification import eligibility
    result, reason = eligibility({**ARCON_SERVER, "classification": {"type": c.type}}, BOOK)
    assert result == "NOT_ELIGIBLE" and "WinRM" in reason


def test_once_winrm_reports_the_os_the_real_windows_type_wins():
    doc = {**ARCON_SERVER, "os": {"name": "Microsoft Windows Server 2019 Datacenter", "family": "windows"},
           "software": {"installed": [{"name": "Microsoft Edge"}]}}
    assert classify(doc, BOOK).type == "Windows Server"
    doc["os"]["name"] = "Microsoft Windows 11 Pro"
    assert classify(doc, BOOK).type == "Windows Workstation"
