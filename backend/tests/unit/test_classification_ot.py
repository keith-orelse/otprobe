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
