"""Rule engine: evaluation order, scoring formula (docs/RULES.md §5 worked example), drift and diff helpers."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

from app.engines.assessment.engine import evaluate_policy, evidence_diff, is_drift, score
from app.rules.book import RuleBook
from tests.sim.seed_data import DEVICES

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sim" / "agent"))
from otprobe_agent.collectors import collect  # noqa: E402

ALL = ["os", "hardware", "firewall", "antivirus", "patches", "software", "services", "local_admins",
       "password_policy", "audit", "usb", "network", "agent"]


@pytest.fixture(scope="module")
def baseline() -> dict:
    from app.core.config import Settings
    return RuleBook.load(Settings().rules_dir).policies["windows-engineering-baseline"]


def seed_state(device_id: str) -> dict:
    return copy.deepcopy(next(d for d in DEVICES if d["device_id"] == device_id)["state"])


def test_worked_example_eng_ws_01(baseline):
    evidence = collect(seed_state("dev-ews01"), ALL)
    outcomes = evaluate_policy(baseline, evidence, "DEEP_AGENT")
    status = {o.rule_id: o.status for o in outcomes}
    assert status == {
        "WIN-FW-001": "PASS", "WIN-AV-001": "PASS", "WIN-PATCH-001": "FAIL", "WIN-SW-001": "WARNING",
        "WIN-OS-001": "PASS", "WIN-PWD-001": "PASS", "WIN-PWD-002": "PASS", "WIN-ADM-001": "FAIL",
        "WIN-USB-001": "UNKNOWN", "WIN-AUD-001": "PASS", "AGT-HEALTH-001": "PASS"}
    s, counts = score(outcomes)
    assert s == 75.0 and counts == {"pass": 7, "fail": 2, "warning": 1, "unknown": 1}
    usb = next(o for o in outcomes if o.rule_id == "WIN-USB-001")
    assert usb.message == "evidence 'usb.storage_policy' not present"
    assert evidence["collectors"]["usb"].startswith("error: registry key")


def test_agentless_source_only_evaluates_agentless_rules(baseline):
    evidence = collect(seed_state("dev-ews02"), ALL)
    ids = {o.rule_id for o in evaluate_policy(baseline, evidence, "AGENTLESS")}
    assert ids == {"WIN-FW-001", "WIN-AV-001", "WIN-OS-001"}   # WIN-SW-001 is DEEP_AGENT only (note N3)
    os_rule = next(o for o in evaluate_policy(baseline, evidence, "AGENTLESS") if o.rule_id == "WIN-OS-001")
    assert os_rule.status == "FAIL" and os_rule.severity == "HIGH"


def test_missing_first_then_type_check(baseline):
    evidence = collect(seed_state("dev-ews01"), ALL)
    evidence["patches"]["missing_count"] = "two"          # wrong type
    del evidence["firewall"]                              # missing
    out = {o.rule_id: o for o in evaluate_policy(baseline, evidence, "DEEP_AGENT")}
    assert out["WIN-FW-001"].status == "UNKNOWN" and not out["WIN-FW-001"].rule_error
    assert out["WIN-PATCH-001"].status == "UNKNOWN" and out["WIN-PATCH-001"].rule_error
    assert out["WIN-PATCH-001"].message.startswith("type mismatch")


def test_unknown_is_excluded_from_score():
    from app.engines.assessment.engine import RuleOutcome
    mk = lambda st, sev: RuleOutcome("R", "t", st, sev, sev, "p", None, "", None, [], None)  # noqa: E731
    assert score([mk("PASS", "HIGH"), mk("UNKNOWN", "CRITICAL")])[0] == 100.0
    assert score([mk("UNKNOWN", "HIGH")])[0] is None
    assert score([mk("PASS", "CRITICAL"), mk("FAIL", "LOW"), mk("WARNING", "MEDIUM")])[0] == round(
        100 * (10 + 0 + 1.5) / 14, 1)


def test_policy_not_applicable_to_linux(baseline):
    from app.engines.assessment.engine import policy_applies
    assert policy_applies(baseline, {"os": {"family": "windows"}})
    assert not policy_applies(baseline, {"os": {"family": "linux"}})
    assert not policy_applies(baseline, {})


def test_drift_and_diff_helpers():
    assert is_drift("PASS", "FAIL") and is_drift("PASS", "WARNING")
    assert not is_drift("FAIL", "FAIL") and not is_drift(None, "FAIL") and not is_drift("PASS", "UNKNOWN")
    before = {"collectedAt": "a", "firewall": {"state": "enabled"}, "patches": {"missing": ["KB1"]}}
    after = {"collectedAt": "b", "firewall": {"state": "disabled"}, "patches": {"missing": ["KB1"]}}
    assert evidence_diff(before, after) == [("firewall.state", "enabled", "disabled")]
