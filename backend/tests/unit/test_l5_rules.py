"""Phase L5 rules: `not matches`, generic Windows classification, the Go-agent-only Windows rules and the Linux
baseline, each evaluated on evidence shaped exactly like the Go agent's (agent-go/internal/collectors)."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.engines.assessment.engine import evaluate_policy, policy_applies, score
from app.engines.classification import classify
from app.rules.book import RuleBook
from app.rules.conditions import evaluate, parse

BOOK = RuleBook.load(Settings().rules_dir)


def test_not_matches():
    assert evaluate("not matches 'TIA'", ["Firefox", "7-Zip"]) is True
    assert evaluate("not matches 'TIA'", ["TIA Portal V18", "7-Zip"]) is False
    assert evaluate("not matches '^Win'", "Linux") is True
    assert parse("not matches 'x' and matches 'y'")   # combines with and/or like every clause


@pytest.mark.parametrize("doc, expected", [
    ({"os": {"name": "Microsoft Windows 10 Home"}, "services": {"winrm": {"available": True}},
      "software": {"installed": [{"name": "Mozilla Firefox"}, {"name": "7-Zip"}]}}, "Windows Workstation"),
    ({"os": {"name": "Microsoft Windows 11 Enterprise"}, "services": {"winrm": {"available": True}},
      "software": {"installed": [{"name": "Siemens TIA Portal V18"}]}}, "Windows Engineering Workstation"),
    ({"os": {"name": "Microsoft Windows Server 2022 Standard"},
      "software": {"installed": [{"name": "Microsoft Edge"}]}}, "Windows Server"),
    ({"os": {"name": "Microsoft Windows Server 2019 Standard"},
      "software": {"installed": [{"name": "WinCC Runtime Advanced"}]}}, "SCADA Server"),
], ids=["real laptop", "engineering ws", "plain server", "scada server"])
def test_windows_classification(doc, expected):
    assert classify(doc, BOOK).type == expected


def go_windows_evidence(**over) -> dict:
    ev = {"schemaVersion": "1.1", "platform": {"os": "windows", "arch": "amd64", "variant": "modern"},
          "os": {"family": "windows", "product": "Windows 11 Enterprise"},
          "firewall": {"state": "enabled"}, "antivirus": {"state": "running"},
          "patches": {"installed": ["KB5066791"], "last_installed_days": 21},
          "software": {"installed": [{"name": "7-Zip"}]}, "rdp": {"enabled": True, "nla_required": True},
          "smb": {"v1_enabled": False}, "agent": {"health": "healthy"}}
    ev.update(over)
    return ev


def results(policy: str, evidence: dict) -> dict[str, str]:
    return {o.rule_id: o.status for o in evaluate_policy(BOOK.policies[policy], evidence, "DEEP_AGENT")}


def test_new_windows_rules_on_go_agent_evidence():
    ok = results("windows-engineering-baseline", go_windows_evidence())
    assert ok["WIN-PATCH-002"] == ok["WIN-RDP-001"] == ok["WIN-SMB-001"] == "PASS"
    bad = results("windows-engineering-baseline", go_windows_evidence(
        patches={"last_installed_days": 200}, rdp={"enabled": True, "nla_required": False},
        smb={"v1_enabled": True}))
    assert bad["WIN-PATCH-002"] == bad["WIN-RDP-001"] == bad["WIN-SMB-001"] == "FAIL"
    no_rdp = results("windows-engineering-baseline", go_windows_evidence(rdp={"enabled": False,
                                                                               "nla_required": False}))
    assert "WIN-RDP-001" not in no_rdp            # RDP off: the NLA rule does not apply at all


def test_new_windows_rules_do_not_apply_to_evidence_without_a_platform():
    """Agentless and simulated evidence has no `platform`: the rules are skipped, not counted as UNKNOWN."""
    old = go_windows_evidence()
    del old["platform"]
    r = results("windows-engineering-baseline", old)
    assert not {"WIN-PATCH-002", "WIN-RDP-001", "WIN-SMB-001"} & set(r)


def go_linux_evidence(**over) -> dict:
    ev = {"schemaVersion": "1.1", "platform": {"os": "linux", "arch": "arm64", "variant": "modern"},
          "os": {"family": "linux", "name": "Debian GNU/Linux 12 (bookworm)"},
          "firewall": {"state": "enabled", "backend": "nftables"},
          "patches": {"pending_security": 0, "last_update_days": 12},
          "ssh": {"permitrootlogin": "no", "passwordauthentication": "no"}, "admins": {"uid0": ["root"]},
          "password_policy": {"min_length": 14, "lockout_threshold": 5}, "audit": {"auditd": "running"},
          "usb": {"storage_policy": "blocked"}, "agent": {"health": "healthy"}}
    ev.update(over)
    return ev


def test_linux_baseline_hardened_host_passes():
    policy = BOOK.policies["linux-host-baseline"]
    ev = go_linux_evidence()
    assert policy_applies(policy, ev)
    outcomes = evaluate_policy(policy, ev, "DEEP_AGENT")
    assert {o.status for o in outcomes} == {"PASS"} and len(outcomes) == 12
    assert score(outcomes)[0] == 100.0


def test_linux_baseline_weak_host():
    r = results("linux-host-baseline", go_linux_evidence(
        os={"family": "linux", "name": "Ubuntu 20.04.6 LTS"}, firewall={"state": "disabled"},
        patches={"pending_security": 7, "last_update_days": 400},
        ssh={"permitrootlogin": "yes", "passwordauthentication": "yes"}, admins={"uid0": ["root", "toor"]},
        password_policy={"min_length": 8}, audit={"auditd": "stopped"}, usb={"storage_policy": "allowed"}))
    failing = {k for k, v in r.items() if v == "FAIL"}
    assert failing == {"LNX-FW-001", "LNX-PATCH-001", "LNX-PATCH-002", "LNX-OS-001", "LNX-SSH-001", "LNX-SSH-002",
                       "LNX-ADM-001", "LNX-PWD-001", "LNX-AUD-001", "LNX-USB-001"}
    assert r["LNX-PWD-002"] == "UNKNOWN"          # lockout not reported: never a FAIL


def test_linux_baseline_does_not_apply_to_windows():
    assert not policy_applies(BOOK.policies["linux-host-baseline"], go_windows_evidence())
    assert not policy_applies(BOOK.policies["windows-engineering-baseline"], go_linux_evidence())
