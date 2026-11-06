"""Local collectors. A real agent would query the registry, WMI, netsh, secedit, auditpol, Get-LocalGroupMember...
Here they read the host's simulated OS state. Collectors COLLECT; they never judge (evaluation is server-side)."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

STARTED = time.monotonic()
AGENT_VERSION = "1.1.0"


def _os(st: dict) -> dict:
    o = st["os"]
    return {k: o[k] for k in ("family", "name", "product", "version", "build") if k in o}


def _firewall(st: dict) -> dict:
    fw = st["firewall"]
    return {"state": fw["state"], "profiles": fw.get("profiles", {}), "default_inbound": fw.get("default_inbound"),
            "rule_count": fw.get("rule_count")}


def _patches(st: dict) -> dict:
    p = st["patches"]
    return {"installed": list(p["installed"]), "missing": list(p["missing"]), "missing_count": len(p["missing"])}


def _admins(st: dict) -> dict:
    members = st["local_admins"]
    return {"members": members, "enabled_count": sum(1 for m in members if m.get("enabled"))}


def _usb(st: dict) -> dict:
    if "usb" not in st:
        raise LookupError(r"registry key HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR unreadable")
    return {"storage_policy": st["usb"]["storage_policy"]}


def _network(st: dict) -> dict:
    n = st["network"]
    return {"interfaces": n.get("interfaces", []), "listening": n.get("listening", []),
            "connections": n.get("connections", [])}


COLLECTORS: dict[str, tuple[str, Callable[[dict], Any]]] = {
    "os": ("os", _os),
    "hardware": ("hardware", lambda st: dict(st["hardware"])),
    "firewall": ("firewall", _firewall),
    "antivirus": ("antivirus", lambda st: dict(st["antivirus"])),
    "patches": ("patches", _patches),
    "software": ("software", lambda st: {"installed": [dict(a) for a in st["software"]]}),
    "services": ("services", lambda st: {"running": [s for s in st["services"] if s["state"] == "running"]}),
    "local_admins": ("local_admins", _admins),
    "password_policy": ("password_policy", lambda st: dict(st["password_policy"])),
    "audit": ("audit", lambda st: dict(st["audit"])),
    "usb": ("usb", _usb),
    "network": ("network", _network),
}


def collect(state: dict, wanted: list[str]) -> dict[str, Any]:
    evidence: dict[str, Any] = {"schemaVersion": "1.0", "collectedAt": datetime.now(timezone.utc).isoformat(),
                                "identity": {"hostname": state["identity"]["hostname"],
                                             "domain": state["identity"].get("domain")}}
    status: dict[str, str] = {}
    for name in wanted:
        if name == "agent":
            continue
        if name not in COLLECTORS:
            status[name] = "error: unknown collector"
            continue
        key, fn = COLLECTORS[name]
        try:
            evidence[key] = fn(state)
            status[name] = "ok"
        except (KeyError, LookupError) as exc:
            status[name] = f"error: {exc.args[0] if exc.args else exc}"
    if "agent" in wanted:
        evidence["agent"] = {"health": "healthy", "version": AGENT_VERSION,
                             "uptime_sec": int(time.monotonic() - STARTED)}
        status["agent"] = "ok"
    evidence["collectors"] = status
    return evidence
