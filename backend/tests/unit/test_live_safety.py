"""Structural live-network safety (docs/SAFETY_AND_SCOPE.md §6, contract C-16L)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[2] / "app"
NET_DIR = APP_DIR / "adapters" / "real" / "net"
NETWORK_MODULES = {"socket", "subprocess", "scapy", "pysnmp", "winrm", "pypsrp", "paramiko", "asyncssh", "icmplib",
                   "requests", "httpx", "urllib", "aiohttp", "paho", "aiomqtt", "ssl", "pymodbus", "asyncua",
                   "bacpypes3"}
NETWORK_CALLS = {"open_connection", "create_connection", "create_datagram_endpoint", "create_subprocess_exec",
                 "create_subprocess_shell", "start_server", "open_unix_connection"}


def _violations(path: Path) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(path.read_text())):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        out += [f"import {n}" for n in names if n.split(".")[0] in NETWORK_MODULES]
        if isinstance(node, ast.Attribute) and node.attr in NETWORK_CALLS:
            out.append(f"call {node.attr}")
    return out


def test_only_the_net_package_can_touch_the_network():
    bad = {str(p.relative_to(APP_DIR)): v for p in APP_DIR.rglob("*.py")
           if NET_DIR not in p.parents and (v := _violations(p))}
    assert not bad, f"network access outside app/adapters/real/net: {bad}"


@pytest.mark.parametrize("path", sorted(NET_DIR.glob("*.py")), ids=lambda p: p.name)
def test_every_sender_in_net_goes_through_the_gate(path: Path):
    """Each module that imports a network library must call gate.permit at least once per sending function."""
    tree = ast.parse(path.read_text())
    if path.name in ("__init__.py", "gate.py", "neighbors.py"):   # neighbors only reads the local kernel table
        return
    senders = [f for f in ast.walk(tree) if isinstance(f, ast.AsyncFunctionDef) and not f.name.startswith("_")]
    assert senders, f"{path.name} has no public senders"
    for f in senders:
        permits = [n for n in ast.walk(f) if isinstance(n, ast.Attribute) and n.attr == "permit"]
        assert permits, f"{path.name}:{f.name} sends without gate.permit"


def test_snmp_module_cannot_build_a_set_request():
    tree = ast.parse((NET_DIR / "snmp.py").read_text())
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not names & {"set_cmd", "SetRequestPDU", "setCmd"}


def test_live_mode_never_imports_the_simulator(tmp_path):
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "from app.core.config import Settings\n"
        "from app.main import build_context\n"
        "ctx = build_context(Settings.from_env(database_url='sqlite:///%s', adapter_mode='real'))\n"
        "sim = ('app.sim', 'app.adapters.simulated', 'app.api.sim')\n"
        "loaded = sorted(m for m in sys.modules if m.startswith(sim))\n"
        "assert not loaded, loaded\n"
        "assert ctx.gate is not None and not ctx.gate.configured\n"
        "print('ok', ctx.registry.get(__import__('app.adapters.base', fromlist=['x']).Protocol.ICMP)"
        ".descriptor().implementation)\n"
    ) % (str(APP_DIR.parent), tmp_path / "live.db")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok icmplib"
