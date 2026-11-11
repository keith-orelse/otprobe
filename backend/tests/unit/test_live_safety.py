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
PURE_SUBMODULES = {"urllib.parse"}   # string parsing only, no I/O
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
        out += [f"import {n}" for n in names if n.split(".")[0] in NETWORK_MODULES and n not in PURE_SUBMODULES]
        if isinstance(node, ast.Attribute) and node.attr in NETWORK_CALLS:
            out.append(f"call {node.attr}")
    return out


def test_only_the_net_package_can_touch_the_network():
    bad = {str(p.relative_to(APP_DIR)): v for p in APP_DIR.rglob("*.py")
           if NET_DIR not in p.parents and (v := _violations(p))}
    assert not bad, f"network access outside app/adapters/real/net: {bad}"


# Names that open a connection or send a packet. A sender either does that inside ``gate.permit`` itself, or only
# calls other senders in this package (which do).
QUALIFIED = {"asyncio.open_connection", "asyncssh.connect", "icmplib.async_ping", "socket.socket",
             "socket.create_connection"}
ANY_RECEIVER = {"create_datagram_endpoint", "execute_ps", "stream", "create_connection", "sendto"}
BARE = {"Exchange"}


def _primitive(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id if f.id in BARE else None
    if isinstance(f, ast.Attribute):
        qualified = f"{f.value.id}.{f.attr}" if isinstance(f.value, ast.Name) else f.attr
        if qualified in QUALIFIED or f.attr in ANY_RECEIVER:
            return qualified
    return None


def _inside_permit(tree: ast.AST) -> set[int]:
    """ids of nodes lexically inside an ``async with gate.permit(...)`` block."""
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncWith) and any(
                isinstance(i.context_expr, ast.Call) and isinstance(i.context_expr.func, ast.Attribute)
                and i.context_expr.func.attr == "permit" for i in node.items):
            inside |= {id(n) for n in ast.walk(node)}
    return inside


@pytest.mark.parametrize("path", sorted(NET_DIR.glob("*.py")), ids=lambda p: p.name)
def test_every_network_primitive_in_net_runs_inside_a_gate_permit(path: Path):
    if path.name in ("__init__.py", "gate.py", "_stream.py"):    # _stream.Exchange is checked where it is used
        return
    if path.name == "broker.py":            # loopback only, to OTProbe's own broker: see the next test
        return
    tree = ast.parse(path.read_text())
    inside = _inside_permit(tree)
    outside = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (name := _primitive(node)) and id(node) not in inside:
            outside.append(f"{name} (line {node.lineno})")
    assert not outside, f"{path.name}: network primitive outside gate.permit: {outside}"




def test_the_bundled_broker_only_binds_and_connects_to_loopback():
    """broker.py talks to OTProbe's own Mosquitto child process, never to a plant device (devices connect in), so it
    is outside the network gate. Every bind and connect in it must name 127.0.0.1."""
    tree = ast.parse((NET_DIR / "broker.py").read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr in ("bind", "connect", "connect_async", "create_connection", "open_connection")]
    assert len(calls) >= 3

    def host(call: ast.Call) -> object:
        arg = call.args[0]
        return arg.elts[0].value if isinstance(arg, ast.Tuple) else getattr(arg, "value", None)

    assert {host(c) for c in calls} == {"127.0.0.1"}, [ast.unparse(c) for c in calls]


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
        "sim = ('tests.sim', 'app.sim', 'app.adapters.simulated', 'app.api.sim')\n"
        "loaded = sorted(m for m in sys.modules if m.startswith(sim))\n"
        "assert not loaded, loaded\n"
        "assert ctx.gate is not None and not ctx.gate.configured\n"
        "print('ok', ctx.registry.get(__import__('app.adapters.base', fromlist=['x']).Protocol.ICMP)"
        ".descriptor().implementation)\n"
    ) % (str(APP_DIR.parent), tmp_path / "live.db")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok icmplib"
