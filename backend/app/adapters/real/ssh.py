"""Read-only SSH probing of Linux / Unix hosts. Parsing is kept in small pure functions (unit-tested on recorded
outputs from Debian, RHEL and Alpine)."""

from __future__ import annotations

import re
import shlex
import time
from typing import Any, AsyncIterator

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Query,
    ResultStatus,
    SshAdapter,
    StageCallback,
    Target,
)
from app.adapters.real.common import RealAdapterMixin
from app.adapters.real.net import ssh, tcp
from app.adapters.real.net.gate import GateBlocked

GROUP_COMMANDS = {"identity": ["hostname", "os_release", "uname", "uptime"], "packages": ["packages"],
                  "services": ["services"], "network": ["listening"], "firewall": ["firewall"]}
STATUS = {"OK": ResultStatus.OK, "AUTH_FAILED": ResultStatus.AUTH_FAILED, "HOST_KEY_CHANGED": ResultStatus.TLS_INVALID,
          "REFUSED": ResultStatus.REFUSED, "TIMEOUT": ResultStatus.TIMEOUT, "ERROR": ResultStatus.ERROR}
MAX_PACKAGES = 5000


def parse_os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            try:
                out[k.strip()] = " ".join(shlex.split(v)) if v.strip() else ""
            except ValueError:
                out[k.strip()] = v.strip().strip('"')
    return out


def parse_packages(text: str) -> list[dict[str, str]]:
    pkgs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("WARNING"):
            continue
        if "\t" in line:
            name, version = line.split("\t", 1)
        else:   # apk: name-1.2.3-r0
            m = re.match(r"^(.+?)-(\d[^-]*-r\d+)$", line)
            name, version = (m.group(1), m.group(2)) if m else (line, "")
        pkgs.append({"name": name, "version": version})
    return pkgs[:MAX_PACKAGES]


def parse_sw_vers(text: str) -> dict[str, str]:
    """macOS `sw_vers`: ProductName / ProductVersion / BuildVersion, tab separated."""
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_uptime(text: str, now: float) -> int | None:
    """Linux /proc/uptime ("86400.55 172000.10") or macOS kern.boottime ("{ sec = 1792770275, usec = ... } ...")."""
    m = re.search(r"sec = (\d+)", text)
    if m:
        return max(0, int(now - int(m.group(1))))
    try:
        return int(float(text.split()[0]))
    except (ValueError, IndexError):
        return None


def parse_services(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        cols = line.split()
        if line.startswith("[ + ]"):                       # SysV: service --status-all
            out.append(line[5:].strip())
        elif cols and cols[0].endswith(".service"):          # systemd
            out.append(cols[0].removesuffix(".service"))
        elif len(cols) == 3 and cols[0].isdigit():           # macOS launchctl list: PID Status Label (PID = running)
            out.append(cols[2])
    return sorted(set(out))


def parse_listening(text: str) -> list[int]:
    """`ss -Hltn` ("LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*"), Linux `netstat -ltn` ("tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN")
    and macOS `netstat -anp tcp` ("tcp4 0 0 *.22 *.* LISTEN", port after the last dot): the local address is the 4th
    column in all three."""
    ports = set()
    for line in text.splitlines():
        cols = line.split()
        if "LISTEN" in cols and len(cols) >= 4:
            port = re.split(r"[:.]", cols[3])[-1]
            if port.isdigit():
                ports.add(int(port))
    return sorted(ports)


def parse_firewall(text: str) -> dict[str, Any]:
    if "Firewall is enabled" in text:                      # macOS application firewall: authoritative either way
        return {"firewall.state": "enabled"}
    if "Firewall is disabled" in text:
        return {"firewall.state": "disabled"}
    active = [line.split()[0] for line in text.splitlines() if line.strip().endswith(" active")]
    # Without root the rule set is not readable: an active firewall service is reported, an inactive one is not
    # claimed as "disabled" (that would be a guess), so the rule stays UNKNOWN.
    return {"firewall.state": "enabled"} if active else {}


class RealSshAdapter(RealAdapterMixin, SshAdapter):
    implementation, label = "asyncssh", "SSH"

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def health_check(self, target: Target) -> AdapterResult:
        """Reads only the server greeting (e.g. 'SSH-2.0-OpenSSH_9.6p1'); sends nothing and never authenticates."""
        port = target.port or 22
        try:
            state, banner = await tcp.read_banner(self.gate, target.address, port, min(target.timeout_sec, 3.0))
        except GateBlocked as exc:
            return self.blocked(target.address, exc)
        if state.state == "CLOSED":
            return self.result(target.address, ResultStatus.REFUSED, {"services.ssh.available": False},
                               error_code="REFUSED", error_detail=f"Connection refused on {target.address}:{port}")
        if state.state != "OPEN":
            return self.result(target.address, ResultStatus.UNREACHABLE, error_code="TIMEOUT",
                               error_detail=f"No answer on {target.address}:{port}")
        data = {"services.ssh.available": bool(banner and banner.startswith("SSH-"))}
        if banner:
            data["services.ssh.banner"] = banner
        return self.result(target.address, ResultStatus.OK, data, raw={"banner": banner})

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        ip, cred, port = target.address, target.credential, target.port or 22
        if cred is None:
            return self.result(ip, ResultStatus.AUTH_FAILED, error_code="NO_CREDENTIAL",
                               error_detail="No SSH credential profile configured")
        names = [c for g in (query.items or GROUP_COMMANDS) for c in GROUP_COMMANDS.get(g, [])]
        try:
            reply = await ssh.run(self.gate, ip, port, cred, names, min(target.timeout_sec, 10.0),
                                  target.options.get("host_key"))
        except GateBlocked as exc:
            return self.blocked(ip, exc)
        if reply.status != "OK":
            data = {"services.ssh.available": True} if reply.status in ("AUTH_FAILED", "HOST_KEY_CHANGED") else {}
            return self.result(ip, STATUS[reply.status], data, error_code=reply.status, error_detail=reply.error)
        out = {n: text for n, (code, text) in reply.outputs.items() if code == 0 or (n == "firewall" and text)}
        data: dict[str, Any] = {"services.ssh.available": True, "ssh.host_key": reply.host_key}
        if "hostname" in out:
            data["identity.hostname"] = out["hostname"].strip()
        if "os_release" in out and "ProductName:" in out["os_release"]:
            mac = parse_sw_vers(out["os_release"])
            data.update({"os.family": "macos", "os.name": f"{mac.get('ProductName')} {mac.get('ProductVersion')}",
                         "os.product": mac.get("ProductName"), "os.version": mac.get("ProductVersion"),
                         "os.build": mac.get("BuildVersion")})
        elif "os_release" in out:
            rel = parse_os_release(out["os_release"])
            data.update({"os.family": "linux", "os.name": rel.get("PRETTY_NAME"), "os.product": rel.get("NAME"),
                         "os.version": rel.get("VERSION_ID")})
        if "uname" in out:
            parts = out["uname"].split()
            if parts and parts[0] not in ("Linux", "Darwin") and "os.family" not in data:
                data["os.family"] = parts[0].lower()
            data["os.kernel"] = parts[1] if len(parts) > 1 else None
        if "uptime" in out:
            data["hardware.uptime_sec"] = parse_uptime(out["uptime"], time.time())
        if "packages" in out:
            data["software.installed"] = parse_packages(out["packages"])
        if "services" in out:
            data["services.running"] = parse_services(out["services"])
        if "listening" in out:
            data["network.listening"] = parse_listening(out["listening"])
        if "firewall" in out:
            data.update(parse_firewall(out["firewall"]))
        failed = [n for n in names if n not in out]
        status = ResultStatus.PARTIAL if failed else ResultStatus.OK
        return self.result(ip, status, {k: v for k, v in data.items() if v not in (None, "")},
                           raw={"commands": names, "failed": failed}, error_code="PARTIAL" if failed else None,
                           error_detail=f"Commands without output: {', '.join(failed)}" if failed else None)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["identity"]))
