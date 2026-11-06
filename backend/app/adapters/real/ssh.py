"""SSH: read-only probing of Linux / Unix hosts, and (phase L6) the session the deployment, removal and restart
engines use to install the Go agent on Linux. Parsing is kept in small pure functions (unit-tested on recorded
outputs from Debian, RHEL and Alpine)."""

from __future__ import annotations

import json
import re
import shlex
import time
from typing import Any, AsyncIterator, Mapping

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    RemoteOperation,
    RemoteSession,
    ResultStatus,
    SshAdapter,
    Stage,
    StageCallback,
    Target,
)
from app.adapters.real.common import RealAdapterMixin
from app.adapters.real.net import ssh, tcp
from app.adapters.real.net.gate import GateBlocked
from app.core.clock import utcnow
from app.core.ids import new_id

GROUP_COMMANDS = {"identity": ["hostname", "os_release", "uname", "uptime"], "packages": ["packages"],
                  "services": ["services"], "network": ["listening"], "firewall": ["firewall"]}
STATUS = {"OK": ResultStatus.OK, "AUTH_FAILED": ResultStatus.AUTH_FAILED, "HOST_KEY_CHANGED": ResultStatus.TLS_INVALID,
          "NO_HOST_KEY": ResultStatus.ERROR, "REFUSED": ResultStatus.REFUSED, "TIMEOUT": ResultStatus.TIMEOUT,
          "ERROR": ResultStatus.ERROR}
QUERIES = {RemoteOperation.QUERY_HOSTNAME: "q_hostname", RemoteOperation.QUERY_ARCH: "q_arch",
           RemoteOperation.QUERY_ROOT_ACCESS: "q_root", RemoteOperation.QUERY_DISK_FREE: "q_disk_free",
           RemoteOperation.QUERY_REBOOT_PENDING: "q_reboot_pending",
           RemoteOperation.QUERY_AGENT_INSTALLED: "q_agent_installed", RemoteOperation.QUERY_SERVICE: "q_service"}
SERVICE_NAMES = {ssh.SERVICE, "OTProbeAgent"}      # engines may use either name for the agent's service
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


def parse_df(text: str) -> list[dict[str, Any]]:
    """`df -Pk` (POSIX format): Filesystem 1024-blocks Used Available Capacity Mounted-on."""
    disks = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 6 and cols[1].isdigit() and cols[3].isdigit():
            disks.append({"drive": cols[5], "size_gb": round(int(cols[1]) / 1048576),
                          "free_gb": round(int(cols[3]) / 1048576, 1)})
    return disks


def parse_service(text: str) -> dict[str, str] | None:
    """`otprobe-agent <is-active> <is-enabled>` from q_service, or nothing when the service is not installed."""
    cols = text.split()
    if len(cols) < 3:
        return None
    return {"name": cols[0], "state": "running" if cols[1] == "active" else "stopped", "start_type": cols[2]}


class RealSshDeployMixin:
    """Agent deployment over SSH: one connection per session, closed operations only (net.ssh.deploy_command)."""

    async def open_session(self, target: Target, on_stage: StageCallback | None = None
                           ) -> tuple[AdapterResult, RemoteSession | None]:
        ip, port, cred = target.address, target.port or 22, target.credential
        try:
            reply, conn = await ssh.open_session(self.gate, ip, port, cred, min(target.timeout_sec, 10.0),
                                                 target.options.get("host_key") or "")
        except GateBlocked as exc:
            return self.blocked(ip, exc), None
        stage = Stage("SESSION_CREATED" if conn else reply.status, STATUS[reply.status],
                      f"Logged in as {cred.username}, host key matches the pinned key" if conn else reply.error or "",
                      utcnow())
        if on_stage is not None:
            await on_stage(stage)
        if conn is None:
            data = {"services.ssh.available": True} if reply.status in ("AUTH_FAILED", "HOST_KEY_CHANGED") else {}
            return self.result(ip, STATUS[reply.status], data, error_code=reply.status, error_detail=reply.error), None
        sid = new_id()
        self._sessions[sid] = conn
        return (self.result(ip, ResultStatus.OK, {"services.ssh.available": True}),
                RemoteSession(sid, ip, [stage], Protocol.SSH))

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        if not isinstance(op, RemoteOperation):
            raise ValueError(f"unsupported remote operation: {op!r}")
        conn = self._sessions.get(session.session_id)
        ip = session.target
        if conn is None:
            return self.result(ip, ResultStatus.ERROR, error_code="NO_SESSION", error_detail="SSH session is closed")
        try:
            return await self._op(conn, ip, op, params)
        except GateBlocked as exc:
            return self.blocked(ip, exc)
        except (ValueError, KeyError) as exc:
            return self.result(ip, ResultStatus.ERROR, error_code="INVALID_PARAMETER",
                               error_detail=f"invalid or missing parameter: {exc}")

    def _failed(self, ip: str, r: ssh.CommandReply, code: str) -> AdapterResult:
        if r.status == "NO_ROOT":
            code = "NO_ROOT"
        elif r.status == "TIMEOUT":
            code = "TIMEOUT"
        return self.result(ip, ResultStatus.TIMEOUT if r.status == "TIMEOUT" else ResultStatus.ERROR,
                           raw={"exit": r.exit_status}, error_code=code, error_detail=r.detail)

    async def _op(self, conn: ssh.SshSession, ip: str, op: RemoteOperation, params: Mapping[str, Any]
                  ) -> AdapterResult:
        if op in (RemoteOperation.START_SERVICE, RemoteOperation.STOP_SERVICE) and \
                params.get("name", ssh.SERVICE) not in SERVICE_NAMES:
            raise ValueError("only the OTProbe agent's service can be started or stopped")
        if op in QUERIES:
            r = await conn.run(QUERIES[op])
            out = r.stdout.strip()
            if r.status != "OK":
                return self._failed(ip, r, "QUERY_FAILED")
            if op == RemoteOperation.QUERY_HOSTNAME:
                return self.result(ip, ResultStatus.OK, {"identity.hostname": out})
            if op == RemoteOperation.QUERY_ARCH:
                return self.result(ip, ResultStatus.OK, {"hardware.arch": out},
                                   raw={"arch": out, "goarch": ssh.GOARCH.get(out)})
            if op == RemoteOperation.QUERY_ROOT_ACCESS:
                if out != "0":
                    return self.result(ip, ResultStatus.ERROR, error_code="NO_ROOT",
                                       error_detail=f"Commands run as uid {out}, not root")
                return self.result(ip, ResultStatus.OK, raw={"via": "login" if conn.cred.username == "root"
                                                             else "sudo"})
            if op == RemoteOperation.QUERY_DISK_FREE:
                return self.result(ip, ResultStatus.OK, {"hardware.disk": parse_df(r.stdout)})
            if op == RemoteOperation.QUERY_SERVICE:
                return self.result(ip, ResultStatus.OK, raw={"service": parse_service(out)})
            return self.result(ip, ResultStatus.OK, raw={
                "reboot_pending" if op == RemoteOperation.QUERY_REBOOT_PENDING else "installed": out == "true"})
        if op == RemoteOperation.QUERY_SERVER_CONNECTIVITY:
            r = await conn.run("q_server_connectivity", {"server": params["server"], "port": str(params["port"])})
            if r.status != "OK":
                return self.result(ip, ResultStatus.ERROR, error_code="TCP_FAILED",
                                   error_detail=f"Host cannot open {params['server']}:{params['port']} "
                                                "(tried curl, nc and bash)")
            return self.result(ip, ResultStatus.OK)
        if op == RemoteOperation.VERIFY_FILE_HASH:
            r = await conn.run("verify_hash", {"path": params["path"]})
            actual, expected = r.stdout.strip().lower(), str(params["sha256"]).lower()
            raw = {"expected": expected, "actual": actual, "algorithm": "SHA256"}
            if r.status != "OK" or actual != expected:
                return self.result(ip, ResultStatus.ERROR, raw=raw, error_code="HASH_MISMATCH",
                                   error_detail=f"Package hash mismatch: expected {expected[:4]}…{expected[-4:]}, "
                                                f"got {actual[:4] or '?'}…{actual[-4:]}")
            return self.result(ip, ResultStatus.OK, raw=raw)
        if op == RemoteOperation.INSTALL_AGENT:
            r = await conn.run("install", {
                "path": params["path"], "sha256": params["sha256"], "token": params["enrollment_token"],
                "server_url": params["server_url"], "ca_sha256": params.get("ca_sha256", ""),
                "deployment_id": params["deployment_id"], "profile": params["profile"]})
            if r.status != "OK":
                return self._failed(ip, r, "HASH_MISMATCH" if "HASH_MISMATCH" in r.stderr else "INSTALL_FAILED")
            try:
                raw = json.loads(r.stdout.strip().splitlines()[-1])
            except (ValueError, IndexError):
                raw = {"output": r.stdout.strip()}
            return self.result(ip, ResultStatus.OK, raw=raw)
        name = {RemoteOperation.START_SERVICE: "start_service", RemoteOperation.STOP_SERVICE: "stop_service",
                RemoteOperation.UNINSTALL_AGENT: "uninstall"}.get(op)
        if name:
            r = await conn.run(name)
            if r.status != "OK":
                return self._failed(ip, r, {"uninstall": "UNINSTALL_FAILED",
                                            "start_service": "SERVICE_START_FAILED"}.get(name, "ERROR"))
            return self.result(ip, ResultStatus.OK, raw={"output": r.stdout.strip()})
        if op == RemoteOperation.REMOVE_FILES:
            for path in params.get("paths", []):
                await (conn.run("remove_uploads") if path == ssh.UPLOAD_GLOB
                       else conn.run("remove_upload", {"path": path}))
            return self.result(ip, ResultStatus.OK)
        return self.result(ip, ResultStatus.NOT_SUPPORTED, error_code="NOT_AVAILABLE",
                           error_detail=f"{op.value} is not used on Linux")

    async def copy(self, session: RemoteSession, local: str) -> ssh.CommandReply:
        conn = self._sessions.get(session.session_id)
        if conn is None:
            return ssh.CommandReply("ERROR", stderr="SSH session is closed")
        try:
            return await conn.put(local)
        except GateBlocked as exc:
            return ssh.CommandReply("BLOCKED", stderr=str(exc))

    async def close_session(self, session: RemoteSession) -> None:
        conn = self._sessions.pop(session.session_id, None)
        if conn is not None:
            await conn.close()


class RealSshAdapter(RealSshDeployMixin, RealAdapterMixin, SshAdapter):
    implementation, label = "asyncssh", "SSH"

    def __init__(self, gate) -> None:
        super().__init__(gate)
        self._sessions: dict[str, ssh.SshSession] = {}

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
            data["hardware.arch"] = parts[2] if len(parts) > 2 else None
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
