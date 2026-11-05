"""Real WinRM and WMI/CIM (over WinRM) adapters. Read-only in phase L3: remote operations that change a host (agent
install, service start/stop, file removal) answer NOT_SUPPORTED until phase L4. The JSON-to-fields mapping lives
in small pure functions, unit-tested on recorded output from Windows 11, Server 2022 and a host without Defender."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator, Mapping

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    RemoteOperation,
    RemoteSession,
    ResultStatus,
    Stage,
    StageCallback,
    Target,
    WinRmAdapter,
    WmiAdapter,
)
from app.adapters.real.common import RealAdapterMixin
from app.adapters.real.net import tcp, winrm
from app.adapters.real.net.gate import GateBlocked
from app.core.clock import utcnow
from app.core.ids import new_id

STATUS = {"OK": ResultStatus.OK, "REFUSED": ResultStatus.REFUSED, "TIMEOUT": ResultStatus.TIMEOUT,
          "TLS_INVALID": ResultStatus.TLS_INVALID, "AUTH_FAILED": ResultStatus.AUTH_FAILED,
          "DISABLED": ResultStatus.DISABLED, "ERROR": ResultStatus.ERROR}
WMI_GROUPS = ("os", "hardware", "firewall", "antivirus", "software", "services", "hotfixes", "network")
READ_ONLY_OPS = {RemoteOperation.QUERY_HOSTNAME: "q_hostname", RemoteOperation.QUERY_DISK_FREE: "q_disk_free",
                 RemoteOperation.QUERY_REBOOT_PENDING: "q_reboot_pending",
                 RemoteOperation.QUERY_AGENT_INSTALLED: "q_agent_installed", RemoteOperation.QUERY_SERVICE: "q_service",
                 RemoteOperation.QUERY_SERVER_CONNECTIVITY: "q_server_connectivity"}


def _list(v) -> list:
    """ConvertTo-Json renders a one-element array as a bare object; normalise."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def map_os(o: dict) -> dict[str, Any]:
    caption = (o.get("caption") or "").strip()
    product = caption.removeprefix("Microsoft ").strip()
    build = f"{o.get('build')}.{o['ubr']}" if o.get("ubr") is not None else o.get("build")
    data = {"os.family": "windows", "os.name": caption, "os.product": product,
            "os.version": o.get("displayVersion") or o.get("releaseId") or o.get("version"), "os.build": build,
            "identity.hostname": o.get("hostname"),
            "identity.domain": o.get("domain") if o.get("partOfDomain") else None}
    if o.get("lastBoot"):
        boot = datetime.fromisoformat(o["lastBoot"].replace("Z", "+00:00"))
        data["hardware.uptime_sec"] = int((datetime.now(timezone.utc) - boot).total_seconds())
    return data


def map_hardware(h: dict) -> dict[str, Any]:
    return {"hardware.manufacturer": h.get("manufacturer"), "hardware.model": h.get("model"),
            "hardware.cpu": (h.get("cpu") or "").strip() or None, "hardware.ram_gb": h.get("ram_gb"),
            "hardware.disk": _list(h.get("disk"))}


def map_firewall(profiles) -> dict[str, Any]:
    profiles = _list(profiles)
    if not profiles:
        return {}
    enabled = {p["name"].lower(): ("on" if p.get("enabled") else "off") for p in profiles}
    state = "enabled" if all(v == "on" for v in enabled.values()) else \
        "disabled" if all(v == "off" for v in enabled.values()) else "partial"
    inbound = {str(p.get("inbound")) for p in profiles}
    data = {"firewall.state": state, "firewall.profiles": enabled}
    if len(inbound) == 1:
        data["firewall.default_inbound"] = inbound.pop().lower().replace("notconfigured", "block")
    return data


def map_antivirus(a: dict) -> dict[str, Any]:
    d = a.get("defender")
    if d:
        return {"antivirus.product": "Microsoft Defender Antivirus",
                "antivirus.state": "running" if d.get("service") else "stopped",
                "antivirus.realtime": bool(d.get("realtime")), "antivirus.signature_age_days": d.get("signatureAge")}
    for p in _list(a.get("securityCenter")):
        # productState: bits 12-15 = scanner state (0x1 on), see Windows Security Center documentation
        on = (int(p.get("state") or 0) >> 12) & 0xF == 0x1
        return {"antivirus.product": p.get("name"), "antivirus.state": "running" if on else "stopped"}
    return {}     # servers without Defender and no Security Center: unknown, not "stopped"


def map_software(items) -> dict[str, Any]:
    seen, out = set(), []
    for s in _list(items):
        key = (s.get("name"), s.get("version"))
        if s.get("name") and key not in seen:
            seen.add(key)
            out.append({"name": s["name"], "version": s.get("version") or ""})
    return {"software.installed": sorted(out, key=lambda x: x["name"].lower())}


def map_network(n: dict) -> dict[str, Any]:
    # 169.254.x.x = link-local: an adapter with no network (unplugged Ethernet, Bluetooth PAN). Not an interface the
    # host is really on, so it must not make a laptop look dual-homed.
    return {"network.interfaces": [{**i, "mac": (i.get("mac") or "").replace("-", ":") or None}
                                   for i in _list(n.get("interfaces"))
                                   if not str(i.get("ip", "")).startswith("169.254.")],
            "network.listening": sorted(int(p) for p in _list(n.get("listening"))),
            "network.connections": [{**c, "protocol": "tcp"} for c in _list(n.get("connections"))]}


MAPPERS = {"os": map_os, "hardware": map_hardware, "firewall": map_firewall, "antivirus": map_antivirus,
           "software": map_software, "services": lambda v: {"services.running": sorted(_list(v))},
           "hotfixes": lambda v: {"patches.installed": sorted({h["id"] for h in _list(v) if h.get("id")})},
           "network": map_network}


def _port(target: Target) -> int:
    params = target.credential.params if target.credential else {}
    return int(target.port or params.get("port") or 5986)


class RealWinRmAdapter(RealAdapterMixin, WinRmAdapter):
    implementation, label = "pypsrp", "WinRM"

    def __init__(self, gate) -> None:
        super().__init__(gate)
        self._sessions: dict[str, Target] = {}

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def health_check(self, target: Target) -> AdapterResult:
        """TCP connect only: is a WinRM listener there? No credentials are used."""
        port = _port(target)
        try:
            state = await tcp.connect(self.gate, target.address, port, min(target.timeout_sec, 3.0))
        except GateBlocked as exc:
            return self.blocked(target.address, exc)
        if state.state == "OPEN":
            return self.result(target.address, ResultStatus.OK, {"services.winrm.available": True,
                                                                 "services.winrm.port": port})
        status = ResultStatus.REFUSED if state.state == "CLOSED" else ResultStatus.TIMEOUT
        return self.result(target.address, status, {"services.winrm.available": False}, error_code=status.value,
                           error_detail=f"TCP {port} {'closed' if state.state == 'CLOSED' else 'not answering'}")

    async def open_session(self, target: Target, on_stage: StageCallback | None = None
                           ) -> tuple[AdapterResult, RemoteSession | None]:
        ip, port, stages = target.address, _port(target), []

        async def emit(name: str, status: str, detail: str) -> None:
            st = Stage(name, STATUS[status], detail, utcnow())
            stages.append(st)
            if on_stage is not None:
                await on_stage(st)

        try:
            reply = await winrm.open_session(self.gate, ip, port, target.credential, min(target.timeout_sec, 5.0),
                                             emit)
        except GateBlocked as exc:
            return self.blocked(ip, exc), None
        tls = port != 5985 and not target.credential.params.get("http")
        data = {"services.winrm.available": reply.stage != "CONNECTING", "services.winrm.port": port}
        if tls and reply.stage != "CONNECTING":
            data["services.winrm.tls"] = "invalid" if reply.status == "TLS_INVALID" else \
                "unverified" if target.credential.params.get("skipCertCheck") else "valid"
        if reply.status != "OK":
            return self.result(ip, STATUS[reply.status], data, error_code=reply.status,
                               error_detail=reply.detail), None
        sid = new_id()
        self._sessions[sid] = target
        return self.result(ip, ResultStatus.OK, data, raw={"psVersion": reply.output}), RemoteSession(sid, ip, stages)

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        if not isinstance(op, RemoteOperation):
            raise ValueError(f"unsupported remote operation: {op!r}")
        target = self._sessions.get(session.session_id)
        if target is None:
            return self.result(session.target, ResultStatus.ERROR, error_code="NO_SESSION",
                               error_detail="WinRM session is closed")
        script = READ_ONLY_OPS.get(op)
        if script is None:
            return self.result(session.target, ResultStatus.NOT_SUPPORTED, error_code="NOT_AVAILABLE",
                               error_detail=f"{op.value} changes the host: live agent deployment arrives in phase L4")
        try:
            reply = await winrm.run(self.gate, target.address, _port(target), target.credential, script,
                                    min(target.timeout_sec, 5.0), dict(params))
        except GateBlocked as exc:
            return self.blocked(session.target, exc)
        except ValueError as exc:
            return self.result(session.target, ResultStatus.ERROR, error_code="INVALID_PARAMETER",
                               error_detail=str(exc))
        if reply.status != "OK":
            return self.result(session.target, STATUS[reply.status], error_code=reply.status, error_detail=reply.detail)
        out = reply.output.strip()
        if op == RemoteOperation.QUERY_HOSTNAME:
            return self.result(session.target, ResultStatus.OK, {"identity.hostname": out})
        if op == RemoteOperation.QUERY_DISK_FREE:
            return self.result(session.target, ResultStatus.OK, {"hardware.disk": _list(winrm.parse_json(out))})
        if op == RemoteOperation.QUERY_REBOOT_PENDING:
            return self.result(session.target, ResultStatus.OK, raw={"reboot_pending": out.lower() == "true"})
        if op == RemoteOperation.QUERY_AGENT_INSTALLED:
            return self.result(session.target, ResultStatus.OK, raw={"installed": out.lower() == "true"})
        if op == RemoteOperation.QUERY_SERVICE:
            return self.result(session.target, ResultStatus.OK, raw={"service": winrm.parse_json(out)})
        conn = winrm.parse_json(out) or {}
        if not conn.get("TcpTestSucceeded"):
            return self.result(session.target, ResultStatus.ERROR, raw=conn, error_code="TCP_FAILED",
                               error_detail=f"TcpTestSucceeded=False to {params.get('server')}:{params.get('port')}")
        return self.result(session.target, ResultStatus.OK, raw=conn)

    async def close_session(self, session: RemoteSession) -> None:
        self._sessions.pop(session.session_id, None)

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)


class RealWmiAdapter(RealAdapterMixin, WmiAdapter):
    """CIM queries over the WinRM transport. One script per group; a failing group makes the result PARTIAL."""

    implementation, label = "pypsrp-cim", "WMI/CIM"
    protocol = Protocol.WMI

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        ip, port = target.address, _port(target)
        data: dict[str, Any] = {}
        failed: dict[str, str] = {}
        for group in query.items or WMI_GROUPS:
            try:
                reply = await winrm.run(self.gate, ip, port, target.credential, group, min(target.timeout_sec, 10.0))
            except GateBlocked as exc:
                return self.blocked(ip, exc)
            if reply.status != "OK":
                if not data and reply.status in ("AUTH_FAILED", "REFUSED", "TIMEOUT", "TLS_INVALID"):
                    return self.result(ip, STATUS[reply.status], error_code=reply.status,
                                       error_detail=f"CIM session failed: {reply.detail}")
                failed[group] = reply.detail
                continue
            try:
                parsed = winrm.parse_json(reply.output)
                data.update(MAPPERS[group](parsed if parsed is not None else []))
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                failed[group] = f"unexpected output ({type(exc).__name__})"
        data = {k: v for k, v in data.items() if v not in (None, "")}
        if failed and not data:
            return self.result(ip, ResultStatus.ERROR, raw={"failed": failed}, error_code="ERROR",
                               error_detail="; ".join(f"{g}: {d}" for g, d in failed.items()))
        return self.result(ip, ResultStatus.PARTIAL if failed else ResultStatus.OK, data, raw={"failed": failed},
                           error_code="PARTIAL" if failed else None,
                           error_detail=f"Groups without data: {', '.join(failed)}" if failed else None)

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["os"]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["os", "hardware"]))
