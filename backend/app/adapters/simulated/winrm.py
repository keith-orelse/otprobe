from __future__ import annotations

from typing import Any, AsyncIterator, Mapping

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Query,
    RemoteOperation,
    RemoteSession,
    ResultStatus,
    Stage,
    StageCallback,
    Target,
    WinRmAdapter,
)
from app.adapters.simulated.common import SimAdapterMixin, winrm_gate
from app.core.clock import utcnow
from app.core.ids import new_id

STAGES = ("CONNECTING", "TCP_OK", "TLS_VALIDATED", "AUTH_OK", "SESSION_CREATED")
_QUERY_OPS = {RemoteOperation.QUERY_DISK_FREE, RemoteOperation.QUERY_HOSTNAME, RemoteOperation.QUERY_SERVICE,
              RemoteOperation.QUERY_REBOOT_PENDING, RemoteOperation.QUERY_AGENT_INSTALLED}


class SimulatedWinRmAdapter(SimAdapterMixin, WinRmAdapter):
    label = "WinRM (Demo)"

    def __init__(self, world, latency) -> None:
        super().__init__(world, latency)
        self._sessions: dict[str, tuple[str, str]] = {}   # session_id -> (device_id, username)

    async def open_session(self, target: Target, on_stage: StageCallback | None = None
                           ) -> tuple[AdapterResult, RemoteSession | None]:
        stages: list[Stage] = []

        async def emit(name: str, status: ResultStatus, detail: str) -> None:
            await self.latency.wait(f"winrm-stage:{target.address}:{name}", 0.25)
            st = Stage(name, status, detail, utcnow())
            stages.append(st)
            if on_stage is not None:
                await on_stage(st)

        d = self.world.device_by_ip(target.address)
        failing, status, detail = winrm_gate(d, target.address, target.credential)
        port = target.port or 5986
        for name in STAGES:
            if name == failing:
                if status == ResultStatus.TIMEOUT:
                    await self.latency.wait(f"winrm-timeout:{target.address}", min(target.timeout_sec, 5.0), 0.0)
                await emit(name, status, detail)
                break
            await emit(name, ResultStatus.OK, {
                "CONNECTING": f"Connecting to {target.address}:{port} (HTTPS)",
                "TCP_OK": f"TCP connection established to {target.address}:{port}",
                "TLS_VALIDATED": "Server certificate chain trusted",
                "AUTH_OK": f"Authenticated as {target.credential.username if target.credential else '?'}",
                "SESSION_CREATED": "WS-Management shell created",
            }[name])
        connected = failing not in ("CONNECTING",)
        data = {"services.winrm.available": connected and status != ResultStatus.DISABLED,
                "services.winrm.port": port}
        if connected:
            data["services.winrm.tls"] = "invalid" if status == ResultStatus.TLS_INVALID else "valid"
        if status != ResultStatus.OK:
            return self.result(target.address, status, data, stages=stages, error_code=status.value,
                               error_detail=detail), None
        sid = new_id()
        self._sessions[sid] = (d.device_id, target.credential.username)
        return self.result(target.address, ResultStatus.OK, data, stages=stages,
                           raw={"shell_id": sid}), RemoteSession(sid, target.address, stages)

    async def close_session(self, session: RemoteSession) -> None:
        self._sessions.pop(session.session_id, None)

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        if not isinstance(op, RemoteOperation):
            raise ValueError(f"unsupported remote operation: {op!r}")
        if session.session_id not in self._sessions:
            return self.result(session.target, ResultStatus.ERROR, error_code="NO_SESSION",
                               error_detail="WinRM session is closed")
        if op not in _QUERY_OPS:
            raise NotImplementedError(f"{op.value} is implemented with the deployment engine (Phase 3)")
        await self.latency.wait(f"winrm-exec:{session.target}:{op.value}", 0.2)
        device_id, _ = self._sessions[session.session_id]
        d = self.world.device(device_id)
        if d is None or not d.online:
            return self.result(session.target, ResultStatus.UNREACHABLE, error_detail="Host went offline")
        st = d.state
        if op == RemoteOperation.QUERY_HOSTNAME:
            out: dict[str, Any] = {"identity.hostname": st["identity"]["hostname"]}
        elif op == RemoteOperation.QUERY_DISK_FREE:
            out = {"hardware.disk": st["hardware"]["disk"]}
        elif op == RemoteOperation.QUERY_REBOOT_PENDING:
            return self.result(session.target, ResultStatus.OK, raw={"reboot_pending": st.get("reboot_pending", False)})
        elif op == RemoteOperation.QUERY_SERVICE:
            name = params.get("name")
            svc = next((s for s in st.get("services", []) if s["name"] == name), None)
            return self.result(session.target, ResultStatus.OK, raw={"service": svc})
        else:  # QUERY_AGENT_INSTALLED
            return self.result(session.target, ResultStatus.OK,
                               raw={"installed": bool(st.get("files", {}).get("agent"))})
        return self.result(session.target, ResultStatus.OK, out)

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover - WinRM cannot discover

    async def health_check(self, target: Target) -> AdapterResult:
        await self.latency.wait(f"winrm-tcp:{target.address}", 0.2)
        d = self.world.device_by_ip(target.address)
        failing, status, detail = winrm_gate(d, target.address, target.credential)
        if failing == "CONNECTING":
            return self.result(target.address, status, {"services.winrm.available": False,
                                                         "services.winrm.port": target.port or 5986},
                               error_code=status.value, error_detail=detail)
        return self.result(target.address, ResultStatus.OK, {"services.winrm.available": True,
                                                              "services.winrm.port": target.port or 5986})

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        res, session = await self.open_session(target, on_stage)
        if session is not None:
            await self.close_session(session)
        return res

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)
