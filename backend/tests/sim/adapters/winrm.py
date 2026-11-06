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
from app.core.clock import utcnow
from app.core.ids import new_id
from tests.sim.adapters.common import SimAdapterMixin, winrm_gate

STAGES = ("CONNECTING", "TCP_OK", "TLS_VALIDATED", "AUTH_OK", "SESSION_CREATED")
AGENT_SERVICE = "OTProbeAgent"
AGENT_DIR = "C:/Program Files/OTProbe/Agent"


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

    def session_device(self, session: RemoteSession) -> str | None:
        entry = self._sessions.get(session.session_id)
        return entry[0] if entry else None

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        if not isinstance(op, RemoteOperation):
            raise ValueError(f"unsupported remote operation: {op!r}")
        if session.session_id not in self._sessions:
            return self.result(session.target, ResultStatus.ERROR, error_code="NO_SESSION",
                               error_detail="WinRM session is closed")
        await self.latency.wait(f"winrm-exec:{session.target}:{op.value}", 0.3)
        device_id, _ = self._sessions[session.session_id]
        d = self.world.device(device_id)
        if d is None or not d.online:
            return self.result(session.target, ResultStatus.UNREACHABLE, error_code="CONNECTION_LOST",
                               error_detail="Host went offline")
        handler = getattr(self, f"_op_{op.value.lower()}")
        return await handler(session, d, params)

    def _ok(self, session: RemoteSession, data: dict | None = None, raw: dict | None = None) -> AdapterResult:
        return self.result(session.target, ResultStatus.OK, data or {}, raw=raw or {})

    def _err(self, session: RemoteSession, code: str, detail: str, raw: dict | None = None) -> AdapterResult:
        return self.result(session.target, ResultStatus.ERROR, raw=raw or {}, error_code=code, error_detail=detail)

    @staticmethod
    def _service(state: dict, name: str) -> dict | None:
        return next((s for s in state.get("services", []) if s["name"] == name), None)

    async def _op_query_hostname(self, session, d, params):
        return self._ok(session, {"identity.hostname": d.state["identity"]["hostname"]})

    async def _op_query_disk_free(self, session, d, params):
        return self._ok(session, {"hardware.disk": d.state["hardware"]["disk"]})

    async def _op_query_reboot_pending(self, session, d, params):
        return self._ok(session, raw={"reboot_pending": d.state.get("reboot_pending", False)})

    async def _op_query_service(self, session, d, params):
        return self._ok(session, raw={"service": self._service(d.state, params.get("name", AGENT_SERVICE))})

    async def _op_query_agent_installed(self, session, d, params):
        agent = d.state.get("files", {}).get("agent")
        return self._ok(session, raw={"installed": bool(agent), "version": (agent or {}).get("version")})

    async def _op_query_server_connectivity(self, session, d, params):
        if d.has("server_unreachable"):
            return self._err(session, "TCP_FAILED", f"TcpTestSucceeded=False to {params.get('server')}:443")
        return self._ok(session, raw={"TcpTestSucceeded": True, "RemoteAddress": params.get("server"),
                                      "RemotePort": 443, "path": "fw-conduit-01"})

    async def _op_verify_file_hash(self, session, d, params):
        staged = d.state.get("files", {}).get("staged", {}).get(params["path"])
        if staged is None:
            return self._err(session, "FILE_NOT_FOUND", f"{params['path']} not found")
        actual, expected = staged["sha256"], params["sha256"]
        raw = {"expected": expected, "actual": actual, "algorithm": "SHA256"}
        if actual != expected:
            return self._err(session, "HASH_MISMATCH",
                             f"Package hash mismatch: expected {expected[:4]}…{expected[-4:]}, "
                             f"got {actual[:4]}…{actual[-4:]}", raw)
        return self._ok(session, raw=raw)

    async def _op_install_agent(self, session, d, params):
        if d.has("install_failure"):
            return self._err(session, "INSTALL_FAILED",
                             "Agent installer failed (exit code 1603). Installer rolled back", {"exit_code": 1603})

        def install(state: dict) -> None:
            files = state.setdefault("files", {})
            files["agent"] = {"version": params["version"], "path": AGENT_DIR, "installed_by": params.get("by")}
            files["enroll_bundle"] = {"enrollmentToken": params["enrollment_token"],
                                      "serverUrl": params["server_url"], "deploymentId": params["deployment_id"],
                                      "agentVersion": params["version"]}
            files.pop("agent_identity", None)
            services = state.setdefault("services", [])
            services[:] = [s for s in services if s["name"] != AGENT_SERVICE]
            services.append({"name": AGENT_SERVICE, "display": "OTProbe Probe Agent", "state": "stopped",
                             "start_type": "auto"})
            state.setdefault("software", []).append({"name": "OTProbe Probe Agent", "version": params["version"],
                                                     "publisher": "OTProbe", "scope": "machine"})

        self.world.update_state(d.device_id, install)
        return self._ok(session, raw={"exit_code": 0, "path": AGENT_DIR})

    async def _op_write_enrollment_bundle(self, session, d, params):
        self.world.update_state(d.device_id, lambda st: st.setdefault("files", {}).update(enroll_bundle=dict(params)))
        return self._ok(session)

    def _set_service_state(self, device_id: str, name: str, value: str) -> bool:
        found = []

        def mutate(state: dict) -> None:
            svc = self._service(state, name)
            if svc is not None:
                svc["state"] = value
                found.append(True)

        self.world.update_state(device_id, mutate)
        return bool(found)

    async def _op_start_service(self, session, d, params):
        name = params.get("name", AGENT_SERVICE)
        if not self._set_service_state(d.device_id, name, "running"):
            return self._err(session, "SERVICE_NOT_FOUND", f"Service {name} not found")
        self.world.clear_fault(d.device_id, "agent_crashed")   # a service restart brings a crashed agent back
        return self._ok(session, raw={"service": name, "state": "running"})

    async def _op_stop_service(self, session, d, params):
        name = params.get("name", AGENT_SERVICE)
        if not self._set_service_state(d.device_id, name, "stopped"):
            return self._err(session, "SERVICE_NOT_FOUND", f"Service {name} not found")
        return self._ok(session, raw={"service": name, "state": "stopped"})

    async def _op_uninstall_agent(self, session, d, params):
        if d.has("rollback_failure"):
            return self._err(session, "UNINSTALL_FAILED", "Uninstall failed (exit code 1603)", {"exit_code": 1603})

        def uninstall(state: dict) -> None:
            files = state.setdefault("files", {})
            for key in ("agent", "enroll_bundle", "agent_identity"):
                files.pop(key, None)
            state["services"] = [s for s in state.get("services", []) if s["name"] != AGENT_SERVICE]
            state["software"] = [a for a in state.get("software", []) if a["name"] != "OTProbe Probe Agent"]

        self.world.update_state(d.device_id, uninstall)
        return self._ok(session, raw={"exit_code": 0})

    async def _op_remove_files(self, session, d, params):
        paths = params.get("paths", [])

        def remove(state: dict) -> None:
            staged = state.setdefault("files", {}).setdefault("staged", {})
            for p in paths:
                staged.pop(p, None)

        self.world.update_state(d.device_id, remove)
        return self._ok(session, raw={"removed": paths})

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
