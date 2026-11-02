from __future__ import annotations

from typing import Any, AsyncIterator

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    ResultStatus,
    SnmpAdapter,
    StageCallback,
    Target,
)
from app.adapters.simulated.common import SimAdapterMixin
from app.sim.world import DeviceView

ALL_GROUPS = ("system", "interfaces", "entity", "lldp", "plc")


class SimulatedSnmpAdapter(SimAdapterMixin, SnmpAdapter):
    label = "SNMP (Demo)"

    def _gate(self, d: DeviceView | None, target: Target) -> tuple[ResultStatus, str | None]:
        if d is None or not d.online or d.state.get("snmp") is None:
            return ResultStatus.TIMEOUT, "No SNMP response (request timed out)"
        if d.has("snmp_timeout"):
            return ResultStatus.TIMEOUT, "SNMPv3 request timed out"
        user = d.state["snmp"]["user"]
        cred = target.credential
        if cred is None or cred.username != user["username"] or cred.secret != user["secret"]:
            return ResultStatus.AUTH_FAILED, "SNMPv3 authentication failed (usmStatsWrongDigests)"
        return ResultStatus.OK, None

    async def _timeout_wait(self, target: Target) -> None:
        await self.latency.wait(f"snmp-timeout:{target.address}", min(target.timeout_sec, 5.0), 0.0)

    @staticmethod
    def _identity(snmp: dict[str, Any]) -> dict[str, Any]:
        ent = snmp.get("entity", {})
        return {"snmp.sys_name": snmp["sys_name"], "snmp.sys_descr": snmp["sys_descr"],
                "snmp.sys_object_id": snmp["sys_object_id"], "hardware.vendor": ent.get("vendor"),
                "hardware.model": ent.get("model")}

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        for d in self.world.devices_in(target.address):
            await self.step_wait(f"snmp-sweep:{d.ip}", 0.3, target.safe_mode)
            status, _ = self._gate(d, target)
            if status == ResultStatus.OK:
                yield DiscoveredHost(d.ip, None, Protocol.SNMP, self._identity(d.state["snmp"]))

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        await self.step_wait(f"snmp:{target.address}", 0.4, target.safe_mode)
        d = self.world.device_by_ip(target.address)
        status, err = self._gate(d, target)
        if status != ResultStatus.OK:
            if status == ResultStatus.TIMEOUT:
                await self._timeout_wait(target)
            return self.result(target.address, status, {"services.snmp.available": False}
                               if status == ResultStatus.TIMEOUT else {}, error_code=status.value, error_detail=err)
        snmp = d.state["snmp"]
        groups = set(query.items or ALL_GROUPS)
        data: dict[str, Any] = {"services.snmp.available": True}
        raw: dict[str, Any] = {}
        if "system" in groups:
            data.update({k: v for k, v in self._identity(snmp).items() if k.startswith("snmp.")})
            data["snmp.uptime_sec"] = snmp["uptime_sec"]
            raw["system"] = {"sysName.0": snmp["sys_name"], "sysDescr.0": snmp["sys_descr"],
                             "sysObjectID.0": snmp["sys_object_id"], "sysUpTime.0": snmp["uptime_sec"] * 100}
        if "entity" in groups:
            ent = snmp.get("entity", {})
            data.update({"hardware.vendor": ent.get("vendor"), "hardware.model": ent.get("model")})
            if ent.get("firmware"):
                data["firmware.version"] = ent["firmware"]
        ifaces = snmp.get("interfaces") or []
        if "interfaces" in groups and ifaces:
            data["network.interfaces"] = [{"index": i["index"], "name": i["name"], "oper_status": i["oper_status"],
                                           "speed_mbps": i["speed_mbps"], "description": i["description"]}
                                          for i in ifaces]
            data["network.active_ports"] = sum(1 for i in ifaces if i["oper_status"] == "up")
        if "lldp" in groups and ifaces:
            data["network.lldp_neighbors"] = [{"port": i["name"], "mac": i["neighbor_mac"]}
                                              for i in ifaces if i.get("neighbor_mac")]
        if "plc" in groups and snmp.get("plc"):
            plc = snmp["plc"]
            data.update({"plc.mode": plc["mode"], "plc.cpu": plc["cpu"], "firmware.version": plc["firmware"]})
        return self.result(target.address, ResultStatus.OK, data, raw=raw,
                           latency_ms=self.latency.jitter(f"snmp-rtt:{d.ip}", 12.0) )

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["system"]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["system", "entity", "plc"]))
