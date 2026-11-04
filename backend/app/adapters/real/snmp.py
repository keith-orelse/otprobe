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
from app.adapters.real.common import RealAdapterMixin, expand, sweep
from app.adapters.real.net import snmp
from app.adapters.real.net.gate import GateBlocked

SYS = {"sys_descr": "1.3.6.1.2.1.1.1.0", "sys_object_id": "1.3.6.1.2.1.1.2.0", "uptime": "1.3.6.1.2.1.1.3.0",
       "sys_name": "1.3.6.1.2.1.1.5.0"}
ENTITY = {"firmware.version": "1.3.6.1.2.1.47.1.1.1.1.9.1", "hardware.vendor": "1.3.6.1.2.1.47.1.1.1.1.12.1",
          "hardware.model": "1.3.6.1.2.1.47.1.1.1.1.13.1"}
IF_DESCR, IF_OPER, IF_SPEED = "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.8", "1.3.6.1.2.1.31.1.1.1.15"
# Enterprise numbers (sysObjectID 1.3.6.1.4.1.<n>) -> vendor, used when ENTITY-MIB gives no manufacturer.
ENTERPRISES = {"9": "Cisco", "11": "HP", "311": "Microsoft", "674": "Dell", "2636": "Juniper", "4329": "Siemens",
               "8072": "Net-SNMP", "25506": "H3C", "1916": "Extreme Networks", "6486": "Alcatel-Lucent",
               "4526": "Netgear", "14988": "MikroTik", "3076": "Phoenix Contact", "13576": "Westermo",
               "8691": "Moxa", "248": "Hirschmann", "16728": "Schneider Electric", "1588": "Brocade"}
STATUS = {"OK": ResultStatus.OK, "TIMEOUT": ResultStatus.TIMEOUT, "AUTH_FAILED": ResultStatus.AUTH_FAILED,
          "ERROR": ResultStatus.ERROR}


def vendor_from_oid(oid: str | None) -> str | None:
    if not oid or not oid.startswith("1.3.6.1.4.1."):
        return None
    return ENTERPRISES.get(oid.split(".")[6])


def port_of(target: Target) -> int:
    """target.port, else the profile's ``params.port`` (agents on non-standard ports), else 161."""
    params = target.credential.params if target.credential else {}
    return int(target.port or params.get("port", 161))


class RealSnmpAdapter(RealAdapterMixin, SnmpAdapter):
    implementation, label = "pysnmp", "SNMP"

    def _identity(self, values: dict[str, Any]) -> dict[str, Any]:
        oid = values.get(SYS["sys_object_id"])
        data = {"snmp.sys_name": values.get(SYS["sys_name"]), "snmp.sys_descr": values.get(SYS["sys_descr"]),
                "snmp.sys_object_id": oid}
        vendor = vendor_from_oid(oid)
        if vendor:
            data["hardware.vendor"] = vendor
        return {k: v for k, v in data.items() if v not in (None, "")}

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        if target.credential is None:
            return
        timeout, port = min(target.timeout_sec, 2.0), port_of(target)

        async def one(ip: str) -> snmp.SnmpReply:
            return await snmp.get(self.gate, ip, target.credential, list(SYS.values()), timeout, port)

        async for ip, reply in sweep(self.gate, expand(target), one):
            if reply.status == "OK":
                yield DiscoveredHost(ip, None, Protocol.SNMP, self._identity(reply.values))

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        ip, cred = target.address, target.credential
        if cred is None:
            return self.result(ip, ResultStatus.AUTH_FAILED, error_code="NO_CREDENTIAL",
                               error_detail="No SNMP credential profile configured")
        groups = set(query.items or ("system", "entity", "interfaces"))
        timeout, port = min(target.timeout_sec, 3.0), port_of(target)
        try:
            base = await snmp.get(self.gate, ip, cred, list(SYS.values()), timeout, port)
            if base.status != "OK":
                data = {"services.snmp.available": False} if base.status == "TIMEOUT" else {}
                detail = base.error if base.status != "TIMEOUT" else f"SNMP request timed out (profile {cred.profile})"
                return self.result(ip, STATUS[base.status], data, error_code=base.status, error_detail=detail)
            data: dict[str, Any] = {"services.snmp.available": True}
            raw: dict[str, Any] = {"system": base.values}
            if "system" in groups:
                data.update(self._identity(base.values))
                if isinstance(base.values.get(SYS["uptime"]), int):
                    data["snmp.uptime_sec"] = base.values[SYS["uptime"]] // 100
            if "entity" in groups:
                ent = await snmp.get(self.gate, ip, cred, list(ENTITY.values()), timeout, port)
                if ent.status == "OK":
                    raw["entity"] = ent.values
                    data.update({k: ent.values.get(o) for k, o in ENTITY.items() if ent.values.get(o)})
            if "interfaces" in groups:
                data.update(await self._interfaces(ip, cred, timeout, port, raw))
        except GateBlocked as exc:
            return self.result(ip, ResultStatus.BLOCKED, error_code=exc.reason.upper().replace("-", "_"),
                               error_detail=self.blocked(ip, exc).error_detail)
        return self.result(ip, ResultStatus.OK, {k: v for k, v in data.items() if v is not None}, raw)

    async def _interfaces(self, ip: str, cred, timeout: float, port: int, raw: dict[str, Any]) -> dict[str, Any]:
        descr = await snmp.walk(self.gate, ip, cred, IF_DESCR, timeout, port=port)
        if descr.status != "OK" or not descr.values:
            return {}
        oper = await snmp.walk(self.gate, ip, cred, IF_OPER, timeout, port=port)
        speed = await snmp.walk(self.gate, ip, cred, IF_SPEED, timeout, port=port)
        ifaces = []
        for oid, name in descr.values.items():
            idx = oid.rsplit(".", 1)[1]
            status = oper.values.get(f"{IF_OPER}.{idx}")
            ifaces.append({"index": int(idx), "name": name, "description": name,
                           "oper_status": {1: "up", 2: "down"}.get(status, "unknown"),
                           "speed_mbps": speed.values.get(f"{IF_SPEED}.{idx}")})
        raw["interfaces"] = ifaces
        return {"network.interfaces": ifaces, "network.active_ports": sum(i["oper_status"] == "up" for i in ifaces)}

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["system"]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["system", "entity"]))
