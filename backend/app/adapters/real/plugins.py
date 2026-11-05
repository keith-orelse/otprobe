"""Read-only OT identification plugins (docs/LIVE_PROTOCOLS.md §4). Each wraps one sender in app.adapters.real.net
and maps its answer to provenance fields. A plugin first asks the gate whether plugins may run for this address
(safe mode, profile, scope entry) and answers NOT_SUPPORTED, without sending anything, when they may not."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from app.adapters.base import AdapterResult, OtPlugin, Protocol, ResultStatus, Target
from app.adapters.real.common import RealAdapterMixin
from app.adapters.real.net import bacnet, enip, http, modbus, opcua, s7
from app.adapters.real.net._stream import WriteAttemptBlocked
from app.adapters.real.net.gate import GateBlocked

S7_FAMILIES = [(r"^6ES7 ?21", "S7-1200"), (r"^6ES7 ?51", "S7-1500"), (r"^6ES7 ?31", "S7-300"),
               (r"^6ES7 ?41", "S7-400"), (r"^6ES7 ?15", "ET 200SP CPU")]


def s7_family(order_code: str | None) -> str | None:
    for pattern, family in S7_FAMILIES:
        if order_code and re.match(pattern, order_code):
            return family
    return None


class _Plugin(RealAdapterMixin, OtPlugin):
    explicit_only = False

    async def _collect(self, ip: str, port: int | None, timeout: float) -> dict:
        raise NotImplementedError

    def _fields(self, answer: dict) -> dict[str, Any]:
        raise NotImplementedError

    async def identify(self, target: Target) -> AdapterResult:
        ip = target.address
        if not self.gate.plugin_allowed(ip, self.name, self.explicit_only):
            return self.result(ip, ResultStatus.NOT_SUPPORTED, error_code="PLUGIN_NOT_ENABLED",
                               error_detail=f"{self.display_label} is not enabled for this range (safe mode, or not "
                                            "listed on an OT-sensitive scope entry)")
        timeout = min(target.timeout_sec, 3.0)
        started = asyncio.get_running_loop().time()
        try:
            answer = await self._collect(ip, target.port, timeout)
        except GateBlocked as exc:
            return self.blocked(ip, exc)
        except WriteAttemptBlocked as exc:      # a bug, never a device problem: surfaced loudly
            return self.result(ip, ResultStatus.ERROR, error_code="WRITE_ATTEMPT_BLOCKED", error_detail=str(exc))
        except ConnectionRefusedError:
            return self.result(ip, ResultStatus.REFUSED, error_code="REFUSED", error_detail="Connection refused")
        except Exception as exc:  # noqa: BLE001 - devices answer in odd ways (short frames, resets); never crash
            return self.result(ip, ResultStatus.TIMEOUT if isinstance(exc, (asyncio.TimeoutError, TimeoutError))
                               else ResultStatus.ERROR, error_code=type(exc).__name__,
                               error_detail=f"No usable {self.display_label} answer ({type(exc).__name__})")
        waited = round((asyncio.get_running_loop().time() - started) * 1000, 2)
        if not answer or "exception" in answer:
            return self.result(ip, ResultStatus.NOT_SUPPORTED, raw=answer, latency_ms=waited,
                               error_code="NO_IDENTITY", error_detail=answer.get("exception", "Device gave no identity")
                               if answer else "Device gave no identity")
        data = {k: v for k, v in self._fields(answer).items() if v not in (None, "", [])}
        return self.result(ip, ResultStatus.OK, data, raw=answer, latency_ms=waited)


class ModbusPlugin(_Plugin):
    name, protocol, display_label, ports = "modbus", Protocol.MODBUS, "Modbus TCP (Read Device Identification)", (502,)
    implementation, label = "modbus", "Modbus TCP"

    async def _collect(self, ip, port, timeout):
        return await modbus.read_device_identification(self.gate, ip, timeout, port or 502)

    def _fields(self, a):
        o = a["objects"]
        return {"hardware.vendor": o.get("vendor"), "plc.product_code": o.get("product_code"),
                "firmware.version": o.get("revision"), "hardware.model": o.get("model_name") or o.get("product_name")}


class S7Plugin(_Plugin):
    name, protocol, display_label, ports = "s7", Protocol.S7, "Siemens S7 (SZL identification)", (102,)
    implementation, label, risk = "s7", "Siemens S7", "MEDIUM"

    async def _collect(self, ip, port, timeout):
        return await s7.identify(self.gate, ip, timeout, port or 102)

    def _fields(self, a):
        code = a.get("order_code")
        return {"hardware.vendor": "Siemens", "plc.product_code": code, "firmware.version": a.get("firmware"),
                "hardware.model": a.get("module_type") or s7_family(code), "hardware.serial": a.get("serial"),
                "plc.name": a.get("plc_name")}


class EnipPlugin(_Plugin):
    name, protocol, display_label, ports = "enip", Protocol.ENIP, "EtherNet/IP (ListIdentity)", (44818,)
    implementation, label = "enip", "EtherNet/IP"

    async def _collect(self, ip, port, timeout):
        return await enip.list_identity(self.gate, ip, timeout, port or 44818)

    def _fields(self, a):
        return {"hardware.vendor": a.get("vendor"), "hardware.model": a.get("product_name"),
                "plc.product_code": str(a["product_code"]), "firmware.version": a.get("revision"),
                "hardware.serial": a.get("serial"), "ot.device_type": a.get("device_type")}


class BacnetPlugin(_Plugin):
    name, protocol, display_label, ports = "bacnet", Protocol.BACNET, "BACnet/IP (ReadProperty)", ()
    implementation, label, explicit_only = "bacnet", "BACnet/IP", True

    async def _collect(self, ip, port, timeout):
        return await bacnet.identify(self.gate, ip, timeout, port or 47808)

    def _fields(self, a):
        return {"hardware.vendor": a.get("vendor_name"), "hardware.model": a.get("model_name"),
                "firmware.version": a.get("firmware_revision"), "plc.name": a.get("object_name")}


class OpcUaPlugin(_Plugin):
    name, protocol, display_label, ports = "opcua", Protocol.OPCUA, "OPC UA (GetEndpoints)", (4840,)
    implementation, label = "opcua", "OPC UA"

    async def _collect(self, ip, port, timeout):
        return await opcua.endpoints(self.gate, ip, timeout, port or 4840)

    def _fields(self, a):
        return {"opcua.application_name": a.get("application_name"), "opcua.product_uri": a.get("product_uri"),
                "opcua.security_policies": a.get("security_policies")}


class HttpTitlePlugin(_Plugin):
    name, protocol, display_label, ports = "http_title", Protocol.HTTP, "Web page title", (80, 8080, 443, 8443)
    implementation, label = "http", "HTTP"

    async def _collect(self, ip, port, timeout):
        return await http.title(self.gate, ip, port or 80, (port or 80) in (443, 8443), timeout)

    def _fields(self, a):
        return {"http.title": a.get("title"), "http.server": a.get("server")}


ALL_PLUGINS = (ModbusPlugin, S7Plugin, EnipPlugin, BacnetPlugin, OpcUaPlugin, HttpTitlePlugin)
