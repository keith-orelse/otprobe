from __future__ import annotations

from typing import Any, AsyncIterator

from app.adapters.base import AdapterResult, DiscoveredHost, Query, ResultStatus, StageCallback, Target, WmiAdapter
from app.adapters.simulated.common import SimAdapterMixin, winrm_gate

ALL_GROUPS = ("os", "hardware", "firewall", "antivirus", "software", "services", "hotfixes", "network")
CIM_CLASSES = {
    "os": "Win32_OperatingSystem", "hardware": "Win32_ComputerSystem/Win32_Processor/Win32_LogicalDisk",
    "firewall": "MSFT_NetFirewallProfile", "antivirus": "MSFT_MpComputerStatus",
    "software": "HKLM Uninstall keys (machine scope only)", "services": "Win32_Service",
    "hotfixes": "Win32_QuickFixEngineering", "network": "MSFT_NetIPAddress/MSFT_NetTCPConnection",
}


class SimulatedWmiAdapter(SimAdapterMixin, WmiAdapter):
    """CIM over the WinRM transport. Agentless visibility is deliberately partial (see PROVENANCE matrix)."""

    label = "WMI/CIM (Demo)"

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        d = self.world.device_by_ip(target.address)
        failing, status, detail = winrm_gate(d, target.address, target.credential)
        if status != ResultStatus.OK:
            return self.result(target.address, status, error_code=status.value,
                               error_detail=f"CIM session failed at {failing}: {detail}")
        st = d.state
        data: dict[str, Any] = {}
        raw: dict[str, Any] = {}
        for group in query.items or ALL_GROUPS:
            await self.latency.wait(f"wmi:{target.address}:{group}", 0.15)
            raw[group] = CIM_CLASSES.get(group, group)
            if group == "os":
                o = st["os"]
                data.update({"os.family": o["family"], "os.name": o["name"], "os.product": o["product"],
                             "os.version": o["version"], "os.build": o["build"],
                             "identity.hostname": st["identity"]["hostname"],
                             "identity.domain": st["identity"].get("domain")})
            elif group == "hardware":
                h = st["hardware"]
                data.update({"hardware.manufacturer": h["manufacturer"], "hardware.model": h["model"],
                             "hardware.cpu": h["cpu"], "hardware.ram_gb": h["ram_gb"], "hardware.disk": h["disk"],
                             "hardware.uptime_sec": h["uptime_sec"]})
            elif group == "firewall":
                data["firewall.state"] = st["firewall"]["state"]
            elif group == "antivirus":
                data.update({"antivirus.product": st["antivirus"]["product"],
                             "antivirus.state": st["antivirus"]["state"]})
            elif group == "software":
                data["software.installed"] = [{"name": a["name"], "version": a["version"]}
                                              for a in st["software"] if a.get("scope", "machine") == "machine"]
            elif group == "services":
                data["services.running"] = sorted(s["name"] for s in st["services"] if s["state"] == "running")
            elif group == "hotfixes":
                data["patches.installed"] = list(st["patches"]["installed"])
            elif group == "network":
                net = st["network"]
                data.update({"network.interfaces": net["interfaces"], "network.listening": net["listening"],
                             "network.connections": net["connections"]})
        return self.result(target.address, ResultStatus.OK, data, raw={"cim_classes": raw},
                           latency_ms=self.latency.jitter(f"wmi-rtt:{target.address}", 85.0))

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["os"]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["os", "hardware"]))
