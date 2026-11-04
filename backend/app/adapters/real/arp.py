from __future__ import annotations

import ipaddress
from typing import AsyncIterator

from app.adapters.base import (
    AdapterResult,
    ArpAdapter,
    DiscoveredHost,
    Protocol,
    Query,
    ResultStatus,
    StageCallback,
    Target,
)
from app.adapters.real.common import RealAdapterMixin
from app.adapters.real.net import neighbors


class RealArpAdapter(RealAdapterMixin, ArpAdapter):
    """Reads the kernel neighbour cache after the ICMP/TCP sweeps. Sends nothing itself. Only local-segment
    addresses appear; remote subnets are found by ICMP/TCP (and later by router ARP tables over SNMP).

    A MAC that answers for several IPs (proxy ARP) is reported as ``network.arp_via`` and never as the device's
    ``network.mac``, because inventory merges devices by MAC."""

    implementation, label = "neighbour-cache", "ARP (kernel neighbour table)"
    runs_after_sweep = True

    @staticmethod
    def _host(ip: str, mac: str, shared: dict[str, int]) -> tuple[str | None, dict]:
        if mac in shared:
            return None, {"network.ip": ip, "network.arp_via": mac}
        return mac, {"network.ip": ip, "network.mac": mac}

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        net = ipaddress.ip_network(target.address, strict=False)
        table = await neighbors.read_table()
        shared = neighbors.shared_macs(table)
        for ip, mac in sorted(table.items()):
            if ipaddress.ip_address(ip) in net and self.gate.decide(ip).allowed:
                own_mac, data = self._host(ip, mac, shared)
                yield DiscoveredHost(ip, own_mac, Protocol.ARP, data)

    async def health_check(self, target: Target) -> AdapterResult:
        table = await neighbors.read_table()
        mac = table.get(target.address)
        if mac is None:
            return self.result(target.address, ResultStatus.UNREACHABLE, error_code="NO_ARP_ENTRY",
                               error_detail=f"No neighbour entry for {target.address} (not on a local segment, "
                                            "or it did not answer)")
        shared = neighbors.shared_macs(table)
        _, data = self._host(target.address, mac, shared)
        raw = {"ip": target.address, "mac": mac, "sharedBy": shared.get(mac, 1)}
        return self.result(target.address, ResultStatus.OK, data, raw=raw)

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)
