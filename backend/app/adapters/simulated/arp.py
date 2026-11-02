from __future__ import annotations

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
from app.adapters.simulated.common import SimAdapterMixin


class SimulatedArpAdapter(SimAdapterMixin, ArpAdapter):
    """Models a passive collector on the industrial switch span port (docs/ARCHITECTURE.md §11.2)."""

    label = "ARP (via switch span, Demo)"

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        for d in self.world.devices_in(target.address):
            await self.step_wait(f"arp-sweep:{d.ip}", 0.4, target.safe_mode)
            if d.online:
                yield DiscoveredHost(d.ip, d.mac, Protocol.ARP, {"network.ip": d.ip, "network.mac": d.mac})

    async def health_check(self, target: Target) -> AdapterResult:
        await self.step_wait(f"arp:{target.address}", 0.2, target.safe_mode)
        d = self.world.device_by_ip(target.address)
        if d is None or not d.online:
            return self.result(target.address, ResultStatus.UNREACHABLE, error_code="NO_ARP_ENTRY",
                               error_detail=f"No ARP entry for {target.address}")
        return self.result(target.address, ResultStatus.OK, {"network.ip": d.ip, "network.mac": d.mac},
                           raw={"ip": d.ip, "mac": d.mac, "interface": "span0"})

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)
