from __future__ import annotations

from typing import AsyncIterator

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    IcmpAdapter,
    Protocol,
    Query,
    Reachability,
    ResultStatus,
    StageCallback,
    Target,
)
from tests.sim.adapters.common import SimAdapterMixin
from tests.sim.world import DeviceView

HIGH_LATENCY_MS = 100.0
_STATUS = {Reachability.ONLINE: ResultStatus.OK, Reachability.HIGH_LATENCY: ResultStatus.OK,
           Reachability.BLOCKED: ResultStatus.BLOCKED, Reachability.OFFLINE: ResultStatus.UNREACHABLE,
           Reachability.TIMEOUT: ResultStatus.TIMEOUT}


class SimulatedIcmpAdapter(SimAdapterMixin, IcmpAdapter):
    label = "ICMP (Demo)"

    def _reach(self, d: DeviceView | None) -> tuple[Reachability, float | None]:
        if d is None:
            return Reachability.TIMEOUT, None
        if not d.online:
            return Reachability.OFFLINE, None   # "Destination host unreachable" from the gateway
        if d.has("icmp_blocked") or d.state.get("icmp") == "BLOCKED":
            return Reachability.BLOCKED, None
        rtt = round(self.latency.jitter(f"rtt:{d.ip}", d.state.get("rtt_ms") or 1.0, 0.1), 2)
        return (Reachability.HIGH_LATENCY if rtt > HIGH_LATENCY_MS else Reachability.ONLINE), rtt

    def _host_result(self, ip: str, d: DeviceView | None) -> AdapterResult:
        reach, rtt = self._reach(d)
        detail = {
            Reachability.BLOCKED: "No ICMP reply (filtered). No reply does not mean the device is offline.",
            Reachability.OFFLINE: "Destination host unreachable",
            Reachability.TIMEOUT: "Request timed out",
        }.get(reach)
        return self.result(ip, _STATUS[reach], {"reachability.icmp": reach.value, "reachability.rtt_ms": rtt},
                           raw={"reply": reach.value, "rtt_ms": rtt}, latency_ms=rtt or 0.0,
                           error_code=None if detail is None else reach.value, error_detail=detail)

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        for d in self.world.devices_in(target.address):
            await self.step_wait(f"icmp-sweep:{d.ip}", 0.15, target.safe_mode)
            res = self._host_result(d.ip, d)
            if res.data["reachability.icmp"] in ("ONLINE", "HIGH_LATENCY", "BLOCKED"):
                yield DiscoveredHost(d.ip, None, Protocol.ICMP, res.data)

    async def health_check(self, target: Target) -> AdapterResult:
        await self.step_wait(f"icmp:{target.address}", 0.2, target.safe_mode)
        return self._host_result(target.address, self.world.device_by_ip(target.address))

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)
