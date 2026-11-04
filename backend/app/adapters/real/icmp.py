from __future__ import annotations

import time
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
from app.adapters.real.common import RealAdapterMixin, expand, sweep
from app.adapters.real.net import icmp
from app.adapters.real.net.gate import GateBlocked

HIGH_LATENCY_MS = 100.0
NO_REPLY = "No ICMP echo reply. Filtered or offline: no reply does not mean the device is offline."


class RealIcmpAdapter(RealAdapterMixin, IcmpAdapter):
    implementation, label = "icmplib", "ICMP"

    @staticmethod
    def _reach(reply: icmp.EchoReply) -> Reachability:
        if not reply.alive:
            return Reachability.TIMEOUT
        return Reachability.HIGH_LATENCY if (reply.rtt_ms or 0) > HIGH_LATENCY_MS else Reachability.ONLINE

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        timeout = min(target.timeout_sec, 2.0)
        async for ip, reply in sweep(self.gate, expand(target), lambda h: icmp.echo(self.gate, h, timeout)):
            if reply.alive:
                yield DiscoveredHost(ip, None, Protocol.ICMP, {"reachability.icmp": self._reach(reply).value,
                                                               "reachability.rtt_ms": reply.rtt_ms})

    async def health_check(self, target: Target) -> AdapterResult:
        started = time.monotonic()
        try:
            reply = await icmp.echo(self.gate, target.address, min(target.timeout_sec, 2.0))
        except GateBlocked as exc:
            return self.blocked(target.address, exc)
        waited = round((time.monotonic() - started) * 1000, 2)
        reach = self._reach(reply)
        data = {"reachability.icmp": reach.value, "reachability.rtt_ms": reply.rtt_ms}
        if not reply.alive:
            return self.result(target.address, ResultStatus.TIMEOUT, data, latency_ms=waited, error_code="TIMEOUT",
                               error_detail=NO_REPLY)
        return self.result(target.address, ResultStatus.OK, data, raw={"rtt_ms": reply.rtt_ms},
                           latency_ms=reply.rtt_ms)

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)
