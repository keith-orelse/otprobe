from __future__ import annotations

import time
from typing import AsyncIterator

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    ResultStatus,
    StageCallback,
    Target,
    TcpAdapter,
)
from app.adapters.real.common import RealAdapterMixin, expand, sweep
from app.adapters.real.net import tcp
from app.adapters.real.net.gate import GateBlocked

# docs/LIVE_PROTOCOLS.md §3. Connect only: decides which protocols to try later and what is exposed.
PORTS = (22, 23, 80, 102, 135, 139, 443, 445, 502, 1883, 1911, 2404, 3389, 4840, 4911, 5900, 5985, 5986, 8080,
         8443, 8883, 9600, 18245, 20000, 44818)


class RealTcpAdapter(RealAdapterMixin, TcpAdapter):
    implementation, label = "tcp-connect", "TCP connect"

    def _ports(self, target: Target) -> tuple[int, ...]:
        return tuple(target.options.get("ports") or ((target.port,) if target.port else PORTS))

    async def _scan(self, ip: str, ports: tuple[int, ...], timeout: float) -> list[tcp.PortState]:
        return [await tcp.connect(self.gate, ip, p, timeout) for p in ports]

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        ports, timeout = self._ports(target), min(target.timeout_sec, 2.0)
        async for ip, states in sweep(self.gate, expand(target), lambda h: self._scan(h, ports, timeout)):
            open_ports = [s.port for s in states if s.state == "OPEN"]
            if open_ports or any(s.state == "CLOSED" for s in states):   # a RST also proves the host is there
                yield DiscoveredHost(ip, None, Protocol.TCP, {"network.open_ports": open_ports})

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        started = time.monotonic()
        try:
            states = await self._scan(target.address, self._ports(target), min(target.timeout_sec, 2.0))
        except GateBlocked as exc:
            return self.blocked(target.address, exc)
        waited = round((time.monotonic() - started) * 1000, 2)
        open_ports = [s.port for s in states if s.state == "OPEN"]
        raw = {str(s.port): s.state for s in states}
        if open_ports:
            return self.result(target.address, ResultStatus.OK, {"network.open_ports": open_ports}, raw, waited)
        if any(s.state == "CLOSED" for s in states):
            return self.result(target.address, ResultStatus.REFUSED, {"network.open_ports": []}, raw, waited,
                               error_code="REFUSED", error_detail="Host answered, every checked port is closed")
        return self.result(target.address, ResultStatus.TIMEOUT, {}, raw, waited, error_code="TIMEOUT",
                           error_detail="No TCP answer on any checked port")

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query([]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query([]))
