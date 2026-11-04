"""Shared helpers for real adapters: result building, target expansion and gated concurrent sweeps."""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, AsyncIterator, Awaitable, Callable, TypeVar

from app.adapters.base import AdapterDescriptor, AdapterResult, Protocol, ResultStatus, Target
from app.adapters.real.net.gate import MESSAGES, GateBlocked, NetworkGate
from app.core.clock import utcnow

T = TypeVar("T")
MAX_SWEEP_HOSTS = 65_536
SWEEP_CONCURRENCY = 64    # tasks in flight; the gate's rate limits decide the real pace


class RealAdapterMixin:
    protocol: Protocol
    implementation: str
    label: str

    def __init__(self, gate: NetworkGate) -> None:
        self.gate = gate

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(self.protocol, self.implementation, False, self.label)

    def result(self, target: str, status: ResultStatus, data: dict[str, Any] | None = None,
               raw: dict[str, Any] | None = None, latency_ms: float | None = None, error_code: str | None = None,
               error_detail: str | None = None) -> AdapterResult:
        return AdapterResult(protocol=self.protocol, target=target, status=status, data=data or {}, raw=raw or {},
                             latency_ms=latency_ms if latency_ms is not None else 0.0, collected_at=utcnow(),
                             error_code=error_code, error_detail=error_detail)

    def blocked(self, target: str, exc: GateBlocked) -> AdapterResult:
        return self.result(target, ResultStatus.BLOCKED, error_code=exc.reason.upper().replace("-", "_"),
                           error_detail=MESSAGES.get(exc.reason, exc.reason))


def expand(target: Target) -> list[str]:
    """Hosts to visit: ``options["hosts"]`` when the engine restricts the sweep, else every host in the CIDR."""
    hosts = target.options.get("hosts")
    if hosts is not None:
        net = ipaddress.ip_network(target.address, strict=False)
        return [h for h in hosts if ipaddress.ip_address(h) in net]
    net = ipaddress.ip_network(target.address, strict=False)
    if net.num_addresses > MAX_SWEEP_HOSTS:
        raise ValueError(f"{target.address} is larger than {MAX_SWEEP_HOSTS} addresses")
    if net.num_addresses <= 2:            # /31, /32 (and IPv6 equivalents): every address is a host
        return [str(a) for a in net]
    return [str(a) for a in net.hosts()]


async def sweep(gate: NetworkGate, hosts: list[str], fn: Callable[[str], Awaitable[T]]) -> AsyncIterator[tuple[str, T]]:
    """Run ``fn`` per in-scope host with bounded concurrency; yield (host, result) as each finishes.
    Hosts the gate refuses are skipped (and counted by the gate). The kill switch, or any unexpected error (for
    example no permission to send ICMP), stops the sweep and is raised to the engine, which fails the job."""
    allowed = [h for h in hosts if gate.decide(h).allowed]
    for h in hosts:
        if h not in allowed:
            gate.count_blocked(gate.decide(h).reason)
    queue: asyncio.Queue = asyncio.Queue()
    sem = asyncio.Semaphore(SWEEP_CONCURRENCY)

    async def one(h: str) -> None:
        async with sem:
            try:
                await queue.put((h, await fn(h), None))
            except Exception as exc:  # noqa: BLE001 - handed to the consumer, which decides
                await queue.put((h, None, exc))

    tasks = [asyncio.create_task(one(h)) for h in allowed]
    try:
        for _ in tasks:
            h, value, exc = await queue.get()
            if exc is not None:
                if isinstance(exc, GateBlocked) and exc.reason != "kill-switch":
                    continue
                raise exc
            yield h, value
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
