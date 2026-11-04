"""ICMP echo through icmplib. Tries unprivileged datagram sockets first (Linux needs net.ipv4.ping_group_range),
then raw sockets (CAP_NET_RAW)."""

from __future__ import annotations

from dataclasses import dataclass

import icmplib

from app.adapters.real.net.gate import NetworkGate

_privileged: bool | None = None   # learned on first use


@dataclass(frozen=True)
class EchoReply:
    alive: bool
    rtt_ms: float | None


async def echo(gate: NetworkGate, ip: str, timeout_sec: float) -> EchoReply:
    global _privileged
    async with gate.permit(ip, "ICMP_ECHO"):
        modes = [_privileged] if _privileged is not None else [False, True]
        last: Exception | None = None
        for privileged in modes:
            try:
                host = await icmplib.async_ping(ip, count=1, timeout=timeout_sec, privileged=privileged)
            except icmplib.SocketPermissionError as exc:
                last = exc
                continue
            _privileged = privileged
            return EchoReply(host.is_alive, round(host.avg_rtt, 2) if host.is_alive else None)
        raise PermissionError("ICMP needs net.ipv4.ping_group_range or CAP_NET_RAW") from last
