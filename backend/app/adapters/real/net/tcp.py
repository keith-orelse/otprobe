"""TCP connect check: full handshake, then a clean close (FIN). No payload is ever written."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from app.adapters.real.net.gate import NetworkGate


@dataclass(frozen=True)
class PortState:
    port: int
    state: str                 # OPEN | CLOSED | FILTERED
    rtt_ms: float | None = None


async def connect(gate: NetworkGate, ip: str, port: int, timeout_sec: float) -> PortState:
    async with gate.permit(ip, "TCP_CONNECT"):
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout_sec)
        except ConnectionRefusedError:
            return PortState(port, "CLOSED")
        except (asyncio.TimeoutError, OSError):
            return PortState(port, "FILTERED")
        rtt = round((loop.time() - started) * 1000, 2)
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        return PortState(port, "OPEN", rtt)


async def read_banner(gate: NetworkGate, ip: str, port: int, timeout_sec: float, max_bytes: int = 256
                      ) -> tuple[PortState, str | None]:
    """Connect and read what the server volunteers (e.g. 'SSH-2.0-OpenSSH_9.6'). Nothing is ever written."""
    async with gate.permit(ip, "TCP_BANNER"):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout_sec)
        except ConnectionRefusedError:
            return PortState(port, "CLOSED"), None
        except (asyncio.TimeoutError, OSError):
            return PortState(port, "FILTERED"), None
        try:
            line = await asyncio.wait_for(reader.readline(), timeout_sec)
            banner = line[:max_bytes].decode(errors="replace").strip() or None
        except (asyncio.TimeoutError, OSError):
            banner = None
        finally:
            writer.close()
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), 1.0)
        return PortState(port, "OPEN"), banner
