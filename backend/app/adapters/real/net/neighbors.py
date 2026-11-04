"""Read the kernel's neighbour (ARP) cache. Sends nothing: earlier ICMP/TCP sweeps make the kernel resolve every
local-segment address it talked to, and this reads the answers."""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

_BSD_LINE = re.compile(r"\((?P<ip>[0-9.]+)\) at (?P<mac>[0-9a-fA-F:]+) on (?P<iface>\S+)")


def normalize_mac(mac: str) -> str:
    return ":".join(part.zfill(2) for part in mac.split(":")).upper()


def _parse_proc(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) >= 6 and cols[2] != "0x0" and cols[3] != "00:00:00:00:00:00":
            out[cols[0]] = normalize_mac(cols[3])
    return out


def _parse_bsd(text: str) -> dict[str, str]:
    out = {}
    for m in _BSD_LINE.finditer(text):
        mac = normalize_mac(m["mac"])
        if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
            out[m["ip"]] = mac
    return out


async def read_table() -> dict[str, str]:
    """{ip: MAC} for every complete entry."""
    proc_file = Path("/proc/net/arp")
    if proc_file.exists():
        return _parse_proc(proc_file.read_text())
    if sys.platform == "darwin" or "bsd" in sys.platform:
        proc = await asyncio.create_subprocess_exec("arp", "-an", stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.DEVNULL)
        stdout, _ = await asyncio.wait_for(proc.communicate(), 10)
        return _parse_bsd(stdout.decode(errors="replace"))
    return {}


def shared_macs(table: dict[str, str]) -> dict[str, int]:
    """MACs that answer for more than one IP: a router doing proxy ARP (Wi-Fi client isolation, firewalls, some
    industrial switches). Such a MAC identifies the box that answered, not the device at that IP."""
    counts: dict[str, int] = {}
    for mac in table.values():
        counts[mac] = counts.get(mac, 0) + 1
    return {mac: n for mac, n in counts.items() if n > 1}
