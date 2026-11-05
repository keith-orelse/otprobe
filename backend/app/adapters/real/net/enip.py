"""EtherNet/IP: encapsulation command 0x63 ListIdentity only. No RegisterSession, no CIP messages, no tag reads."""

from __future__ import annotations

import struct

from app.adapters.real.net._stream import Exchange
from app.adapters.real.net.gate import NetworkGate

LIST_IDENTITY = 0x0063
VENDORS = {1: "Rockwell Automation/Allen-Bradley", 47: "Omron"}
DEVICE_TYPES = {0x02: "AC Drive", 0x07: "General Purpose Discrete I/O", 0x0C: "Communications Adapter",
                0x0E: "Programmable Logic Controller", 0x18: "Human-Machine Interface"}


def _guard(frame: bytes) -> bool:
    return len(frame) == 24 and struct.unpack("<H", frame[:2])[0] == LIST_IDENTITY


def request() -> bytes:
    return struct.pack("<HHII8sI", LIST_IDENTITY, 0, 0, 0, b"otprobe\x00", 0)


def parse(body: bytes) -> dict:
    count = struct.unpack("<H", body[:2])[0]
    if count < 1:
        return {}
    item_type, _ = struct.unpack("<HH", body[2:6])
    if item_type != 0x0C:
        return {}
    p = body[6:]
    vendor, dtype, product_code, rev_major, rev_minor, status, serial = struct.unpack("<HHHBBHI", p[18:32])
    name_len = p[32]
    return {"vendor_id": vendor, "vendor": VENDORS.get(vendor, f"vendor id {vendor}"), "device_type_id": dtype,
            "device_type": DEVICE_TYPES.get(dtype, f"device type {dtype}"), "product_code": product_code,
            "revision": f"{rev_major}.{rev_minor:03d}", "serial": f"{serial:08X}", "status": status,
            "product_name": p[33:33 + name_len].decode(errors="replace")}


async def list_identity(gate: NetworkGate, ip: str, timeout_sec: float, port: int = 44818) -> dict:
    async with gate.permit(ip, "ENIP_LIST_IDENTITY"):
        async with Exchange(ip, port, timeout_sec, _guard) as ex:
            await ex.send(request())
            header = await ex.read_exactly(24)
            command, length = struct.unpack("<HH", header[:4])
            body = await ex.read_exactly(length) if length else b""
    return parse(body) if command == LIST_IDENTITY else {}
