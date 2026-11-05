"""BACnet/IP: confirmed ReadProperty on the Device object, using the wildcard instance 4194303 ("the device I am
talking to"), for four identity properties. No Who-Is broadcast, no WriteProperty, no DeviceCommunicationControl,
no ReinitializeDevice: the frame guard allows service choice 0x0C (ReadProperty) only."""

from __future__ import annotations

import asyncio
import struct

from app.adapters.real.net.gate import NetworkGate

READ_PROPERTY = 0x0C
DEVICE_WILDCARD = (8 << 22) | 4194303
PROPERTIES = {77: "object_name", 121: "vendor_name", 70: "model_name", 44: "firmware_revision"}


def _guard(frame: bytes) -> bool:
    # BVLC(4) NPDU(2) APDU: confirmed request, service choice at APDU offset 3
    return len(frame) > 9 and frame[0] == 0x81 and frame[6] & 0xF0 == 0x00 and frame[9] == READ_PROPERTY


def read_property(invoke_id: int, prop: int) -> bytes:
    apdu = bytes([0x00, 0x05, invoke_id, READ_PROPERTY]) + b"\x0c" + struct.pack(">I", DEVICE_WILDCARD)
    apdu += bytes([0x19, prop])
    npdu = b"\x01\x04"                                            # version 1, expecting reply
    return struct.pack(">BBH", 0x81, 0x0A, 4 + len(npdu) + len(apdu)) + npdu + apdu


def parse_string(reply: bytes) -> str | None:
    """Character-string value from a ReadProperty ComplexACK, or None (error / reject / other type)."""
    if len(reply) < 6 or reply[0] != 0x81:
        return None
    npdu = reply[4:]
    pos = 2
    if npdu[1] & 0x20:                                            # DNET, DLEN, DADR (+ hop count below)
        pos += 3 + npdu[pos + 2]
    if npdu[1] & 0x08:                                            # SNET, SLEN, SADR (reply came through a router)
        pos += 3 + npdu[pos + 2]
    if npdu[1] & 0x20:
        pos += 1
    apdu = npdu[pos:]
    if not apdu or apdu[0] & 0xF0 != 0x30 or apdu[2] != READ_PROPERTY:
        return None
    i = apdu.index(0x3E) + 1                                      # opening tag 3
    tag = apdu[i]
    if tag >> 4 != 7:                                             # application tag 7: character string
        return None
    length = tag & 0x07
    i += 1
    if length == 5:
        length = apdu[i]
        i += 1
    return apdu[i + 1:i + length].decode("utf-8", errors="replace")   # first byte: character set


class _Client(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.replies: asyncio.Queue = asyncio.Queue()

    def datagram_received(self, data, addr) -> None:
        self.replies.put_nowait(data)


async def identify(gate: NetworkGate, ip: str, timeout_sec: float, port: int = 47808) -> dict:
    out: dict = {}
    async with gate.permit(ip, "BACNET_READ_PROPERTY"):
        loop = asyncio.get_running_loop()
        transport, client = await loop.create_datagram_endpoint(_Client, remote_addr=(ip, port))
        try:
            for invoke_id, (prop, key) in enumerate(PROPERTIES.items(), start=1):
                frame = read_property(invoke_id, prop)
                if not _guard(frame):
                    raise RuntimeError("BACnet frame guard refused a frame")
                transport.sendto(frame)
                try:
                    value = parse_string(await asyncio.wait_for(client.replies.get(), timeout_sec))
                except asyncio.TimeoutError:
                    break                                         # no BACnet device here: stop after one try
                if value is not None:
                    out[key] = value
        finally:
            transport.close()
    return out
