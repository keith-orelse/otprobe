"""Modbus/TCP: Function 43 / MEI 14 Read Device Identification only. Every other function code (reads of
registers included) is refused before anything is written."""

from __future__ import annotations

import struct

from app.adapters.real.net._stream import Exchange
from app.adapters.real.net.gate import NetworkGate

ALLOWED_FUNCTIONS = frozenset({0x2B})
OBJECTS = {0x00: "vendor", 0x01: "product_code", 0x02: "revision", 0x03: "vendor_url", 0x04: "product_name",
           0x05: "model_name", 0x06: "application_name"}
EXCEPTIONS = {1: "illegal function (not supported)", 2: "illegal data address", 3: "illegal data value",
              4: "server device failure", 10: "gateway path unavailable", 11: "gateway target failed to respond"}


def _guard(frame: bytes) -> bool:
    return len(frame) >= 8 and frame[7] in ALLOWED_FUNCTIONS and frame[8:9] == b"\x0e"


def request(tid: int, unit: int, code: int, object_id: int) -> bytes:
    pdu = bytes([0x2B, 0x0E, code, object_id])
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


async def read_device_identification(gate: NetworkGate, ip: str, timeout_sec: float, port: int = 502,
                                     unit: int = 1) -> dict:
    """Returns {"objects": {...}, "conformity": int} or {"exception": text}. At most 4 requests in one session."""
    objects: dict[str, str] = {}
    conformity = None
    async with gate.permit(ip, "MODBUS_FC43_14"):
        async with Exchange(ip, port, timeout_sec, _guard) as ex:
            code, next_id = 0x01, 0x00          # basic stream first
            for tid in range(1, 5):
                await ex.send(request(tid, unit, code, next_id))
                header = await ex.read_exactly(7)
                _, _, length, _ = struct.unpack(">HHHB", header)
                pdu = await ex.read_exactly(length - 1)
                if pdu[0] & 0x80:
                    if objects:
                        break
                    return {"exception": EXCEPTIONS.get(pdu[1], f"exception {pdu[1]}")}
                conformity, more, next_id, count = pdu[3], pdu[4], pdu[5], pdu[6]
                pos = 7
                for _ in range(count):
                    oid, olen = pdu[pos], pdu[pos + 1]
                    value = pdu[pos + 2:pos + 2 + olen].decode(errors="replace")
                    objects[OBJECTS.get(oid, f"object_{oid:02x}")] = value
                    pos += 2 + olen
                if more == 0xFF:
                    continue
                if code == 0x01 and (conformity & 0x7F) >= 0x02:
                    code, next_id = 0x02, 0x00      # regular stream (product name, model name) if the device has it
                    continue
                break
    return {"objects": objects, "conformity": conformity}
