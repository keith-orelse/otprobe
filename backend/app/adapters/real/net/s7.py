"""Siemens S7comm: COTP connect, S7 setup communication, then SZL reads (0x0011 module identification, 0x001C
component identification). Nothing else can be sent: write-var, download, PLC stop/start, block functions are all
refused by the frame guard. One short session; it uses one of the CPU's connection resources for about a second."""

from __future__ import annotations

import struct

from app.adapters.real.net._stream import Exchange
from app.adapters.real.net.gate import NetworkGate

COTP_CR, COTP_DT = 0xE0, 0xF0
ROSCTR_JOB, ROSCTR_USERDATA = 0x01, 0x07
FN_SETUP = 0xF0
REMOTE_TSAPS = (0x0102, 0x0101, 0x0100)     # rack 0 slot 2 (S7-300/400), slot 1 (S7-1200/1500), slot 0
COMPONENT_IDS = {1: "plc_name", 2: "module_name", 3: "plant_id", 5: "serial", 7: "module_type"}


def _tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def cotp_connect(remote_tsap: int) -> bytes:
    params = b"\xc0\x01\x0a" + b"\xc1\x02\x01\x00" + b"\xc2\x02" + struct.pack(">H", remote_tsap)
    body = bytes([COTP_CR]) + struct.pack(">HHB", 0, 1, 0) + params
    return _tpkt(bytes([len(body)]) + body)


def _s7(header_rosctr: int, pdu_ref: int, params: bytes, data: bytes = b"") -> bytes:
    hdr = struct.pack(">BBHHHH", 0x32, header_rosctr, 0, pdu_ref, len(params), len(data))
    return _tpkt(b"\x02\xf0\x80" + hdr + params + data)


def setup_communication() -> bytes:
    return _s7(ROSCTR_JOB, 1, struct.pack(">BBHHH", FN_SETUP, 0, 1, 1, 480))


def read_szl(szl_id: int, index: int, pdu_ref: int) -> bytes:
    params = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00])   # userdata: CPU functions, read SZL
    data = bytes([0xFF, 0x09]) + struct.pack(">HHH", 4, szl_id, index)
    return _s7(ROSCTR_USERDATA, pdu_ref, params, data)


def _guard(frame: bytes) -> bool:
    """Allow exactly: COTP connection request, S7 setup communication, S7 userdata read-SZL."""
    if len(frame) < 7 or frame[0] != 3:
        return False
    if frame[5] == COTP_CR:
        return True
    if frame[5] != COTP_DT or len(frame) < 19 or frame[7] != 0x32:
        return False
    rosctr, param_start = frame[8], 17
    if rosctr == ROSCTR_JOB:
        return frame[param_start] == FN_SETUP
    if rosctr == ROSCTR_USERDATA:
        return frame[param_start + 5] == 0x44 and frame[param_start + 6] == 0x01   # CPU functions / read SZL
    return False


async def _read_tpkt(ex: Exchange) -> bytes:
    head = await ex.read_exactly(4)
    return await ex.read_exactly(struct.unpack(">H", head[2:4])[0] - 4)


def _szl_records(tpkt_payload: bytes) -> tuple[int, list[bytes], bytes]:
    """Returns (record length, records, raw SZL data) from a read-SZL response."""
    s7 = tpkt_payload[3:]                      # skip COTP DT header
    param_len, data_len = struct.unpack(">HH", s7[6:10])
    data = s7[10 + param_len:10 + param_len + data_len]
    if len(data) < 12 or data[0] != 0xFF:
        return 0, [], b""
    szl = data[4:]                             # return code, transport size, length
    rec_len, count = struct.unpack(">HH", szl[4:8])
    body = szl[8:8 + rec_len * count]
    return rec_len, [body[i * rec_len:(i + 1) * rec_len] for i in range(count)], szl[8:]


def _text(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", errors="replace").strip()


async def identify(gate: NetworkGate, ip: str, timeout_sec: float, port: int = 102) -> dict:
    async with gate.permit(ip, "S7_SZL_READ"):
        for tsap in REMOTE_TSAPS:
            async with Exchange(ip, port, timeout_sec, _guard) as ex:
                await ex.send(cotp_connect(tsap))
                cc = await _read_tpkt(ex)
                if len(cc) < 2 or cc[1] != 0xD0:          # connection confirm
                    continue
                await ex.send(setup_communication())
                await _read_tpkt(ex)
                out: dict = {"tsap": f"0x{tsap:04X}"}
                await ex.send(read_szl(0x0011, 0x0000, 2))
                _, records, raw = _szl_records(await _read_tpkt(ex))
                if records:
                    out["order_code"] = _text(records[0][2:22])
                    if len(raw) >= 3:
                        out["firmware"] = f"V{raw[-3]}.{raw[-2]}.{raw[-1]}"
                await ex.send(read_szl(0x001C, 0x0000, 3))
                _, records, _ = _szl_records(await _read_tpkt(ex))
                for rec in records:
                    key = COMPONENT_IDS.get(struct.unpack(">H", rec[:2])[0]) if len(rec) >= 2 else None
                    if key:
                        out[key] = _text(rec[2:])
                return out
    return {}
