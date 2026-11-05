"""Fake industrial devices for manual testing of the OT plugins (phase L3) on 127.0.0.1 only.

  * Modbus/TCP on port 502  : a real pymodbus server identifying as a Schneider Modicon M340
  * EtherNet/IP on port 44818: answers ListIdentity as an Allen-Bradley CompactLogix

Every request that arrives is printed, so you can see that OTProbe sends only read-only identification requests
(Modbus function 0x2B, EtherNet/IP command 0x63). Stop with Ctrl+C.

Run from the repository root:
    backend/.venv/bin/python scripts/lab_devices.py
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import warnings
from datetime import datetime

warnings.filterwarnings("ignore")             # pymodbus prints v4 deprecation notices on import

from pymodbus.datastore import ModbusDeviceContext, ModbusServerContext
from pymodbus.pdu.device import ModbusDeviceIdentification
from pymodbus.server import ModbusTcpServer

HOST = "127.0.0.1"
MODBUS_INTERNAL = 15020     # the pymodbus server itself listens here, loopback only
MODBUS_NAMES = {0x2B: "Read Device Identification (read-only)", 0x03: "Read Holding Registers",
                0x05: "WRITE single coil", 0x06: "WRITE single register", 0x10: "WRITE multiple registers"}


def log(device: str, text: str) -> None:
    print(f"{datetime.now():%H:%M:%S}  [{device}]  {text}", flush=True)


def list_identity_reply() -> bytes:
    name = b"1769-L33ER/A LOGIX5333ER"
    item = struct.pack("<H", 1) + struct.pack(">HH4s8s", 2, 44818, socket.inet_aton(HOST), b"\0" * 8)
    item += struct.pack("<HHHBBHI", 1, 0x0E, 103, 33, 11, 0x0030, 0x60C0FFEE) + bytes([len(name)]) + name + b"\x03"
    body = struct.pack("<H", 1) + struct.pack("<HH", 0x0C, len(item)) + item
    return struct.pack("<HHII8sI", 0x63, len(body), 0, 0, b"otprobe\0", 0) + body


async def enip_device(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        header = await asyncio.wait_for(reader.readexactly(24), 5)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        log("EtherNet/IP", f"connection from {peer[0]} with no request (a port check)")
        writer.close()
        return
    command = struct.unpack("<H", header[:2])[0]
    log("EtherNet/IP", f"request from {peer[0]}: command 0x{command:04X}"
                       f"{' = ListIdentity (read-only)' if command == 0x63 else '  <-- NOT ListIdentity'}")
    if command == 0x63:
        writer.write(list_identity_reply())
        await writer.drain()
    writer.close()


async def modbus_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Port 502 must be bound on all interfaces on macOS (a normal user cannot bind it on 127.0.0.1), so this relay
    refuses every peer except this machine itself and forwards to the loopback-only Modbus server."""
    peer = writer.get_extra_info("peername")[0]
    if peer not in ("127.0.0.1", "::1"):
        log("Modbus", f"refused a connection from {peer} (lab device answers this Mac only)")
        writer.close()
        return
    try:
        up_r, up_w = await asyncio.open_connection(HOST, MODBUS_INTERNAL)
    except OSError:
        writer.close()
        return

    async def pipe(src, dst):
        try:
            while data := await src.read(4096):
                dst.write(data)
                await dst.drain()
        except ConnectionError:
            pass
        finally:
            dst.close()

    await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))


async def main() -> None:
    def trace(sending: bool, pdu):
        if not sending:
            name = MODBUS_NAMES.get(pdu.function_code, "other")
            flag = "" if pdu.function_code == 0x2B else "  <-- NOT a read-only identification request"
            log("Modbus", f"request: function 0x{pdu.function_code:02X} = {name}{flag}")
        return pdu

    identity = ModbusDeviceIdentification(info_name={
        "VendorName": "Schneider Electric", "ProductCode": "BMXP342020", "MajorMinorRevision": "3.20",
        "ProductName": "Modicon M340", "ModelName": "BMX P34 2020"})
    modbus = ModbusTcpServer(ModbusServerContext(devices=ModbusDeviceContext(), single=True), identity=identity,
                             address=(HOST, MODBUS_INTERNAL), trace_pdu=trace)
    relay = await asyncio.start_server(modbus_relay, "0.0.0.0", 502)
    enip = await asyncio.start_server(enip_device, HOST, 44818)
    log("lab", "Modbus device (Schneider M340) on port 502 (answers this Mac only)")
    log("lab", f"EtherNet/IP device (Allen-Bradley CompactLogix) on {HOST}:44818")
    log("lab", "waiting for OTProbe... (Ctrl+C to stop)")
    async with enip, relay:
        await modbus.serve_forever()


if __name__ == "__main__":
    logging.getLogger("pymodbus").setLevel(logging.ERROR)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
    except (PermissionError, OSError) as exc:
        print(f"Could not open the lab ports ({exc}). Is another copy already running?")
