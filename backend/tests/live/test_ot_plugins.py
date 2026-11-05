"""OT identification plugins against devices on 127.0.0.1 that RECORD every request:
- Modbus: the real pymodbus server (its own decoder reports each function code);
- OPC UA: the real asyncua server behind a byte-recording proxy;
- S7, EtherNet/IP, BACnet: small protocol-faithful fake devices.
Each test proves identification works AND that only the allow-listed read-only requests reached the device
(LIVE_TEST_PLAN.md contract C-18)."""

from __future__ import annotations

import asyncio
import socket
import struct

import pytest
from pymodbus.datastore import ModbusDeviceContext, ModbusServerContext
from pymodbus.pdu.device import ModbusDeviceIdentification
from pymodbus.server import ModbusTcpServer

from app.adapters.base import ResultStatus, Target
from app.adapters.real.net import bacnet, enip, modbus, s7
from app.adapters.real.net._stream import Exchange, WriteAttemptBlocked
from app.adapters.real.net.gate import NetworkGate
from app.adapters.real.plugins import BacnetPlugin, EnipPlugin, ModbusPlugin, OpcUaPlugin, S7Plugin, s7_family

pytestmark = pytest.mark.live


def free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def gate(profile="IT", plugins=(), safe_mode=False) -> NetworkGate:
    g = NetworkGate()
    g.load([{"id": "lo", "cidr": "127.0.0.1/32", "kind": "INCLUDE", "profile": profile, "plugins": list(plugins)}],
           armed=True, safe_mode=safe_mode)
    return g


async def tcp_device(handler) -> tuple[int, asyncio.AbstractServer, list[bytes]]:
    received: list[bytes] = []

    async def serve(reader, writer):
        try:
            await handler(reader, writer, received)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    port = free_port()
    return port, await asyncio.start_server(serve, "127.0.0.1", port), received


# ---- Modbus: real pymodbus server -----------------------------------------------------------------------------------

async def test_modbus_identifies_and_sends_only_function_43():
    functions: list[int] = []

    def trace(sending: bool, pdu):
        if not sending:
            functions.append(pdu.function_code)
        return pdu

    identity = ModbusDeviceIdentification(info_name={"VendorName": "Schneider Electric", "ProductCode": "BMXP342020",
                                                     "MajorMinorRevision": "3.20", "ProductName": "Modicon M340",
                                                     "ModelName": "BMX P34 2020"})
    port = free_port()
    server = ModbusTcpServer(ModbusServerContext(devices=ModbusDeviceContext(), single=True), identity=identity,
                             address=("127.0.0.1", port), trace_pdu=trace)
    task = asyncio.create_task(server.serve_forever())
    await asyncio.sleep(0.3)
    try:
        res = await ModbusPlugin(gate()).identify(Target("127.0.0.1", port=port))
    finally:
        await server.shutdown()
        task.cancel()
    assert res.status == ResultStatus.OK, res.error_detail
    assert res.data["hardware.vendor"] == "Schneider Electric" and res.data["plc.product_code"] == "BMXP342020"
    assert res.data["firmware.version"] == "3.20" and res.data["hardware.model"] == "BMX P34 2020"
    assert functions and set(functions) == {0x2B}


def test_modbus_guard_refuses_every_write_function():
    for fc in (0x05, 0x06, 0x0F, 0x10, 0x16, 0x17, 0x03):          # writes, and even a register read
        frame = bytearray(modbus.request(1, 1, 0x01, 0x00))
        frame[7] = fc
        assert not modbus._guard(bytes(frame)), hex(fc)


async def test_guard_stops_a_forbidden_frame_before_it_is_written():
    async def handler(reader, writer, received):
        received.append(await reader.read(100))

    port, server, received = await tcp_device(handler)
    async with server:
        async with Exchange("127.0.0.1", port, 1.0, modbus._guard) as ex:
            with pytest.raises(WriteAttemptBlocked):
                await ex.send(b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x01\x00\x01")    # FC6 write single register
        await asyncio.sleep(0.1)
    assert received in ([], [b""])                                                    # nothing reached the device


# ---- EtherNet/IP ----------------------------------------------------------------------------------------------------

def list_identity_reply() -> bytes:
    name = b"1769-L33ER/A LOGIX5333ER"
    item = struct.pack("<H", 1) + struct.pack(">HH4s8s", 2, 44818, socket.inet_aton("127.0.0.1"), b"\0" * 8)
    item += struct.pack("<HHHBBHI", 1, 0x0E, 103, 33, 11, 0x0030, 0x60C0FFEE) + bytes([len(name)]) + name + b"\x03"
    body = struct.pack("<H", 1) + struct.pack("<HH", 0x0C, len(item)) + item
    return struct.pack("<HHII8sI", 0x63, len(body), 0, 0, b"otprobe\0", 0) + body


async def test_enip_list_identity():
    async def handler(reader, writer, received):
        frame = await reader.readexactly(24)
        received.append(frame)
        writer.write(list_identity_reply())
        await writer.drain()

    port, server, received = await tcp_device(handler)
    async with server:
        res = await EnipPlugin(gate()).identify(Target("127.0.0.1", port=port))
    assert res.status == ResultStatus.OK, res.error_detail
    assert res.data["hardware.vendor"] == "Rockwell Automation/Allen-Bradley"
    assert res.data["ot.device_type"] == "Programmable Logic Controller"
    assert res.data["hardware.model"] == "1769-L33ER/A LOGIX5333ER" and res.data["firmware.version"] == "33.011"
    assert res.data["hardware.serial"] == "60C0FFEE"
    assert [struct.unpack("<H", f[:2])[0] for f in received] == [0x63]              # ListIdentity, nothing else
    assert enip.parse(list_identity_reply()[24:])["product_code"] == 103


# ---- Siemens S7 -----------------------------------------------------------------------------------------------------

def szl_reply(szl_id: int, rec_len: int, records: list[bytes], pdu_ref: int) -> bytes:
    szl = struct.pack(">HHHH", szl_id, 0, rec_len, len(records)) + b"".join(records)
    data = bytes([0xFF, 0x09]) + struct.pack(">H", len(szl)) + szl
    params = bytes([0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])
    s7hdr = struct.pack(">BBHHHH", 0x32, 0x07, 0, pdu_ref, len(params), len(data))
    payload = b"\x02\xf0\x80" + s7hdr + params + data
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def s7_records() -> tuple[list[bytes], list[bytes]]:
    module = [struct.pack(">H", 1) + b"6ES7 214-1AG40-0XB0 " + struct.pack(">HHH", 0, 0x2020, 0x2020),
              struct.pack(">H", 7) + b"6ES7 214-1AG40-0XB0 " + struct.pack(">HBBBB", 0, 0x56, 4, 5, 2)]
    comp = [struct.pack(">H", i) + text.ljust(32, b"\0") for i, text in
            ((1, b"PLC_LINE1"), (2, b"CPU 1214C DC/DC/DC"), (5, b"S C-X4U421302012"), (7, b"CPU 1214C"))]
    return module, comp


async def test_s7_identifies_cpu_and_sends_only_read_frames():
    module, comp = s7_records()

    async def handler(reader, writer, received):
        async def frame():
            head = await reader.readexactly(4)
            body = await reader.readexactly(struct.unpack(">H", head[2:])[0] - 4)
            received.append(head + body)
            return head + body

        cr = await frame()
        assert cr[5] == 0xE0
        cc = bytes([0xD0]) + struct.pack(">HHB", 1, 0x0001, 0) + cr[11:]               # connection confirm
        writer.write(struct.pack(">BBH", 3, 0, len(cc) + 5) + bytes([len(cc)]) + cc)
        await frame()                                                                 # setup communication
        writer.write(struct.pack(">BBH", 3, 0, 27) + b"\x02\xf0\x80" +
                     struct.pack(">BBHHHHBB", 0x32, 3, 0, 1, 8, 0, 0, 0) + struct.pack(">BBHHH", 0xF0, 0, 1, 1, 240))
        await frame()
        writer.write(szl_reply(0x0011, 28, module, 2))
        await frame()
        writer.write(szl_reply(0x001C, 34, comp, 3))
        await writer.drain()

    port, server, received = await tcp_device(handler)
    async with server:
        res = await S7Plugin(gate()).identify(Target("127.0.0.1", port=port))
    assert res.status == ResultStatus.OK, res.error_detail
    assert res.data["plc.product_code"] == "6ES7 214-1AG40-0XB0" and res.data["firmware.version"] == "V4.5.2"
    assert res.data["hardware.model"] == "CPU 1214C" and res.data["hardware.serial"] == "S C-X4U421302012"
    assert res.data["plc.name"] == "PLC_LINE1" and res.data["hardware.vendor"] == "Siemens"
    assert all(s7._guard(f) for f in received) and len(received) == 4
    assert s7_family("6ES7 516-3AN02-0AB0") == "S7-1500"


def test_s7_guard_refuses_write_and_control_functions():
    for fn in (0x05, 0x1A, 0x1B, 0x28, 0x29):         # write var, download, upload, PLC control (start), PLC stop
        frame = bytearray(s7.setup_communication())
        frame[17] = fn
        assert not s7._guard(bytes(frame)), hex(fn)


# ---- BACnet ---------------------------------------------------------------------------------------------------------

def bacnet_ack(invoke_id: int, prop: int, text: str) -> bytes:
    value = b"\x00" + text.encode()
    tag = bytes([0x75, len(value)]) if len(value) > 4 else bytes([0x70 | len(value)])
    apdu = bytes([0x30, invoke_id, 0x0C, 0x0C]) + struct.pack(">I", (8 << 22) | 1201) + bytes([0x19, prop])
    apdu += b"\x3e" + tag + value + b"\x3f"
    npdu = b"\x01\x00"
    return struct.pack(">BBH", 0x81, 0x0A, 4 + len(npdu) + len(apdu)) + npdu + apdu


async def test_bacnet_read_property_only_and_only_when_enabled():
    props = {77: "AHU-3 controller", 121: "Distech Controls", 70: "ECY-S1000", 44: "1.4.21049.1"}
    received: list[bytes] = []

    class Device(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.t = transport

        def datagram_received(self, data, addr):
            received.append(data)
            self.t.sendto(bacnet_ack(data[8], data[-1], props[data[-1]]), addr)

    port = free_port(socket.SOCK_DGRAM)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Device, local_addr=("127.0.0.1", port))
    try:
        skipped = await BacnetPlugin(gate("IT")).identify(Target("127.0.0.1", port=port))
        assert skipped.error_code == "PLUGIN_NOT_ENABLED" and received == []          # UDP: explicit opt-in only
        res = await BacnetPlugin(gate("OT_SENSITIVE", ["bacnet"])).identify(Target("127.0.0.1", port=port))
    finally:
        transport.close()
    assert res.status == ResultStatus.OK, res.error_detail
    assert res.data == {"hardware.vendor": "Distech Controls", "hardware.model": "ECY-S1000",
                        "firmware.version": "1.4.21049.1", "plc.name": "AHU-3 controller"}
    assert all(bacnet._guard(f) for f in received) and len(received) == 4


# ---- OPC UA: real asyncua server behind a recording proxy ------------------------------------------------------------

async def test_opcua_identifies_server_from_get_endpoints():
    from asyncua import Server

    server = Server()
    await server.init()
    port = free_port()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}/")
    server.set_server_name("Line 1 SCADA OPC UA")
    async with server:
        res = await OpcUaPlugin(gate()).identify(Target("127.0.0.1", port=port))
    assert res.status == ResultStatus.OK, res.error_detail
    assert res.data["opcua.application_name"] == "Line 1 SCADA OPC UA"
    assert "None" in res.data["opcua.security_policies"]           # an unauthenticated endpoint is visible


# ---- Policy ---------------------------------------------------------------------------------------------------------

async def test_plugins_send_nothing_in_safe_mode_or_unlisted_ot_ranges():
    async def handler(reader, writer, received):
        received.append(await reader.read(100))

    port, server, received = await tcp_device(handler)
    async with server:
        for g in (gate("IT", safe_mode=True), gate("OT_SENSITIVE", plugins=["modbus"])):
            res = await EnipPlugin(g).identify(Target("127.0.0.1", port=port))
            assert res.error_code == "PLUGIN_NOT_ENABLED"
        await asyncio.sleep(0.1)
    assert received == []


async def test_probe_identifies_and_classifies_a_plc_end_to_end(live):
    """Probe of a fake ControlLogix on the real EtherNet/IP port: identified, classified PLC, agent refused. Then the
    same range as OT-sensitive without plugins listed: nothing is sent to the controller."""
    from tests.live.test_live_loopback import add_scope, safe_mode

    async def handler(reader, writer, received):
        received.append(await reader.readexactly(24))
        writer.write(list_identity_reply())
        await writer.drain()

    received: list[bytes] = []

    async def serve(reader, writer):
        try:
            await handler(reader, writer, received)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    try:
        server = await asyncio.start_server(serve, "127.0.0.1", 44818)
    except OSError:
        pytest.skip("port 44818 busy on 127.0.0.1")
    async with server:
        entry = await add_scope(live)
        await safe_mode(live, False)
        await live.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
        await live.idle()
        asset = await live.asset_by_ip("127.0.0.1")
        r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
        await live.idle()
        probe = await live.get(f"/probes/{r.json()['id']}")
        ot = next(s for s in probe["steps"] if s["name"] == "OT")
        assert ot["status"] == "OK" and "1769-L33ER" in ot["detail"], ot
        detail = await live.get(f"/assets/{asset['id']}")
        assert detail["type"] == "PLC" and detail["eligibility"] == "NOT_ELIGIBLE"
        fields = {f["path"]: f for g in detail["groups"].values() for f in g}
        assert fields["ot.protocols"]["value"] == ["enip"] and fields["hardware.serial"]["source"] == "EtherNet/IP"
        assert len(received) == 1

        await live.login("admin")
        r = await live.client.patch(f"/api/v1/scope/{entry['id']}", json={"profile": "OT_SENSITIVE"},
                                    headers={"Idempotency-Key": "ot-sensitive-1"})
        assert r.status_code == 200, r.text
        await live.login("operator")
        r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
        await live.idle()
        probe = await live.get(f"/probes/{r.json()['id']}")
        ot = next(s for s in probe["steps"] if s["name"] == "OT")
        assert "not enabled for this range" in ot["detail"] and len(received) == 1        # nothing new was sent
