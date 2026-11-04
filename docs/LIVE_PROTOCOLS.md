# Real adapters and OT protocol plugins

The interfaces in [`backend/app/adapters/base.py`](../backend/app/adapters/base.py) do not change. Engines keep
calling `registry.get(Protocol.X)`. This document defines the real implementations behind those interfaces and a
new plugin interface for OT protocols. All network access goes through the network gate
([SAFETY_AND_SCOPE.md](SAFETY_AND_SCOPE.md) §6).

## 1. Device coverage: three tiers

| Tier | Devices | How OTProbe sees them | Depth |
|---|---|---|---|
| **1. Agent** | Windows 10/11, Server 2016–2025; Windows 7/8.1, Server 2008 R2/2012 (legacy build); Linux on x86, x86-64, ARM, ARM64; macOS (optional) | Discovery + agentless + **Go agent** | Full baseline assessment |
| **2. Agentless host** | Windows XP/2003, vendor-locked HMIs, appliances, hosts where an agent is not allowed | Discovery + WinRM/WMI, SSH or SNMP | Partial assessment. Rules without evidence report UNKNOWN |
| **3. Field and network devices** | PLCs, RTUs, drives, I/O, switches, routers, gateways, sensors | Discovery + SNMP + **read-only protocol plugins** | Identity (vendor, model, firmware, serial), exposure (open services), network rules |

A device that matches nothing is still discovered (IP, MAC, MAC vendor, open ports) and listed as
`Unknown device`.

## 2. Real adapters

| Adapter | Library / mechanism | Discovery behaviour | Probe query groups | Notes |
|---|---|---|---|---|
| **ICMP** | `icmplib` (unprivileged datagram sockets; falls back to raw with `CAP_NET_RAW`) | Echo sweep of the CIDR at the profile's rate | `echo` | No reply means `BLOCKED`, **not** offline (as in the POC) |
| **ARP** | **L2:** reads the kernel neighbour table (`/proc/net/arp`, or `arp -an` on macOS) after the ICMP sweep, which makes the kernel resolve every local address it touched. Sends nothing itself. **Later:** router/switch ARP tables over SNMP (`IP-MIB::ipNetToPhysicalTable`) for remote subnets | Yields IP + MAC for every local neighbour | `neighbor` | ARP does not cross routers: remote hosts are found by ICMP/TCP and listed without a MAC |
| **TCP** (new) | `asyncio` connect via the gate, then a clean FIN close. No SYN scanning, no banner probes on OT ports | Port list per profile (§3) | `ports` | Feeds `network.open_ports[]` and the plugin selection |
| **SNMP** | `pysnmp` (lextudio, asyncio). v3 authPriv (SHA-256/AES-128) by default, v2c only with an explicit profile (`params.version: 2c`). `params.port` for agents on a non-standard port | `sysObjectID` / `sysDescr` GET on responders | `system`, `interfaces`, `entity`, `lldp`, `arp_table` | GET / GETNEXT / GETBULK only. **No SET**: the SNMP adapter has no code path that builds a SetRequest |
| **WinRM** | `pypsrp` over HTTPS 5986 (NTLM, Kerberos, or certificate auth). HTTP 5985 only if a profile allows it, with NTLM message encryption | — | `session` | Stages unchanged: `CONNECTING, TCP_OK, TLS_VALIDATED, AUTH_OK, SESSION_CREATED`. Each `RemoteOperation` maps to one script in `backend/app/adapters/real/winrm_scripts/` |
| **WMI/CIM** | `Get-CimInstance` (`Get-WmiObject` on PowerShell 2.0) over the WinRM session | — | `os`, `hardware`, `firewall`, `antivirus`, `software`, `services`, `hotfixes`, `network` | No DCOM / `impacket` |
| **SSH** | `asyncssh`, host key pinned on first use (TOFU, audited) or pre-loaded | — | `identity`, `os`, `packages`, `services`, `firewall` | Read-only commands from a fixed list. `sudo` only for the install/uninstall scripts |
| **MQTT** | `aiomqtt` against the bundled Mosquitto | — | — | Subscribe only. See [MQTT_BROKER.md](MQTT_BROKER.md) |
| **Package transfer** | PULL: target downloads over HTTPS with a one-time token. PUSH: chunked copy over the WinRM (base64, 512 KiB) or SSH (SFTP) session | — | — | Progress callback contract C-15 unchanged |
| **Vault** | Local Fernet-encrypted vault in the OTProbe DB, write-only API | — | — | Pluggable later: HashiCorp Vault, CyberArk |

## 3. Port lists

The TCP adapter never sends payload. These lists only decide which plugins to try and what to show as "exposed
services".

| Group | Ports | In `OT_SENSITIVE` profile |
|---|---|---|
| Remote management | 22 SSH, 23 Telnet, 3389 RDP, 5900 VNC, 5985/5986 WinRM | yes |
| Windows | 135 RPC, 139/445 SMB | yes |
| Web | 80, 443, 8080, 8443 | yes |
| Industrial | 102 S7comm, 502 Modbus, 4840 OPC UA, 20000 DNP3, 2404 IEC 104, 44818 EtherNet/IP, 1911/4911 Fox, 9600 FINS, 18245 GE SRTP | yes, **connect only** |
| Messaging | 1883 MQTT, 8883 MQTTS | yes |
| UDP (probe only via plugins) | 161 SNMP, 47808 BACnet, 2222 ENIP implicit, 44818 ENIP ListIdentity | via plugin only |

## 4. OT protocol plugins

### 4.1 Interface

```python
class OtProtocolPlugin(Protocol):
    name: str                       # "modbus"
    display_label: str              # "Modbus TCP (read device ID)"
    ports: list[PortSpec]           # [PortSpec(502, "tcp")]
    risk: Literal["LOW", "MEDIUM"]  # HIGH-risk protocols are not allowed as active plugins
    allowed_ops: frozenset[str]     # e.g. {"MODBUS_FC43_14"}: the gate refuses anything else

    async def identify(self, target: Target, gate: NetworkGate, timeout_sec: float) -> AdapterResult
```

- A plugin runs only if (a) its port answered the TCP connect (or, for UDP, the scope entry enables it),
  (b) the scope entry enables the plugin, and (c) safe mode is off.
- One plugin run is **one short session**: connect, one or two read requests, close. No polling, no subscriptions.
- A per-device cooldown (default 10 min) stops repeated probes of the same controller.
- `identify` returns normalised fields: `hardware.vendor`, `hardware.model`, `hardware.serial`,
  `firmware.version`, `plc.product_code`, `plc.mode` (only if read-only), `ot.protocols[]`.
- Adding a protocol means adding one module under `app/adapters/real/plugins/`, plus a provenance entry and
  classification signals in `rules/classification.yaml`. The engines do not change.

### 4.2 Plugins in scope (L3)

| Plugin | Covers (examples) | Exactly what is sent | Library | Risk |
|---|---|---|---|---|
| `modbus` | Schneider Modicon/M-series, Wago, many gateways and meters | Function 43 / MEI type 14 *Read Device Identification* (basic objects 0x00–0x02, then regular 0x03–0x06 if supported) | `pymodbus` client, with a function-code allowlist enforced in a wrapper | LOW |
| `s7` | Siemens S7-300/400/1200/1500, ET200 CPUs | COTP connect → S7 setup communication → SZL read 0x0011 (module ID) and 0x001C (component ID) → disconnect | Small pure-Python S7comm reader (no `snap7` native dependency) | MEDIUM: uses one of the CPU's limited connection slots for about 1 s |
| `enip` | Rockwell / Allen-Bradley ControlLogix, CompactLogix, Micro800; Omron; many drives | EtherNet/IP `ListIdentity` (encapsulation command 0x63). No CIP session, no tag reads | Own ~80-line encoder | LOW |
| `bacnet` | Building automation controllers | Unicast `Who-Is` to the target → `ReadProperty` (object-name, vendor-name, model-name, firmware-revision) on the Device object | `bacpypes3` | LOW |
| `opcua` | Modern controllers, SCADA servers, gateways | `GetEndpoints` only (no session). Optionally `FindServers` | `asyncua` | LOW |
| `http_title` | Web HMIs, switch UIs, gateways | One `GET /` and `<title>` + `Server` header. No login, no further crawling | `httpx` via the gate | LOW |
| `mac_vendor` | Everything with a MAC | Nothing: offline IEEE OUI lookup | Bundled OUI file | none |

**Not active plugins:** PROFINET DCP, DNP3, IEC 60870-5-104, Siemens S7comm-plus, GE SRTP, Omron FINS,
CODESYS. Some are layer-2 only; others are known to disturb some stacks even with read requests, or have no
stable read-only identification request. They can be added later as **passive** decoders.

### 4.3 Read-only enforcement in plugins

- Each plugin declares `allowed_ops`. The gate checks every outgoing request's op against it.
- Protocol-level guards are implemented in the wrapper, not just by convention:
  - **Modbus:** function code must be 43. FC 5/6/15/16/22/23 raise `WriteAttemptBlocked` before encoding.
  - **S7:** only SZL read (function 0x04 userdata, subfunction 0x01). Write var, PLC stop/start and download
    function codes are refused.
  - **ENIP:** only encapsulation command 0x63. No RegisterSession.
  - **BACnet:** only Who-Is and ReadProperty. WriteProperty / DeviceCommunicationControl / ReinitializeDevice refused.
  - **OPC UA:** no session, so no Write / Call is possible.
- Contract tests run every plugin against a **recording fake server** and assert that the full byte stream contains
  only allowed requests ([LIVE_TEST_PLAN.md](LIVE_TEST_PLAN.md) §2).

## 5. Classification signals added

`rules/classification.yaml` gains signal types so classification stays data-driven:

| Signal | Example rule |
|---|---|
| `ot.protocols contains 's7'` | → class `PLC`, vendor hint Siemens, level L1 |
| `plc.product_code matches '^6ES7 21'` | → model family S7-1200 |
| `ot.protocols contains 'enip' and hardware.vendor == 'Rockwell Automation/Allen-Bradley'` | → class `PLC` |
| `network.open_ports intersects [3389, 5986] and os.family == 'windows'` | → `ENGINEERING_WORKSTATION` / `SCADA_SERVER` (with services) |
| `ot.protocols contains 'bacnet'` | → class `BAS_CONTROLLER` |
| `mac.vendor in $industrial_oui_vendors` | weak signal, +10 % confidence |

Eligibility (`rules/eligibility.yaml`) maps class + OS to an **agent profile** or `AGENTLESS_ONLY`:

| Class / OS | Result |
|---|---|
| Windows workstation (10/11, 7/8.1) | `windows-workstation` |
| Windows server (2008 R2 … 2025) | `windows-server` |
| Linux host / gateway | `linux-host` |
| Windows XP / 2003, unknown Linux kernel < 2.6.32 | `AGENTLESS_ONLY` (no supported build) |
| PLC, RTU, drive, switch, sensor, BAS controller | `AGENTLESS_ONLY` (never an agent) |

## 6. Contract test changes

| ID | Change |
|---|---|
| C-03, C-06, C-08, C-10, C-11 | Run against **container targets** (snmpd, OpenSSH, a Windows VM in stage 3) instead of the simulator |
| C-07 | Measured against the gate's rate limiter with a fake clock, and with packet capture in the lab |
| C-09 | Dropped (determinism came from the simulator `SEED`) |
| C-16 | Replaced by **C-16L**: only `app.adapters.real.gate` imports networking primitives |
| **C-17 (new)** | Every gate call checks scope: an out-of-scope target returns `BLOCKED` and sends zero bytes |
| **C-18 (new)** | Each plugin, against a recording fake server, sends only its `allowed_ops`. Attempts to build a write request raise `WriteAttemptBlocked` |
| **C-19 (new)** | Kill switch: after `stop`, every adapter call returns `BLOCKED: kill-switch` within 1 s, and open sessions are closed |
