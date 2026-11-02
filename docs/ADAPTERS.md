# Protocol adapters

Source of truth: [`backend/app/adapters/base.py`](../backend/app/adapters/base.py).

## 1. Common contract

Every protocol adapter implements:

| Method | Purpose | Returns |
|---|---|---|
| `descriptor()` | Implementation name, `simulated` flag, UI display label (`SNMP (Demo)`) | `AdapterDescriptor` |
| `discover(target)` | Stream the hosts found in a CIDR target, one by one | `AsyncIterator[DiscoveredHost]` |
| `probe(target, query, on_stage)` | Collect named query groups from one host. `on_stage` streams visible sub-steps | `AdapterResult` |
| `health_check(target)` | Cheap protocol-level reachability check | `AdapterResult` |
| `get_device_info(target)` | Identity summary (vendor/model/OS/hostname) that this protocol can provide | `AdapterResult` |

Every `AdapterResult` carries `status` (`OK`, `PARTIAL`, `TIMEOUT`, `UNREACHABLE`, `REFUSED`, `BLOCKED`,
`AUTH_FAILED`, `TLS_INVALID`, `DISABLED`, `NOT_SUPPORTED`, `ERROR`), normalised `data` keyed by **provenance
field paths** (for example `os.build`), the protocol-specific `raw` payload, `stages`, `latency_ms`,
`collected_at` and error code/detail.

**Expected network outcomes are results, not exceptions.** Timeouts, auth failures and blocked responses are all
returned as statuses. Adapters raise only on programming errors.

Protocol-specific extensions:

| Interface | Extra methods |
|---|---|
| `WinRmAdapter` | `open_session(target, on_stage)`, `execute(session, RemoteOperation, params)`, `close_session(session)` |
| `MqttAdapter` | `subscribe(topic_filter, handler)`, `unsubscribe(id)` |
| `PackageTransfer` | `transfer(session, package, on_progress)` |
| `CredentialVault` | `resolve(profile, purpose, correlation_id)` (audited), `describe(profile)` (masked), `list_profiles()` |

`RemoteOperation` is a **closed enum** (`INSTALL_AGENT`, `STOP_SERVICE`, `QUERY_DISK_FREE`, …). Engines cannot send
free-form commands. A real WinRM adapter maps each operation to one vetted, signed PowerShell script.

## 2. Query groups and normalised output

| Adapter | `discover` | Query groups (`probe`) | Main normalised fields |
|---|---|---|---|
| ICMP | ping sweep (rate-limited in safe mode) | `echo` | `reachability.icmp`, `reachability.rtt_ms` |
| ARP | ARP table / passive cache of a subnet | `neighbor` | `network.mac`, `network.ip` |
| SNMP | GET on sysObjectID for responding hosts | `system`, `interfaces`, `entity`, `lldp`, `plc` | `snmp.sys_name`, `snmp.sys_descr`, `hardware.vendor`, `hardware.model`, `firmware.version`, `plc.mode`, `network.interfaces[]`, `network.active_ports` |
| WinRM | — | `session` (session stages only) | `services.winrm.available`, `services.winrm.port`, `services.winrm.tls` |
| WMI/CIM (over WinRM) | — | `os`, `hardware`, `firewall`, `antivirus`, `software`, `services`, `hotfixes`, `network` | `identity.hostname`, `os.*`, `hardware.*`, `firewall.state`, `antivirus.*`, `software.installed[]`, `services.running[]`, `patches.installed[]` |
| SSH (stub) | — | `identity` | `identity.hostname`, `os.name`, `os.version`, `os.kernel`, `hardware.uptime_sec` |
| MQTT | broker client list → (client_id, source IP) | `clients`, `topics` | `mqtt.client_id`, `mqtt.topics[]`, `telemetry.kind` |

## 3. Selection by configuration

```python
registry = AdapterRegistry.from_settings(settings)      # ADAPTER_MODE, ADAPTER_OVERRIDES
winrm: WinRmAdapter = registry.get(Protocol.WINRM)      # engines only ever see the interface
```

Implementations register themselves with `@register(Protocol.SNMP, "simulated")`. Swapping `simulated` for a
real implementation is a config change only. Acceptance K checks this with a test that registers an alternative
in-test `FakeSnmpAdapter`, sets `ADAPTER_OVERRIDES=snmp=fake` and runs discovery. No service code changes.

## 4. Contract test suite

`tests/contract/` is parametrised over **every registered implementation** of each interface. A future real
adapter runs the same suite against a lab fixture.

| ID | Contract |
|---|---|
| C-01 | `descriptor()` returns a matching `protocol` and a non-empty `display_label` |
| C-02 | All methods are `async` and return the declared types; `discover` is an async iterator |
| C-03 | Unknown/unreachable target → `status ∈ {UNREACHABLE, TIMEOUT, BLOCKED}`, no exception |
| C-04 | `data` keys are all registered provenance field paths (validated against `PROVENANCE_FIELDS`) |
| C-05 | `collected_at` is set and timezone-aware, and `latency_ms ≥ 0` |
| C-06 | Wrong credential → `AUTH_FAILED`, and the secret appears nowhere in `raw`, `error_detail` or `repr()` |
| C-07 | `safe_mode=True` → adapter performs no write operations and honours the rate limit (≤ 1 op/s per host in the sim clock) |
| C-08 | `timeout_sec` is honoured (simulated time scaled by `SPEED_FACTOR`) |
| C-09 | Repeated `probe` with the same state returns equal `data` (deterministic under `SEED`) |
| C-10 | `discover` on a CIDR yields each IP at most once |
| C-11 (WinRM) | Stages appear in order `CONNECTING, TCP_OK, TLS_VALIDATED, AUTH_OK, SESSION_CREATED`; on failure the sequence stops at the failing stage, with the matching status |
| C-12 (WinRM) | `execute` rejects operations outside `RemoteOperation` |
| C-13 (MQTT) | A subscriber receives messages that match the topic filter (`+`, `#` wildcards), in order |
| C-14 (Vault) | `describe`/`list_profiles` never return the plaintext; `resolve` emits an audit hook |
| C-15 (Transfer) | Progress callback values are monotonic in [0, 1] and end at 1.0 on success |
| C-16 (sim only) | Module imports no networking or process primitives (safety test) |

## 5. Replacing simulated adapters with real ones

The POC ships **no** real adapters. This table records what each replacement would need.

| Adapter | Suggested library / approach | Notes and gaps |
|---|---|---|
| ICMP | `icmplib` (unprivileged datagram sockets) | Needs `net.ipv4.ping_group_range` or CAP_NET_RAW. OT networks often drop ICMP, so keep "no reply ≠ offline". Strict rate limiting is needed for Level 0/1 |
| ARP | Read the switch ARP/FDB tables over SNMP (`IP-MIB::ipNetToPhysicalTable`, `BRIDGE-MIB`) is preferred. Alternative: passive capture on a SPAN port with `scapy` | Active ARP sweeps should be avoided on fragile L1/L0 networks. A sensor in each L2 segment is needed for a real passive capture |
| SNMP | `pysnmp` (lextudio fork, asyncio) | v3 USM authPriv (SHA-256/AES-128). Vendor MIBs are needed for PLC mode/firmware (often unavailable; many PLCs need native protocols such as S7comm/CIP, which are out of scope) |
| WinRM | `pypsrp` (HTTPS 5986, NTLM/Kerberos, cert validation) | Kerberos needs domain join or keytab. Map each `RemoteOperation` to signed PowerShell. Needs a JEA endpoint for least privilege |
| WMI/CIM | `pypsrp` running `Get-CimInstance` over the same WinRM session | Avoid DCOM/`impacket` in OT. Installed-apps coverage is partial (Uninstall keys, 32/64-bit) |
| SSH | `asyncssh` | Host key pinning, read-only commands, `sudo`-less collectors |
| MQTT | `aiomqtt` (paho) against Mosquitto/EMQX/HiveMQ | TLS + client certs, ACL for a read-only subscriber, Sparkplug B decoding |
| Package transfer | Preferred: agent bootstrapper pulls from OTProbe's HTTPS package endpoint with a signed short-lived URL. Alternatives: `pypsrp` file copy (chunked) or SMB (`smbprotocol`) | Code-signing verification (Authenticode) on host, bandwidth throttling, resumable transfer |
| Credential vault | HashiCorp Vault (`hvac`), CyberArk CCP, Azure Key Vault (`azure-keyvault-secrets`) | Lease/rotation, just-in-time credentials, break-glass audit |

The steps are the same for each adapter: implement the interface, register it, pass `tests/contract` against a lab
target, and enable it per protocol through `ADAPTER_OVERRIDES`. Before any real adapter can run, the safety test
(C-16) and the `ADAPTER_MODE=real` start-up guard need an explicit, documented change.
