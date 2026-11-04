# Test plan: OTProbe Live

Testing runs in four stages. A stage must pass before the next starts. Stages 1 and 2 run in CI on every commit;
stage 3 runs in the lab at the end of each phase L2–L6; stage 4 is the pilot.

| Stage | Where | Needs | Proves |
|---|---|---|---|
| 1. Unit | CI (Linux + Windows runners) | nothing external | Logic, parsers, collectors on recorded data, safety guards |
| 2. Containers | CI / any Linux machine with Docker | Docker | Real adapters and the agent against real protocol servers |
| 3. Lab | Isolated lab network | VMs + a soft PLC (see §3) | The whole product end to end on real hosts, acceptance criteria, failure matrix, packet capture |
| 4. Pilot | One approved plant subnet | Owner sign-off, maintenance window | Safe behaviour on the real network |

## 1. Stage 1: unit tests

| Area | Tool | Examples |
|---|---|---|
| Backend (kept from the POC) | pytest | Condition parser, evaluator, scoring, state machines, provenance, eligibility, RBAC, idempotency, audit chain |
| Network gate | pytest, fake clock | Scope include/exclude/empty, `/16` ceiling, rate limits, kill switch, out-of-scope = zero bytes |
| Plugins | pytest | Encoders/decoders against captured byte streams; `WriteAttemptBlocked` for every write function code |
| Install scripts | pytest renders the templates; `shellcheck` on `install.sh`; PSScriptAnalyzer on `install.ps1` (PS 2.0 rule set) | No secrets beyond the one-time tokens; exit code paths |
| Go agent | `go test` on Linux and Windows runners | Each collector against `testdata/` (registry dumps, `nft -j` output, `dpkg` lists, `sshd -T` output, Win7 and Win11 variants); transport against an `httptest` server (pinning, revoke, backoff); evidence size cap |
| Go builds | CI matrix | Every build in [GO_AGENT.md](GO_AGENT.md) §1 compiles. The legacy builds compile with Go 1.20.14 |

## 2. Stage 2: container tests

A `docker compose -f compose.test.yml` network that contains only test containers. The scan scope is set to that
network, so the gate's rules apply in tests too.

| Container | Used for |
|---|---|
| `net-snmp` (snmpd, v3 user + v2c community) | SNMP adapter contract tests, ARP table read |
| `openssh-server` (Debian, Alpine) | SSH adapter, `install.sh` / `uninstall.sh` end to end, Linux Go agent (amd64 and arm64 via QEMU) |
| `mosquitto` (the product image) | Broker defaults, dynsec accounts, telemetry mapping, broker checks |
| `pymodbus` server (test only) | `modbus` plugin; a **recording** server asserts that only FC43 arrives |
| `conpot` (ICS honeypot: S7, Modbus, BACnet, EtherNet/IP personalities) | `s7`, `enip`, `bacnet` plugins identification, with recording proxies |
| `asyncua` demo server | `opcua` plugin |
| OTProbe `api` + `web` | Acceptance tests through the real API |

Acceptance criteria that run fully in stage 2: A (discovery), B (Linux probe), D and G with the Linux agent,
E and F on the Linux baseline, K (adapter registry), and the safety tests L-SAFE-1 to 4.

Windows cannot run in Linux containers. Windows paths are covered by stage 1 (collectors) and stage 3 (VMs).

## 3. Stage 3: the lab

### 3.1 Topology

An isolated network: VirtualBox/Proxmox/Hyper-V internal networks, or a spare switch with no uplink.

```
                    ┌────────────── 10.99.0.0/24  "Lab L3 – operations" (scope profile IT) ───────────────┐
                    │  otprobe-srv   Ubuntu 24.04  10.99.0.10   OTProbe (compose), Mosquitto, Wireshark      │
                    │  win11-eng     Windows 11 Ent (eval)      WinRM HTTPS, agent: windows-amd64          │
                    │  win2022-scada Windows Server 2022 (eval) WinRM HTTPS, agent: windows-amd64          │
                    │  win7-legacy   Windows 7 SP1 (if an image/licence exists) agent: windows-legacy-amd64 │
                    │  ubuntu-hmi    Ubuntu 22.04               SSH, agent: linux-amd64                     │
                    └──────────────────────────────┬──────────────────────────────────────────────────────┘
                                           lab router / VM with SNMPv3 (ARP table)
                    ┌──────────────────────────────┴───────── 10.99.1.0/24  "Lab L1/L2 – control" (OT_SENSITIVE) ┐
                    │  openplc       Raspberry Pi 4 (Raspberry Pi OS) — OpenPLC runtime, Modbus TCP 502;          │
                    │                 agent: linux-arm64; publishes telemetry via a gateway account              │
                    │  conpot        Conpot VM — S7 (102), ENIP (44818), BACnet (47808) personalities             │
                    │  (optional)    real PLC, e.g. Siemens S7-1200 or a Micro800, if one is available            │
                    │  sensor-sim    small MQTT publisher (test tool, not product) — temperature readings         │
                    └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

Minimum lab: `otprobe-srv`, one Windows VM, one Linux VM and Conpot. Windows evaluation images are free for
90–180 days.

### 3.2 Acceptance criteria (live)

| ID | Criterion | Pass condition |
|---|---|---|
| A | Discovery | Both lab subnets discovered. Every VM, the Pi and Conpot are listed with IP, MAC (local) or MAC from the router's ARP table (remote), and open ports. Sources are recorded per field |
| B | Agentless probe | Windows VMs: OS, build, firewall, AV, hotfixes via WinRM. Ubuntu: OS, packages via SSH. Wrong credential → `PARTIAL`, stopped at `AUTH_OK` |
| C | Identification and classification | Conpot S7 → `PLC`, vendor Siemens, model from SZL. ENIP → vendor and product name. OpenPLC → Modbus device, or "Unknown device" if FC43 is not supported, with no error. Windows → workstation / server |
| D | Deploy agent | Request → approve (different user) → precheck → deploy for each OS: win11 (`windows-amd64`), win2022, win7 (`windows-legacy-amd64`, PUSH), ubuntu (`linux-amd64`), Pi (`linux-arm64`). Each one reaches `ENROLLED` / agent `ONLINE` with no manual step |
| D-M | Manual install | One-liner on a host without WinRM/SSH → agent `ONLINE`, deployment `COMPLETED` |
| E | Deep assessment | Each agent uploads evidence. Score and findings match a hand check of that VM's settings |
| F | Drift | Turn off the Windows firewall on win11 → next assessment: `WIN-FW-001` FAIL + `CONFIGURATION_DRIFT_DETECTED`. Turn it on → RESOLVED |
| G | Heartbeat | Block outbound 443 on a target → STALE → OFFLINE. Unblock → ONLINE |
| H | Failures | §3.3 table |
| I | Rollback / removal | Remove agent → service and files gone (checked by hand on the VM), credential revoked, later calls → 401 |
| J | Clear inventory | Admin clears inventory → assets gone, audit kept |
| K | Adapter registry | Container-level: a fake adapter registered in tests is used for one protocol without service changes |
| L | Multi-platform | Every build in the lab (Win modern, Win legacy, Linux amd64, Linux arm64) passes D, E, G, I |
| M | MQTT | Gateway account publishes. OTProbe maps topics, opens `TEL-TEMP-002` at 97 °C, and `TEL-STALE-001` when the publisher stops. Anonymous connect is refused |

### 3.3 Failure matrix (real injection)

Every row from the POC's failure matrix maps to a real action in the lab:

| # | Failure | How to cause it in the lab | Expected (as in the POC) |
|---|---|---|---|
| 1 | Device offline | Power off the VM / unplug the Pi | Probe `FAILED`, asset `OFFLINE`, agent STALE → OFFLINE |
| 2 | WinRM disabled | `Stop-Service WinRM; Set-Service WinRM -StartupType Disabled` | Precheck `WINRM_AVAILABLE` FAIL |
| 3 | WinRM refused | Windows Firewall rule: **reject** 5986 | `WINRM_CONNECTION_REFUSED` |
| 4 | WinRM timeout | Firewall rule: **drop** 5986 (on the lab router) | `WINRM_TIMEOUT` |
| 5 | Wrong credentials | Change the account's password on the VM | `WINRM_AUTH_FAILED`, probe `PARTIAL` |
| 6 | Bad certificate | Rebind the HTTPS listener to a self-signed certificate that is not in the trust store | `WINRM_TLS_INVALID` |
| 7 | ICMP blocked | Firewall: block echo-request | `reachability.icmp=BLOCKED`, asset still ONLINE |
| 8 | SNMP timeout | Stop snmpd on the router VM | Discovery `COMPLETED` (ARP from the kernel table), probe `PARTIAL` |
| 9 | Checksum mismatch | Replace the stored binary with a modified file (`truncate -s -1`) **without** updating `SHA256SUMS` | Install script exit 10, `HASH_MISMATCH`, nothing installed |
| 10 | Install failure | Deny write on `C:\Program Files\OTProbe` (icacls) / make `/opt/otprobe` immutable (`chattr +i`) | Exit 20, `INSTALL_FAILED` |
| 11 | Enrollment failure | Block the target's outbound 443 **after** staging, so the agent starts but cannot enroll | After timeout: `ENROLLMENT_FAILED`, token revoked |
| 12 | Heartbeat loss | Block outbound 443 on an enrolled target | STALE → OFFLINE → ONLINE when unblocked |
| 13 | Agent crash | `taskkill /F /IM otprobe-agent.exe` with recovery disabled / `kill -9` with `Restart=no` override | STALE → OFFLINE. **Restart agent service** → ONLINE |
| 14 | Assessment timeout | Suspend the agent process after it takes the task (`pssuspend` / `kill -STOP`) | Run `TIMED_OUT` |
| 15 | Rollback failure | Hold a lock on the agent binary during removal (open handle / `chattr +i`) | Removal `UNINSTALL_FAILED`, credential revoked anyway; retry succeeds after unlock |
| 16 | PLC offline | Stop the OpenPLC runtime / unplug the Pi | Telemetry stale finding |
| 17 | High sensor value | `sensor-sim` publishes 97 °C | `TEL-TEMP-002` CRITICAL |
| 18 | Rogue device | Connect a new VM to the control subnet | `NET-ROGUE-001` on the next discovery |

### 3.4 Safety verification (packet capture)

Wireshark / `tcpdump` runs on `otprobe-srv` and on a mirror port of the control subnet during every lab run.

| ID | Check | Pass condition |
|---|---|---|
| L-SAFE-1 | Scope | Add an exclusion for the Conpot IP and run discovery. Capture shows **zero** packets to that IP. Then remove the whole scope: zero packets on any interface during a discovery attempt |
| L-SAFE-2 | Rate | During discovery of the `OT_SENSITIVE` subnet: ≤ 10 packets/s to the subnet and ≤ 1 operation/s per host, measured in the capture |
| L-SAFE-3 | Kill switch | Start discovery + a deployment, press **Stop all**. Last OTProbe-originated packet to a target within 1 s. Workflows `FAILED: Stopped by kill switch` |
| L-SAFE-4 | Read-only | Filter the capture by protocol: Modbus function codes ⊆ {43}; S7 only SZL reads; ENIP only command 0x63; BACnet only Who-Is / ReadProperty; SNMP has no SetRequest |
| L-SAFE-5 | PLC still healthy | After a full lab campaign, OpenPLC and Conpot (and any real PLC) are still in RUN with unchanged program and values. Real PLC: diagnostic buffer shows no new errors |
| L-SAFE-6 | Credentials | No plaintext password in the capture (WinRM over TLS, SSH, SNMPv3 authPriv, MQTT TLS) or in `docker logs` |

## 4. Stage 4: pilot on the real network

1. **Paperwork:** written permission (already given) recorded on the scope entry, the subnet chosen with the
   network owner, a maintenance window booked, and someone from OT operations present.
2. **Day 1:**
   - Safe mode on, discovery only, one subnet.
   - Capture running; compare against L-SAFE-1/2.
   - Review the asset list with the owner.
3. **Day 2:**
   - Agentless probes of the Windows/Linux hosts the owner names.
   - Plugins enabled only for device types that already passed in the lab with the same vendor family.
4. **Day 3:**
   - One agent on one engineering workstation, with a full deploy → assess → remove cycle.
   - Check the host by hand afterwards.
5. **Exit criteria:**
   - No device faults or alarms caused.
   - Capture is clean.
   - Findings were reviewed with the owner.
   - Then decide on a wider rollout.

## 5. Mapping to CI

```
.github/workflows/ci.yml
  backend-unit        ruff · import-linter (incl. C-16L) · pytest -m "not containers and not lab"
  agent-unit          go vet · go test (ubuntu, windows) · build matrix (current Go + Go 1.20.14)
  scripts             shellcheck · PSScriptAnalyzer
  containers          docker compose -f compose.test.yml up · pytest -m containers
lab (manual)          make lab-acceptance   → runs A–M against the lab, writes a signed report
```
