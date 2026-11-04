# Safety and scan scope

OTProbe Live sends real packets into industrial networks. Some devices on those networks (older PLCs, RTUs,
drives, safety controllers) can fault, drop their connections or reboot when they get unexpected traffic.
The guarantees below are enforced **in code at one chokepoint**, the network gate, not by convention.

## 1. Guarantees

| # | Guarantee | Enforced by | Verified by |
|---|---|---|---|
| S1 | No packet is sent to an address outside the scan scope | `NetworkGate.check(ip)` before every socket open / send | Unit + contract tests; packet capture in the lab (`LIVE_TEST_PLAN.md` L-SAFE-1) |
| S2 | With no scope configured, nothing is sent at all | Gate returns `BLOCKED: no-scope` | Test: fresh install → discovery → `409 scan-scope-empty` |
| S3 | Excluded addresses are never touched, even inside an included subnet | Exclusions are checked after inclusions | Test + capture |
| S4 | Nothing is ever **written** to a PLC, controller or field device | Plugins expose only identification reads; function-code / service allowlists in each plugin | Recording fake servers in contract tests; capture in the lab |
| S5 | Traffic rate stays under configured limits | Token buckets in the gate (global, per subnet, per host) | Contract test C-07; capture in the lab |
| S6 | An operator can stop everything at once | Kill switch closes the gate and cancels all workflows | Test L-SAFE-3 |
| S7 | Remote commands on hosts are a closed set | `RemoteOperation` enum → vetted scripts, no free-form commands | Contract test C-12 (kept) |
| S8 | The agent cannot run arbitrary commands | Fixed, compiled-in collectors; tasks are a closed enum (decision R4) | Go tests; review |
| S9 | Real credentials never leave the vault in clear | Masking in API/UI, AES-GCM at rest, redaction in logs, `repr()` masking | Contract test C-06, C-14 (kept) |
| S10 | Every scan, probe and remote operation is attributable | Audit events with actor, correlation ID, targets and counts | Existing audit tests |

## 2. Scan scope

Admins manage the scope in **Settings → Scan Scope**. Every change writes `SCOPE_CHANGED` with before/after
values.

| Field | Example | Meaning |
|---|---|---|
| `cidr` | `10.20.1.0/24` | IPv4 or IPv6 network. Single hosts are written as `/32` |
| `kind` | `INCLUDE` / `EXCLUDE` | Exclusions always win |
| `profile` | `IT` / `OT_SENSITIVE` | Picks the safety profile (§3) |
| `label` | `Line 1 controllers` | Shown in the banner and on discovery jobs |

Rules:

- **Empty by default.** No scope means no network activity. Discovery, probes, prechecks and deployments return
  `409 scan-scope-empty`, and the banner says `NO SCAN SCOPE CONFIGURED (scanning disabled)`.
- **Ceiling on size.** An INCLUDE entry larger than `/16` (IPv4) or `/112` (IPv6) is refused. Wide sweeps of
  plant networks are never the right first step.
- **Snapshot per job.** A discovery job copies the scope at start (`discovery_jobs.scope_snapshot`). If the scope
  is narrowed mid-job, the gate still applies the **current** scope on each packet, so narrowing takes effect at
  once.
- **Agents are not scanned.** Agents call OTProbe outbound. The scope controls what OTProbe sends, not what it
  accepts. An agent on an out-of-scope host can still enroll if its deployment was approved and was a manual
  install.

## 3. Safety profiles

| Setting | `IT` | `OT_SENSITIVE` (default for new entries) |
|---|---|---|
| Max packets/s to the subnet | 50 | 10 |
| Concurrent operations per host | 2 | 1 |
| Min gap between operations to one host | 200 ms | 1 s |
| ICMP sweep | yes | yes |
| Active ARP (local segment) | yes | yes (ARP is broadcast and harmless to devices) |
| TCP connect on the port list | full list, connect + clean close, no payload | same list, same rules; slower because of the 1 op/s per-host gap |
| OT protocol plugins (Modbus, S7, ENIP, BACnet, OPC UA) | enabled | **off until enabled per entry** (`plugins: [modbus, enip]`) |
| SNMP | v3, v2c if a profile exists | v3 only |
| Retries on timeout | 2 | 0 (a timeout is reported, not retried) |

The OT protocols that are known to be fragile (DNP3, IEC 60870-5-104, PROFINET DCP) are **never** sent active
requests by OTProbe. Their port presence can be noted (TCP connect only), and DNP3/IEC 104/PROFINET
identification is a later **passive** option (listening on a SPAN port), not part of L2–L6.

## 4. Safe mode

`SAFE_MODE=true` (default) applies the `OT_SENSITIVE` settings to **every** scope entry, whatever profile it
has, and disables all plugins. Turning it off needs an admin, a reason, and writes `SAFE_MODE_DISABLED`. The
banner shows `SAFE MODE` while it is on.

## 5. Kill switch

- **Stop all** button in the header, available to operators and admins. Calls `POST /api/v1/safety/stop` with a
  reason.
- Effect, in this order:
  1. The gate closes: every new `check()` returns `BLOCKED: kill-switch`.
  2. All running discovery, probe, precheck, deployment, removal and assessment workflows are cancelled. They
     move to their failure state with reason `Stopped by kill switch` and audit `WORKFLOW_STOPPED`.
  3. Open sessions (WinRM, SSH, plugin sockets) are closed.
  4. Agents are told to cancel running tasks on their next poll. Heartbeats continue: they are inbound and harmless.
- **Re-arm** needs an admin (`POST /api/v1/safety/rearm`) and writes `SAFETY_REARMED`.
- Survives restarts: the state lives in `safety_state`, not in memory.

## 6. The network gate

```python
class NetworkGate:
    async def check(self, ip: IPAddress, op: GateOp) -> GateDecision      # scope, exclusions, kill switch
    async def acquire(self, ip: IPAddress, op: GateOp) -> AsyncContextManager  # rate limit + per-host concurrency
    async def open_tcp(self, ip, port, op) -> (reader, writer)            # check + acquire + connect
    async def open_udp(self, ip, port, op) -> DatagramTransport
    async def icmp_echo(self, ip, op) -> PingResult
    async def arp_sweep(self, iface, cidr, op) -> list[Neighbor]
    def transport_for(self, library: str, ip, op)                          # pysnmp / pypsrp / asyncssh / pymodbus
```

- **Only package allowed to import networking primitives** is `app/adapters/real/net/` (the gate plus one small
  sender per protocol). Enforced by `tests/unit/test_live_safety.py` (AST scan of all of `app/`), which also checks
  that every public sender in that package calls `gate.permit`.
- `GateOp` names the protocol and operation (`ICMP_ECHO`, `TCP_CONNECT`, `SNMP_GET`, `MODBUS_FC43`, …). It is
  used for rate limits, audit counters and the allowlist check.
- Every decision is counted per job. The job's audit event `DISCOVERY_COMPLETED` / `PROBE_COMPLETED` includes
  `{sent, blockedByScope, blockedByKillSwitch, rateLimitedMs}`.
- Out-of-scope attempts are a **bug signal**: `SCOPE_VIOLATION_BLOCKED` is audited and shown on the dashboard.

## 7. Credentials

- Credentials are real. They are stored encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using the key from
  `VAULT_KEY` or `VAULT_KEY_FILE` (generated 0400 on first start; Compose keeps it on its own `otprobe-keys` volume). The key never appears in the DB, env dumps or backups of the data volume.
- They are shown masked (`••••••••`, `secretSet: true`) everywhere. There is no "reveal" in the UI or API.
- They are resolved only inside an engine step, for one target, with audit `CREDENTIAL_RETRIEVED` (purpose, asset,
  correlation ID). They are never written to logs (a log filter redacts known secret values as a second line of
  defence).
- Recommended accounts (documented in the admin guide):
  - **WinRM:** a dedicated local or domain account, ideally a JEA endpoint limited to the vetted scripts.
  - **SSH:** a dedicated account with a `sudoers` entry limited to the install and uninstall scripts.
  - **SNMP:** a v3 read-only user.

## 8. Rules for engagements

These are process, not code, but the product supports them:

1. Written permission from the network owner. Recorded as the `label` and a free-text `authorization` note on
   each scope entry.
2. Start in safe mode with discovery only, on one subnet.
3. Deployments only in an approved maintenance window. Approvals already support windows.
4. Packet capture during the first run on any new subnet, to confirm the rates and targets (see the test plan).
