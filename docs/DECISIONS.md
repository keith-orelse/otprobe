# Design decisions log

Decisions made during the build, by phase. Every Phase 1 default was accepted. Each later note was reviewed and
approved with its phase.

## Phase 1 open questions (resolved: defaults accepted)

The design makes a default choice for each of these. Please confirm or change.

| # | Question | Default chosen in the docs |
|---|---|---|
| Q1 | What are the "baseline findings" after Reset POC? | Reset clears the OTProbe inventory, so there are **no** findings until discovery and a probe run again. The first agentless probe of eng-ws-02 produces `WIN-OS-001` (unsupported OS, source AGENTLESS). The alternative is for Reset to keep discovered assets and agentless data, and remove only agent/deep data. |
| Q2 | Should Reset POC clear the audit log? | **No.** The audit log is append-only and survives a reset, with a `POC_RESET` event added. |
| Q3 | Retrying a FAILED deployment (e.g. checksum failure) | Creates a **new** deployment (`retry_of_id`) that needs a **new approval**. The alternative is to reuse the original approval if the target and package are unchanged. |
| Q4 | Removal state machine additions | Added `REQUESTED → REJECTED` and an admin retry `FAILED → RUNNING` under the same approval. Neither is in the brief. |
| Q5 | Acceptance A says "discovery of 192.168.20.0/24 … sensors found only via ARP", but the sensors are on 192.168.10.0/24 | The test discovers **both** subnets in one job and asserts that the sensors' only discovery source is ARP. |
| Q6 | Drift trigger | PASS→FAIL **and** PASS→WARNING emit `CONFIGURATION_DRIFT_DETECTED`. The brief names only PASS→FAIL. |

Phase 2 went ahead with these defaults.

## Phase 2 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| N1 | Python version | Code is 3.11-compatible (tested locally on 3.11.x). Docker runs 3.12 |
| N2 | Pagination cursor | Opaque, offset-encoded in the POC. It can become keyset-based without an API change |
| N3 | Agentless software visibility | `RemoteTool Demo` is a **per-user** install, so agentless WMI (machine-scope Uninstall keys) does not see it; only the deep agent will. **Proposal for Phase 4:** make `WIN-SW-001` `DEEP_AGENT`-only, so agentless never reports a false PASS |
| N4 | Classification confidence | eng-ws-01 scores **91%**. The unmatched signal is "Dual-homed (L2 + L1 interfaces)". Confidences and evidence come entirely from `rules/classification.yaml` |
| N5 | Unprobed Windows hosts | After discovery alone, Windows hosts are unclassified with eligibility `UNKNOWN`. This follows the provenance matrix: discovery yields no OS data |

## Phase 3 notes for review

| # | Topic | What was done |
|---|---|---|
| N6 | "Retrieve credential" step | The installer credential is fetched from the vault when the WinRM session opens (and audited as `CREDENTIAL_RETRIEVED`). The `RETRIEVE_CREDENTIAL` step mints the agent's enrollment credential: the single-use token that the installer writes into the agent's enrollment bundle |
| N7 | Enrollment idempotency | `POST /agents/enroll` does not store an idempotency record, because that would persist the plaintext credential. The single-use token makes the call idempotent: a replay returns `401 Enrollment token already used` |
| N8 | Enrollment failure | The simulated fault makes the agent present a tampered token. It is rejected (`ENROLLMENT_TOKEN_REJECTED`), and the deployment goes `FAILED / ENROLLMENT_FAILED` when `ENROLLMENT_TIMEOUT_SEC` (default 120 s) expires, leaving the agent in `ERROR` |
| N9 | Simulator token | One shared `SIM_SERVICE_TOKEN` guards `/sim/v1` (not scoped per host). This is a deliberate simplification: `/sim` stands in for each host's own disk |
| N10 | Approval reason | A reason is required to reject, and to approve a deployment to a CRITICAL asset |
| N11 | Who runs precheck and deploy | The requester (operator) or an admin. Approvers only decide |
| N12 | Bug fixed | List filters sent in camelCase (`entityId`, `correlationId`, `assetId`) were silently ignored. They now work, with a regression test |

## Phase 4 notes for review

| # | Topic | What was done |
|---|---|---|
| N13 | WIN-SW-001 is deep-agent only | Implemented as proposed in N3 (Phase 2). Agentless WMI cannot see per-user installs, so an agentless PASS would be false |
| N14 | Drift baseline | Drift compares with the previous run of the **same source** (deep with deep, agentless with agentless). Comparing across sources would create false drift, because agentless evidence is partial. `docs/RULES.md` is updated |
| N15 | Observed value for list rules | For `not intersects` rules, the finding records only the offending items (`["RemoteTool Demo"]`), not the whole software list |
| N16 | Rogue finding | `NET-ROGUE-001` (source DISCOVERY) is created on rediscovery. An admin authorizes the device via `POST /assets/{id}/authorize`, which resolves the finding |
| N17 | Compliance on the dashboard | The average is taken over each asset's latest evaluated run (deep or agentless). The asset page names the source of its score |
| N18 | Score precision | One decimal place (75.0, 60.7); the docs' worked example rounds to 75 |
| N19 | Brought forward from Phase 5 | Configuration controls (firewall, antivirus, unauthorized software, remove patch) and the `assessment_timeout` fault, because F needs them |

## Phase 5 notes

| # | Topic | What was done |
|---|---|---|
| N20 | Rollback compensation | If any rollback step fails, the agent credential is revoked anyway, so a half-removed agent cannot keep talking to the server. The agent goes to `ERROR`, and an admin can retry under the same approval |
| N21 | Reset POC and discovery history | The audit log is kept and gets a `POC_RESET` event. Discovery history is kept as *archived* by default (`clearDiscoveryHistory` removes it). Archived jobs never count as a rogue baseline, so rediscovering after a reset does not flag every device as rogue |
| N22 | Reset while workflows run | The API refuses (`409 workflows-running`) unless `force=true`. The console always sends `force=true` after the typed `RESET` confirmation |
| N23 | Telemetry attribution | Each MQTT publisher is mapped to an asset through the broker's client list (client id → source IP → asset). Real brokers expose this through an admin API. Messages from unknown publishers are stored unattributed |
| N24 | Telemetry staleness | `TEL-PLC-001` raises a finding when no status arrives within `stale_after_sec` (30 s). `TELEMETRY_TIME_SCALE` shortens that window in tests |
| N25 | Sensor display name | Sensors expose no hostname protocol, so after a probe they are named by their MQTT client id (`sensor01`). Before that they show as their IP |
| N26 | Agent restart | A crash stops the simulated `OTProbeAgent` service. The recovery is **RESTART AGENT SERVICE** (WinRM `Start-Service`); the agent then resumes with its saved credential |
| N27 | Agent runtime reinstall detection | A stopped (revoked or crashed) agent is keyed to its deployment id, so a fast remove-and-reinstall is always seen as a new install. This fixed a race found by the enrollment-failure test |
| N28 | Docker | `docker compose up` (api, agent-runtime, telemetry-sim, web) is defined but **not verified on this machine**, because Docker is not installed. Everything was verified as local processes, including the agent and telemetry as separate OS processes |

## Live network redesign (phase L1, for review)

Design: [LIVE_ARCHITECTURE.md](LIVE_ARCHITECTURE.md) and the documents it links.

### Decisions agreed

| # | Decision |
|---|---|
| R1 | `main` becomes the real-network product. The simulated POC is kept, frozen, on the `simulated` branch. Work happens on `real-network` and merges into `main` after each approved phase |
| R2 | The OTProbe server runs on **Linux** (Docker Compose with host networking, or systemd) |
| R3 | The agent is rewritten in **Go**: one codebase, a separate build per OS/arch (including legacy Windows 7/2008 R2/2012 builds on Go 1.20). It is installed and removed by generated scripts (`install.ps1`/`install.sh`) |
| R4 | **Option A:** the agent runs fixed, compiled-in, read-only checks only. The server cannot send scripts or commands to it. New checks ship as a new agent version through an approved UPGRADE deployment |
| R5 | OTProbe **ships its own MQTT broker** (Mosquitto 2.0, TLS, no anonymous access). OTProbe subscribes only |
| R6 | Device coverage in three tiers: agent / agentless host / read-only identification for PLCs and network devices. Unknown devices are still listed |
| R7 | Permission to scan is given. The **subnets are decided later**: the scan scope is configured in the console, is empty by default, and blocks all network activity while empty |

### Defaults proposed in this design (please confirm or change)

| # | Topic | Default in the docs |
|---|---|---|
| D1 | New scope entries' safety profile | `OT_SENSITIVE` (10 pkt/s, 1 op/s per host, plugins off until enabled) |
| D2 | `SAFE_MODE` at install | On. An admin turns it off with a reason |
| D3 | Active OT protocols | Modbus FC43, S7 SZL read, ENIP ListIdentity, BACnet ReadProperty, OPC UA GetEndpoints. **Never active:** DNP3, IEC 104, PROFINET DCP (passive later) |
| D4 | Agent transfer mode | PULL over HTTPS by default. PUSH (copy over WinRM/SSH) for legacy Windows and hosts without a TLS 1.2 client |
| D5 | Kill switch | Operators can stop; only admins can re-arm |
| D6 | Demo Controls / Reset POC on `main` | Removed. Admin keeps an audited "Clear inventory" |
| D7 | New rules | `WIN-PATCH-002`, `WIN-RDP-001`, `WIN-SMB-001`, a Windows server baseline, a Linux host baseline, `MQTT-BRK-*`, `NET-MQTT-*` |
| D8 | macOS agent build | Built but not tested in the lab unless a Mac target is in scope |

### Open questions

| # | Question | Why it matters |
|---|---|---|
| O1 | Is there a code-signing certificate for Windows (Authenticode)? | Unsigned binaries may be blocked by AppLocker/WDAC or flagged by AV on hardened hosts. Without one, we rely on SHA-256 + the Ed25519-signed `SHA256SUMS` |
| O2 | Missing-patch detection on Windows: is there a WSUS server, or can we use an offline catalog (`wsusscn2.cab`, ~1 GB, refreshed monthly)? | Without either, `WIN-PATCH-001` reports UNKNOWN and only `WIN-PATCH-002` (days since last update) is evaluated |
| O3 | Are target Windows hosts set up for WinRM over **HTTPS** (5986), or only HTTP 5985? Domain-joined (Kerberos) or local accounts (NTLM)? | Decides the default WinRM profile and the lab setup |
| O4 | Is a Windows 7 / Server 2008 R2 image available for the lab? | Needed to test the legacy build (acceptance L) |
| O5 | Is any real PLC available for the lab (e.g. S7-1200, Micro800)? | Conpot covers protocol parsing, but only real hardware proves "no disturbance" (L-SAFE-5) |
| O6 | SQLite or Postgres for the first real deployments? | SQLite is fine for one site and a few hundred assets; Postgres for anything larger |

## Phase L2 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| L2-1 | Simulator still in the code | `ADAPTER_MODE=real` is now the default and loads **no** simulator code (a test checks `sys.modules`). The simulator stays loadable with `ADAPTER_MODE=simulated` because the deployment, agent, assessment and telemetry flows (and 151 tests) still depend on it until their real versions land in L3–L5. It moves out of `app/` into the test suite in L6. This deviates from the L1 plan, which removed it in L2 |
| L2-2 | ARP in L2 | Reads the kernel neighbour cache after the ICMP sweep (sends nothing itself). Active ARP via scapy was not added: the sweep already makes the kernel ARP every local address, and it avoids a root-only dependency. Remote-subnet ARP over SNMP (router tables) is still to do |
| L2-3 | TCP and SNMP only visit hosts already seen | In live mode, TCP connect and SNMP run only on hosts that answered ICMP or ARP in the same job. Silent addresses get zero traffic. Trade-off: a remote host that blocks ICMP is missed by discovery (it can still be added by probing its IP directly). A per-scope "full TCP sweep" option can be added if needed |
| L2-4 | Assets without a MAC | Remote hosts become assets keyed by IP. When a MAC shows up later it is attached (`ASSET_MAC_LEARNED`) |
| L2-5 | Accounts in live mode | No demo passwords. `admin`, `operator`, `approver` get `OTPROBE_*_PASSWORD` (≥ 12 chars) or a random password printed once in the API log. A user-management page (create users, change password) is not built yet: proposed for L6 |
| L2-6 | Secrets | Vault: Fernet with a generated key file (0400), never the demo key in live mode. JWT secret: generated key file if the demo value is still set. Vault profiles are write-only through `PUT /api/v1/vault/profiles/{name}` |
| L2-7 | Kill switch | `POST /safety/stop` closes the gate before the DB commit (fail-safe), then cancels every running workflow. Measured on loopback: no new packets after the stop (test allows the one already in flight). State survives restarts |
| L2-8 | Docker | Compose now runs the API with `network_mode: host` and only `CAP_NET_RAW`; simulator containers are behind the `simulated` profile. **Not verified** here (Docker is not installed on this machine); to be checked on the Linux lab host |
| L2-9 | Tests | 179 tests pass: the 151 POC tests (simulated mode) plus 28 new — 12 network-gate unit tests (fake clock), 9 structural safety tests, 7 live tests on 127.0.0.1 against a real TCP listener and a real SNMP agent (v2c + v3 SHA-256/AES). The Playwright smoke test still passes, and the live console was checked in a browser |
| L2-10 | Proxy ARP (found on a real Wi-Fi) | Testing on an office Wi-Fi showed the router answering ARP for isolated clients with its own MAC, so a laptop and a phone both appeared as `A8:5B:F7:CC:12:A0` and inventory "moved" one onto the other. A MAC that answers for more than one IP in the neighbour table is now recorded as `network.arp_via` and never used as identity; such hosts are tracked by IP. Remaining edge case: when a device with a known MAC really moves (DHCP) onto an IP that already has a MAC-less asset, two assets exist until one is cleared (merge tool proposed for L6) |
