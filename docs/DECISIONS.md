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

## Phase L3 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| L3-1 | Plugins run in the probe, not in discovery | Discovery stays cheap (ICMP, ARP, TCP connect, SNMP). Identification of PLCs and other OT devices happens when an operator probes an asset, so every OT request is tied to a deliberate, audited action. A "probe all new assets after discovery" option can be added later |
| L3-2 | Plugin defaults per profile | IT ranges: every TCP plugin on by default. OT-sensitive ranges: only plugins ticked on the scope entry. UDP plugins (BACnet): only where ticked, on any range. Safe mode: none. S7 is marked MEDIUM risk (uses one of the CPU's connection slots for about a second) |
| L3-3 | Hand-written OT encoders | Modbus, S7, EtherNet/IP and BACnet requests are built by hand (a few dozen lines each) instead of using full client libraries, so the exact bytes are known and a guard can refuse anything outside the read-only allow-list before it is written. pymodbus is used only as a test fixture (a real server) |
| L3-4 | BACnet without Who-Is | ReadProperty on the Device wildcard instance 4194303. Devices that do not support the wildcard will not be identified; a passive Who-Is/I-Am listener is the fallback for a later phase |
| L3-5 | WinRM needs PowerShell 3.0+ | Agentless Windows inventory uses ConvertTo-Json. Windows 7 / 2008 R2 without WMF 3+ report "PowerShell 3.0 or later required" and rely on the legacy Go agent (L4) |
| L3-6 | WinRM certificate check | OTProbe verifies the WinRM certificate chain itself (profile CA or system store, no hostname match because targets are IPs), then pypsrp connects without its own check. A short interception window remains; pinning inside the pypsrp session is planned for L6. A profile can skip validation for labs; probes then show the TLS state as "unverified" |
| L3-7 | Not built | `mac_vendor` (needs an offline OUI file), router ARP tables over SNMP, per-device plugin cool-down, Windows end-to-end verification (needs a Windows host: lab stage) |
| L3-8 | Tests | 219 pass. New: SSH against an in-process server (allow-list, host-key pinning, wrong password, Debian inventory); OT plugins against the real pymodbus and asyncua servers and recording S7/ENIP/BACnet fakes, each proving only allow-listed requests arrive; WinRM read-only script audit, injection attempts, mapping of recorded Windows output, stage-by-stage TLS failures against a real TLS server; a PLC probe end to end (identified, classified PLC, agent refused; then nothing sent once the range is OT-sensitive without plugins) |
| L3-9 | First real Windows test (Windows 10 Home 22H2, Dell Inspiron, WinRM HTTPS with a self-signed certificate, local admin account) | All WinRM stages and all eight WMI groups worked end to end. Real data exposed three problems, now fixed and tested: (1) the unsupported-OS list missed "Windows 10 Home", Education and Server editions (real products include the edition), so WIN-OS-001 passed wrongly; (2) link-local `169.254.x.x` adapters (Bluetooth, unplugged Ethernet) made a laptop look dual-homed; (3) the certificate name showed as `CN=?` when validation is skipped. **Open:** a plain Windows desktop is still classified "Windows Engineering Workstation" (41 %) because the rules have no generic Windows type; fixing it needs a "no engineering software" signal (`not matches` in the condition language). Proposed for L4 |

## Phase L4 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| L4-1 | Scope of L4 | Built: the Go agent, the signed release pipeline and its verification on the server, WinRM install/uninstall, deployment, enrollment over pinned TLS, assessment with agent evidence, removal and restart. **Moved to L6:** the manual one-liner install (and `install.sh`), and Linux deployment over SSH. There is no Linux host to test them on, and on Windows the one-liner is long to type by hand. New rules (Linux baseline, WIN-PATCH-002, RDP, SMBv1) and the generic Windows classification stay in **L5** as planned, because adding them now would change the simulated baseline scores the tests pin |
| L4-2 | Releases | `agent-go/build.sh` builds 14 targets, and `scripts/sign_release.py` signs `SHA256SUMS` with Ed25519. The server accepts a release only if the signature verifies and every file's hash matches. A release altered after registration is withdrawn (its packages become BLOCKED). A dev key was generated in `keys/` (git-ignored); a real site keeps the private key off the server |
| L4-3 | Builds as packages | Each verified build is registered as a deployable package, so the existing request → approve → precheck → deploy flow and screens are unchanged. The request form preselects the build that matches the asset's OS |
| L4-4 | Server TLS for agents | `scripts/make_lab_tls.py` creates a lab CA and a server certificate. The API serves the full chain, and agents pin the CA's SHA-256 (`caSha256` in agent.json): any other certificate, including a publicly trusted one, is refused. Plain HTTP is refused unless a lab-only flag is set by hand |
| L4-5 | Deploy scripts | Separate from the read-only probe scripts. Each value is validated against a strict pattern: the staging folder only, a SHA-256, the token format, an HTTPS URL, a profile name. The install script re-checks the binary's SHA-256 on the host before installing, and uninstall retries for 15 s while Windows releases the binary |
| L4-6 | Scope enforcement | Precheck, deploy, removal and restart now go through the scan-scope and kill-switch check, like discovery and probes |
| L4-7 | Known gaps | Windows collectors need PowerShell 3.0+ (legacy Win7 hosts report few sections). The credential in agent.json is ACL-protected, not yet DPAPI-encrypted. Antivirus software may quarantine the unsigned agent binary until releases are Authenticode-signed (open question O1) |
| L4-8 | Tests | Go: parsers (Linux, macOS, Windows), pinned TLS, revocation, and the full agent protocol against a fake server. Python: release verification (tampered, unsigned, wrong key, altered later, no key); unsafe deploy parameters refused before sending; and **the real Go agent through the real workflow**: deploy, enroll over HTTPS with the CA pinned, assessment with real evidence, removal, with a stand-in only for the Windows host's WinRM transport |
| L4-9 | Found in the manual test | (1) Migration 0006 was regenerated under the same revision after a running API had already applied its first version, so a live database missed two columns and the deployment failed right after INSTALL. Fixed by splitting into 0006 (agent builds) and 0007 (agent platform/profile), tested on a fresh DB and a copy of the live DB. Rule kept for the future: never change a migration that may have run; add a new one. (2) That failure left the agent half-installed on the laptop. The deployment engine now uninstalls from the host if anything fails after INSTALL (`DEPLOY_ROLLED_BACK`), with a test |

## Phase L5 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| L5-1 | Scope | Rules and assessments only. The bundled MQTT broker (Mosquitto, telemetry sources, broker checks) is **deferred** at your request; telemetry keeps working in simulated mode only |
| L5-2 | Generic Windows types | Rule language gained `not matches`. New types **Windows Workstation** (MEDIUM, level 3) and **Windows Server** (HIGH, level 3) win when no engineering or SCADA software is installed, which fixes the laptop that was called an engineering workstation. Hosts with TIA Portal, WinCC and similar still classify as before |
| L5-3 | New Windows rules (baseline 1.1.0) | WIN-PATCH-002 (an update within 90 days, HIGH), WIN-RDP-001 (NLA required when RDP is on, MEDIUM), WIN-SMB-001 (SMBv1 off, HIGH). They apply only to Go-agent evidence (`platform` present), so agentless and simulated evidence skip them instead of counting UNKNOWN, and the simulated scores are unchanged. Drift compares by policy name, so it continues across the version change |
| L5-4 | Linux baseline | `linux_host_baseline.yaml`: 12 rules (firewall, pending security updates, update age, supported release, SSH root and password login, UID 0, password length and lockout, auditd, USB storage, agent health). The release list reflects support dates as of November 2026 and needs review with each distribution release. Policy and collector set are chosen from the asset's OS |
| L5-5 | Not testable here | The Linux baseline runs only in tests (no Linux host, and SSH deployment is L6). Windows Server baseline variant (D7) not built: the workstation baseline applies to servers too |
| L5-6 | Tests | 246 pass: `not matches`; classification of the real laptop, an engineering workstation, a plain server and a SCADA server; the new Windows rules pass, fail and stay not-applicable on evidence shaped like the Go agent's; a hardened and a weak Linux host |

## Phase L6 notes for review

| # | Topic | What was done / proposed |
|---|---|---|
| L6-1 | Simulator removed from the product | `app/sim`, `app/adapters/simulated`, the `/sim/v1` API, Demo Controls (`/api/v1/demo`, Reset POC), the demo seed (zones, demo users, demo vault profiles, demo packages), the Python agent runtime and the telemetry simulator moved to `backend/tests/sim`. The product has no simulated mode left: `create_app`/`build_context` accept an `environment` argument, and only the tests pass one (`SimEnvironment`), which registers the simulated adapters and mounts the simulator routes. Without it, any `ADAPTER_MODE` other than `real` stops the server at start-up. `ctx.sim_control` and the `SimulationControl` port are gone from `app/`. A test now fails if anything under `app/` imports from `tests` |
| L6-2 | Database | Migration **0008** drops the four `sim_*` tables (empty on a live database). The test simulator creates them in its own test database from a separate metadata. Upgrade, downgrade and upgrade again were checked, and the models still match the migrations |
| L6-3 | Console | The Demo Controls page, the "POC reset" toast and the demo-user hint on the login page are removed. The settings page no longer shows the simulated vault and package panels. The console still shows a `SIMULATED` banner if the API reports that mode, which only the tests' server does |
| L6-4 | Packaging and docs | `docker-compose.yml` has no `simulated` profile, no `agent-runtime` and no `telemetry-sim`. The Makefile loses `up-sim` and `dev-api-sim`. `.env.example` loses the simulated-only settings. `DEMO_SCRIPT.md`, `SIMULATED_NETWORK.md`, `TESTING_D_G.md`, `TESTING_E_F.md` and the `try_*.sh` scripts are removed here and remain on the `simulated` branch. `FAILURE_MATRIX.md` stays as the specification of the test simulator's faults |
| L6-5 | Tests | The same suite runs against the simulator in its new place: unit, contract, acceptance A–K (with the agent runtime and telemetry simulator as subprocesses), the live loopback tests and the Playwright smoke test. Import contracts: the four that guarded the simulator packages are removed with them; three remain |
