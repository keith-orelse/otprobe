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
