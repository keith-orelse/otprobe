# OTProbe

**Simulated OT discovery, agentless probing and deep agent probing: a standalone, fully local POC.**

> **SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED.**
> The OT network, its devices and every protocol response are simulated. The web console, REST API, database,
> workflows, approvals, compliance rules, findings and audit trail are real.

## Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Design documents, contracts, rules schema, project skeleton | Done |
| 2 | Simulator, seed, discovery (SSE), assets, agentless probing, classification, topology | Done (approved) |
| 3 | Auth/roles, approvals, vault, packages, precheck, deployment, enrollment, agent runtime, heartbeat | **Done, awaiting review** |
| 4 | Assessments, rule engine, scoring, findings lifecycle, drift, comparison screen | — |
| 5 | Demo controls, failure scenarios, rollback, MQTT telemetry, UI polish, tests, demo script | — |

## Quick start

```bash
cp .env.example .env
docker compose up --build
# Console:  http://localhost:8080      API docs: http://localhost:8000/docs
```

### Without Docker (local development)

Requires Python 3.11+ (the container uses 3.12) and Node 20+.

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/uvicorn app.main:app --port 8000          # creates ./otprobe.db, runs migrations, seeds the simulated plant
cd frontend && npm install && npm run dev           # http://localhost:5173 (proxies /api to :8000)
cd agent && ../backend/.venv/bin/python -m otprobe_agent   # agent runtime: a SEPARATE process (needs httpx)
```

Log in as one of the seeded demo users (synthetic credentials): `operator / operator-demo`,
`approver / approver-demo`, `admin / admin-demo`.

`SPEED_FACTOR=0.3` makes simulated delays faster. `HEARTBEAT_INTERVAL_SEC=2` makes agents go STALE in 6 s and OFFLINE
in 12 s, which keeps the heartbeat demo short. Delete `backend/otprobe.db` to start from scratch until Reset POC
arrives in Phase 5.

### Tests

```bash
cd backend && .venv/bin/pytest            # unit, adapter contract, acceptance (A, B, C, D, G, J-partial, K)
.venv/bin/ruff check app tests && .venv/bin/lint-imports   # lint + layering contracts
```

## What works now (Phase 2)

- **Discovery** (`Discovery` screen / `POST /api/v1/discovery/jobs`): ARP → ICMP → SNMP over 192.168.20.0/24 and
  192.168.10.0/24. Progress goes 10/30/60/100%, and devices appear one by one over SSE. Assets are merged by MAC.
  Rediscovery flags unknown MACs as rogue. Level 0/1 runs in safe mode.
- **Assets**: the inventory table and an asset page with every field grouped and labelled with its source, stage and age.
- **Agentless probe** (`RUN AGENTLESS PROBE`): live ICMP → ARP → WinRM (with session stages) → WMI → SNMP → SSH →
  MQTT → collect → classify. Classification is data-driven (`rules/classification.yaml`), with confidence and
  evidence. Agent eligibility is data-driven (`rules/eligibility.yaml`).
- **PLC pages** show vendor, firmware and mode from SNMP. Deploy Agent is disabled with the reason "Traditional PLCs
  are handled agentless/read-only in this POC."
- **Network Map**: DMZ → conduit → switch → Purdue levels, built only from what OTProbe has observed (switch
  LLDP/FDB links, WMI netstat and MQTT flows).
- **Audit Logs**: a hash-chained audit trail with a verify button. Every action and transition carries a correlation ID.
- **Settings**: zones, the masked credential vault, the package repository and the adapter table.

## What works now (Phase 3)

- **Login and roles**: JWT login for the three seeded users. The API enforces role checks (operator requests,
  approver decides, admin does both and controls the demo). Every audit event names the acting user.
  `/auth/me` returns the user's permissions, so the console never decides what a role may do.
- **Approvals**: each approval records the requester, target, purpose, criticality, maintenance window, decision,
  approver, timestamp and reason. **A requester can never approve their own request, admins included**
  (`403 self-approval-forbidden`, audited as `APPROVAL_SELF_DENIED`). Critical assets (scada-01) need a maintenance
  window and an approval reason.
- **Package repository**: Probe Agent 1.0.0 (DEPRECATED) and 1.1.0 (ACTIVE), each with a real SHA-256, size,
  architecture, supported OS list and creation date.
- **Precheck**: nine checks, each PASS/FAIL/WARN with a detail line: reachable, hostname verified, WinRM available,
  authentication, package compatible, disk space, existing agent, server connectivity, reboot. DEPLOY AGENT stays
  disabled until precheck passes, and a pass is valid for 30 minutes.
- **Deployment**: connect → WinRM session → retrieve credential (mint the enrollment token) → transfer package (with
  %) → verify hash → install → service created → start → await enrollment. Every step is visible live.
- **Enrollment and agent trust**: the enrollment token is single-use, has a 15-minute TTL, is stored hashed and is
  bound to the asset and deployment. `POST /agents/enroll` exchanges it for a per-agent bearer credential, which is
  also stored hashed and shown once. Heartbeat and task polling require that credential.
- **Agent runtime**: `agent/otprobe_agent`, a separate process (its own container in Compose). It starts an agent for
  every virtual host where the installer ran. Each agent enrolls, heartbeats and long-polls for tasks **over
  outbound HTTP only**; the server never connects to it.
- **Heartbeat watchdog**: an agent goes STALE after 3 missed heartbeats and OFFLINE after 6, and returns to ONLINE on
  the next heartbeat. The Agents screen shows "Last heartbeat: N seconds ago".
- **State machines** (section 8): deployment, agent, approval and removal transitions are validated and audited.
  Removal is declared now; the rollback workflow that uses it arrives in Phase 5.
- **SIMULATION CONTROLS** (admin, partial): device faults for testing this phase: `heartbeat_blocked`,
  `agent_crashed`, WinRM failures, `package_checksum_mismatch`, `install_failure`, `enrollment_failure` and others.

## How to test acceptance criteria D and G

**Automated** (the agent runtime is spawned as a real subprocess; the API is served over loopback HTTP):

```bash
cd backend && .venv/bin/pytest tests/acceptance/test_d_deployment.py tests/acceptance/test_g_heartbeat.py -v
```

**Scripted through the real API** (needs a running API and agent runtime):

```bash
API=http://127.0.0.1:8000 ./scripts/try_d_g.sh
```

**By hand in the console**: see [docs/TESTING_D_G.md](docs/TESTING_D_G.md).

### Known gaps, scheduled for later phases

| Gap | Phase |
|---|---|
| Agents poll for tasks, but no tasks exist yet. Deep assessments, the rule engine and findings arrive then | 4 |
| Rogue devices raise an audit event and an asset flag, but not yet the `NET-ROGUE-001` finding | 4 |
| Remove agent / rollback, the "restart agent service" action, and the full failure matrix with UI messages | 5 |
| Full Demo Controls (configuration drift, telemetry, rogue injection, Reset POC) | 5 |
| The Assessments, Findings and MQTT Telemetry screens are placeholders | 4–5 |

## Repository layout

```
docker-compose.yml        api · agent-runtime · telemetry-sim · web  (+ volume otprobe-data)
backend/app/              FastAPI app: api/ services/ engines/ adapters/ sim/ workflow/ models/ schemas/
backend/app/adapters/base.py   protocol adapter interfaces (Phase 1 deliverable)
backend/tests/            unit/ contract/ acceptance/
agent/                    simulated agent runtime (separate process, outbound HTTP only)
telemetry/                telemetry simulator (separate process)
frontend/                 React + Vite + TypeScript console
rules/                    compliance / telemetry / classification / eligibility rules as DATA + schema.json
docs/                     design documents (below)
```

## Design documents

| Doc | What it covers |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Containers, layering, simulation boundary, agent model, workflows, SSE, security, API conventions, simplifications |
| [docs/SIMULATED_NETWORK.md](docs/SIMULATED_NETWORK.md) | Seed devices, MACs, per-protocol capabilities, host state, topology |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | ERD, tables, retention |
| [docs/ADAPTERS.md](docs/ADAPTERS.md) | Adapter interfaces, contract tests, how to replace each simulated adapter |
| [docs/PROVENANCE.md](docs/PROVENANCE.md) | Field provenance, provenance matrix, merge-by-MAC, classification |
| [docs/STATE_MACHINES.md](docs/STATE_MACHINES.md) | Discovery, deployment, agent, removal, finding (and supporting) state machines |
| [docs/FAILURE_MATRIX.md](docs/FAILURE_MATRIX.md) | Every injectable failure → state, UI message, audit event, recovery |
| [docs/RULES.md](docs/RULES.md) | Rule schema, condition grammar, evaluation order, score formula, drift |
| [docs/api/openapi.yaml](docs/api/openapi.yaml) | OpenAPI 3.1 contract draft |

`docs/DEMO_SCRIPT.md` is written in Phase 5.

## REAL vs SIMULATED

| Layer | Status |
|---|---|
| Web console, REST API, OpenAPI, RFC 7807 errors, idempotency, correlation IDs | **REAL** |
| Auth (JWT), RBAC, self-approval prevention, approvals | **REAL** |
| Database, migrations, persistence across restarts | **REAL** (SQLite) |
| Workflows and state machines, audit trail (hash-chained) | **REAL** |
| Enrollment tokens, agent credentials, revocation | **REAL** |
| Agent runtime process, heartbeats, task polling, evidence upload over HTTP | **REAL** (separate container) |
| Rule engine, rules-as-data, scoring, findings, drift | **REAL** |
| SSE live updates | **REAL** |
| Credential vault | **SIMULATED** secrets, real encrypted storage |
| Package repository and transfer | **SIMULATED** transfer, real metadata and hashes |
| ICMP, ARP, SNMP, WinRM, WMI/CIM, SSH adapters | **SIMULATED** |
| MQTT broker and telemetry | **SIMULATED** (in-process broker + telemetry-sim) |
| Devices, hosts, topology, faults | **SIMULATED** |

How to replace each simulated adapter with a real one: [docs/ADAPTERS.md §5](docs/ADAPTERS.md#5-replacing-simulated-adapters-with-real-ones).

## Phase 1 open questions

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
