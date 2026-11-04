# OTProbe

**Simulated OT discovery, agentless probing and deep agent probing: a standalone, fully local proof of concept.**

> **SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED.**
> The OT network, its devices and every protocol response are simulated. The web console, REST API, database,
> workflows, approvals, compliance rules, findings and audit trail are real.

All five build phases are complete. Acceptance criteria A–K are automated (150 tests, including a Playwright browser
smoke test).

## Quick start

### Docker (one command)

```bash
cp .env.example .env
docker compose up --build
# Console http://localhost:8080 · API docs http://localhost:8000/docs
```

Compose starts four containers: `api`, `agent-runtime` and `telemetry-sim` (both separate processes that make only
outbound calls), and `web`. Data lives in the `otprobe-data` volume and survives restarts.
*The Compose setup is written but has not been run on the development machine, because Docker was not installed
there. The local setup below is what was verified.*

### Local processes (verified)

Requires Python 3.11+ and Node 20+.

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cd frontend && npm install
```

Run each of these in its own terminal:

```bash
cd backend   && SPEED_FACTOR=0.5 HEARTBEAT_INTERVAL_SEC=2 .venv/bin/uvicorn app.main:app --port 8000
cd frontend  && npm run dev                                                          # http://localhost:5173
cd agent     && OTPROBE_API_URL=http://127.0.0.1:8000 ../backend/.venv/bin/python -m otprobe_agent
cd telemetry && OTPROBE_API_URL=http://127.0.0.1:8000 ../backend/.venv/bin/python -m otprobe_telemetry
```

**Demo users** (synthetic credentials):

| Username | Password | Role |
|---|---|---|
| `operator` | `operator-demo` | requests discovery, probes, deployments and removals |
| `approver` | `approver-demo` | approves or rejects requests |
| `admin` | `admin-demo` | everything above, plus the simulation controls |

Follow **[docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)** for the full walkthrough. Use **Demo Controls → Reset POC**
to start over.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SPEED_FACTOR` | 1.0 | Scales all simulated delays |
| `SEED` | 42 | Deterministic latency, telemetry and noise |
| `HEARTBEAT_INTERVAL_SEC` | 10 | Agent heartbeat period. STALE after 3 missed, OFFLINE after 6 |
| `ASSESSMENT_INTERVAL_SEC` / `ASSESSMENT_TIMEOUT_SEC` | 300 / 120 | Scheduled deep assessments and their timeout |
| `ENROLLMENT_TOKEN_TTL_SEC` / `ENROLLMENT_TIMEOUT_SEC` | 900 / 120 | Token lifetime, and how long to wait for first contact |
| `TELEMETRY_INTERVAL_SEC` | 5 | Telemetry simulator publish period |
| `ADAPTER_MODE` / `ADAPTER_OVERRIDES` | simulated / — | Adapter selection, e.g. `snmp=real` |
| `DATABASE_URL`, `JWT_SECRET`, `SIM_SERVICE_TOKEN`, `VAULT_KEY` | see `.env.example` | Demo values |

## What it does

| Area | Highlights |
|---|---|
| Discovery | ARP → ICMP → SNMP. Progress goes 10/30/60/100% with live device events (SSE). Merge by MAC. Safe mode for Level 0/1. Rogue detection on rediscovery |
| Inventory and provenance | Every field records its source, stage (DISCOVERY / AGENTLESS / DEEP) and collection time. Effective values and per-stage comparison |
| Agentless probing | ICMP, ARP, WinRM (session stages), WMI/CIM, SNMP, SSH stub, MQTT. Data-driven classification with confidence and evidence. Data-driven eligibility |
| Auth and approvals | JWT, three roles, no self-approval for any role, everything audited with the acting user |
| Deployment | Credential vault, package repository (real SHA-256), 9-check precheck, live deploy steps, single-use hashed enrollment token, per-agent credential |
| Agents | A separate process, outbound only: enrolls, heartbeats, long-polls for tasks, uploads evidence. Restart and rollback with revocation |
| Compliance | Rules as YAML data, ordered evaluation, weighted score with UNKNOWN excluded, findings lifecycle, drift, configuration changes, Agentless vs Deep Agent comparison, scheduled assessments |
| Telemetry | In-process MQTT broker, a separate telemetry simulator, threshold and staleness rules → TELEMETRY findings |
| Simulation controls | All failure-matrix faults, host configuration changes, sensor override, rogue injection, Reset POC (typed confirmation) |
| Platform | REST `/api/v1`, Swagger at `/docs`, RFC 7807 errors, correlation IDs, idempotency keys, pagination, SSE, hash-chained audit log, SQLite with Alembic migrations |

## REAL vs SIMULATED

| Layer | Status |
|---|---|
| Web console; REST API; OpenAPI; RFC 7807; idempotency; correlation IDs; SSE | **REAL** |
| Auth (JWT); RBAC; self-approval prevention; approvals; maintenance windows | **REAL** |
| Database; migrations; persistence across restarts; Reset POC | **REAL** (SQLite) |
| Workflows and state machines; hash-chained audit trail | **REAL** |
| Enrollment tokens; agent credentials; revocation | **REAL** (real hashing; secrets shown once) |
| Agent runtime process; HTTP enroll, heartbeat, task polling and evidence upload | **REAL** (separate process/container) |
| Rule engine; rules as data; scoring; findings; drift; comparison | **REAL** |
| Telemetry ingest; telemetry rules; findings | **REAL** |
| Credential vault | **SIMULATED** secrets in real encrypted storage |
| Package repository and transfer | **SIMULATED** transfer; real metadata and SHA-256 |
| ICMP, ARP, SNMP, WinRM, WMI/CIM, SSH adapters | **SIMULATED** |
| MQTT broker; telemetry publishers | **SIMULATED** (in-process broker plus a separate telemetry-sim process) |
| OT devices, hosts, topology, faults; what the agent reads from its host | **SIMULATED** (`sim_*` tables, `/sim/v1`) |

## Replacing simulated adapters with real ones

The business services see only the interfaces in `backend/app/adapters/base.py`. Implementations are chosen by
configuration (`ADAPTER_MODE`, `ADAPTER_OVERRIDES`), and the same contract test suite (`tests/contract`) applies to
every implementation. Acceptance K proves that a swap needs no business-code change.

| Adapter | Suggested real implementation | Main gaps to close |
|---|---|---|
| ICMP | `icmplib` (unprivileged) | Raw-socket privileges; strict rate limits for Level 0/1 |
| ARP | Switch ARP/FDB tables over SNMP, or passive SPAN capture (`scapy`) | Avoid active sweeps on L1/L0; one collector per segment |
| SNMP | `pysnmp` (asyncio, v3 authPriv) | Vendor MIBs for PLC mode and firmware |
| WinRM | `pypsrp` (HTTPS 5986, NTLM/Kerberos) | Kerberos/JEA least privilege; signed scripts per `RemoteOperation` |
| WMI/CIM | `pypsrp` running `Get-CimInstance` | Installed-apps coverage (32/64-bit, per-user) |
| SSH | `asyncssh` | Host-key pinning; read-only collectors |
| MQTT | `aiomqtt` with Mosquitto/EMQX/HiveMQ | TLS/client certs; read-only ACL; client list from the broker admin API |
| Package transfer | Agent bootstrapper pulls a signed URL from OTProbe (or `pypsrp` copy/SMB) | Authenticode verification; resumable transfer |
| Credential vault | HashiCorp Vault (`hvac`), CyberArk, Azure Key Vault | Rotation; just-in-time credentials |

Details: [docs/ADAPTERS.md §5](docs/ADAPTERS.md#5-replacing-simulated-adapters-with-real-ones).

## Tests

```bash
cd backend
.venv/bin/pytest                    # 149 tests: unit, adapter contract, acceptance A–K (agent/telemetry as subprocesses)
.venv/bin/pytest -m e2e             # Playwright browser smoke test of the main journey (starts Vite itself)
.venv/bin/ruff check app tests ../agent ../telemetry && .venv/bin/lint-imports   # lint and 5 layering contracts
```

| Criterion | Test module(s) |
|---|---|
| A: progressive discovery, merge by MAC, sensors via ARP only | `tests/acceptance/test_a_discovery.py` |
| B: agentless probe on eng-ws-01, sources, classification | `test_b_agentless_probe.py` |
| C: PLC agentless; Deploy Agent disabled with reason | `test_c_plc.py` |
| D: no self-approval; approval → precheck → deploy → enroll → heartbeat; separate agent process | `test_d_deployment.py` |
| E: first deep assessment, mixed results, findings | `test_e_assessment.py` |
| F: firewall drift → finding OPEN → RESOLVED → REOPENED | `test_f_drift.py` |
| G: heartbeat loss → STALE → OFFLINE → ONLINE | `test_g_heartbeat.py` |
| H: every failure-matrix row | `test_h_failures.py`, `test_h_live_failures.py` (+ G, phase-4 extras) |
| I: rollback, revocation, history retained | `test_i_rollback.py` |
| J: restart persistence; Reset POC | `test_j_restart.py`, `test_j_reset.py` |
| K: adapter contracts; swap by configuration | `tests/contract/`, `test_k_adapter_swap.py` |

Scripted walkthroughs against a running stack: `scripts/try_d_g.sh`, `scripts/try_e_f.sh`.

## Documentation

| Doc | Contents |
|---|---|
| [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md) | The 10-step demo walkthrough |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Processes, layering, simulation boundary, agent model, security, API conventions, simplifications |
| [docs/SIMULATED_NETWORK.md](docs/SIMULATED_NETWORK.md) | Seed devices, topology, protocol behaviour |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | ERD and tables |
| [docs/ADAPTERS.md](docs/ADAPTERS.md) | Adapter interfaces, contract tests, replacement guide |
| [docs/PROVENANCE.md](docs/PROVENANCE.md) | Field provenance and the provenance matrix |
| [docs/STATE_MACHINES.md](docs/STATE_MACHINES.md) | All state machines and audit events |
| [docs/FAILURE_MATRIX.md](docs/FAILURE_MATRIX.md) | Every failure: state, message, audit event, recovery, test |
| [docs/RULES.md](docs/RULES.md) | Rule schema, condition language, evaluation order, scoring, drift |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisions log for every phase |
| [docs/TESTING_D_G.md](docs/TESTING_D_G.md), [docs/TESTING_E_F.md](docs/TESTING_E_F.md) | Manual test guides |
| Swagger (`/docs`) | The live, generated OpenAPI contract (source of truth) |

## Repository layout

```
docker-compose.yml   api · agent-runtime · telemetry-sim · web (+ volume otprobe-data)
backend/app/         api/ (v1 + sim) · services/ · engines/ · adapters/ (base + simulated) · sim/ · workflow/ · models/
backend/alembic/     migrations 0001–0004
backend/tests/       unit · contract · acceptance (A–K) · e2e (Playwright)
agent/               simulated Probe Agent runtime (separate process)
telemetry/           telemetry simulator (separate process)
frontend/            React + Vite + TypeScript console
rules/               compliance, telemetry, network, classification and eligibility rules (data) + schema.json
scripts/             try_d_g.sh, try_e_f.sh
docs/                design and operating documentation
```
