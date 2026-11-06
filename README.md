# OTProbe

**OT asset discovery, agentless probing and deep agent probing on real networks.**

OTProbe discovers devices on approved subnets, identifies them without changing anything (ICMP, ARP, TCP, SNMP,
WinRM/WMI, SSH and read-only OT protocols), and, with approval, deploys a Go agent to Windows and Linux hosts for deep
compliance assessments. Every packet goes through a network gate: nothing outside the approved scan scope is ever
contacted, and **STOP ALL** halts everything at once.

The original simulated POC is preserved on the **`simulated`** branch. On this branch the simulator exists only
inside the test suite (`backend/tests/sim`).

Design: [docs/LIVE_ARCHITECTURE.md](docs/LIVE_ARCHITECTURE.md). Read
[docs/SAFETY_AND_SCOPE.md](docs/SAFETY_AND_SCOPE.md) first, and only scan networks you have written permission to
scan.

## Quick start (Linux or macOS)

Requires Python 3.11+ and Node 20+.

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
OTPROBE_ADMIN_PASSWORD='choose-a-long-one' OTPROBE_OPERATOR_PASSWORD='choose-another' \
OTPROBE_APPROVER_PASSWORD='and-a-third-one' .venv/bin/uvicorn app.main:app --port 8000
cd frontend && npm install && npm run dev            # http://localhost:5173
```

1. Sign in as `admin`. The banner reads **NO SCAN SCOPE CONFIGURED (scanning disabled)**.
2. **Settings → Scan scope:** add the approved subnet(s), with a safety profile (IT or OT-sensitive), Purdue level,
   who authorised it, and which OT plugins may run. Add exclusions for anything that must never be touched.
3. **Settings → Credential vault:** add SNMP, WinRM or SSH profiles if you want agentless probing to log in.
4. **Discovery:** pick the range and start. Safe mode is on by default (≤ 10 packets/s per range, ≤ 1 operation/s
   per host).

ICMP needs `net.ipv4.ping_group_range` to include the service's group, or `CAP_NET_RAW`. Docker Compose
(`docker compose up -d`) runs the API with host networking and only `CAP_NET_RAW` (not yet verified on a Docker
host).

To deploy the Go agent, the API must run over HTTPS so agents can pin its CA. Step by step:
[docs/TESTING_L4.md](docs/TESTING_L4.md).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OTPROBE_ADMIN_PASSWORD` / `_OPERATOR_` / `_APPROVER_` | generated | First-start passwords (≥ 12 characters). If empty, printed once in the API log |
| `SAFE_MODE` / `SCAN_MAX_PPS` | true / 50 | OT-sensitive limits on every range; global packet ceiling |
| `VAULT_KEY` / `VAULT_KEY_FILE` | generated | Credential vault key. Back it up |
| `OTPROBE_PUBLIC_URL`, `OTPROBE_TLS_CA_FILE` | — | HTTPS address agents call, and the CA they pin |
| `AGENT_DIST_DIR`, `AGENT_RELEASE_PUBKEY(_FILE)` | — | Signed Go agent builds and the release key that verifies them |
| `HEARTBEAT_INTERVAL_SEC` | 10 | Agent heartbeat period. STALE after 3 missed, OFFLINE after 6 |
| `ASSESSMENT_INTERVAL_SEC` / `ASSESSMENT_TIMEOUT_SEC` | 300 / 120 | Scheduled deep assessments and their timeout |
| `DATABASE_URL` | SQLite | Database |

## What it does

| Area | Highlights |
|---|---|
| Safety | Scan scope (include/exclude), IT and OT-sensitive profiles, safe mode, rate limits, kill switch, all audited |
| Discovery | ICMP sweep, kernel neighbour table (proxy-ARP aware), TCP connect, SNMP v2c/v3. Live progress, rogue detection |
| Agentless probing | WinRM/WMI and SSH with read-only command allow-lists; Modbus, S7, EtherNet/IP, BACnet, OPC UA and HTTP identification. Classification with evidence |
| Deployment | Request → approval (no self-approval) → 9-check precheck → install over WinRM (Windows) or SSH (Linux) → enrollment over pinned TLS. Rollback if anything fails after install |
| Go agent | Windows (modern and legacy), Linux, macOS; signed releases; outbound HTTPS only; fixed compiled-in checks |
| Compliance | Rules as YAML: Windows and Linux baselines, scoring with UNKNOWN excluded, findings lifecycle, drift, agentless vs deep comparison |
| Platform | REST `/api/v1`, Swagger at `/docs`, RFC 7807 errors, idempotency keys, SSE, hash-chained audit log, Alembic migrations |

Not built yet: manual one-line install, user management, and the bundled MQTT broker (see the phase table in [docs/LIVE_ARCHITECTURE.md](docs/LIVE_ARCHITECTURE.md)).

## Tests

```bash
cd backend
.venv/bin/pytest                    # unit, contract, acceptance A–K (simulator), live loopback tests
.venv/bin/pytest -m e2e             # Playwright browser smoke test (starts Vite itself)
.venv/bin/ruff check app tests && .venv/bin/lint-imports
cd ../agent-go && go test ./...     # Go agent
```

The acceptance tests run the workflows against the simulated plant in `backend/tests/sim`, which the tests plug in
with `create_app(settings, environment=SimEnvironment())`. The live tests use real protocol servers on 127.0.0.1
and the real Go agent. Manual guides for real hardware: [TESTING_L3.md](docs/TESTING_L3.md),
[TESTING_L4.md](docs/TESTING_L4.md), [TESTING_L5.md](docs/TESTING_L5.md),
[TESTING_L6_LINUX.md](docs/TESTING_L6_LINUX.md).

## Documentation

| Doc | Contents |
|---|---|
| [docs/LIVE_ARCHITECTURE.md](docs/LIVE_ARCHITECTURE.md) | Live design, branches, phases |
| [docs/SAFETY_AND_SCOPE.md](docs/SAFETY_AND_SCOPE.md) | Scan scope, network gate, safe mode, kill switch |
| [docs/LIVE_PROTOCOLS.md](docs/LIVE_PROTOCOLS.md) | Real adapters and the read-only OT plugins |
| [docs/GO_AGENT.md](docs/GO_AGENT.md) | Go agent builds, collectors, install and enrollment |
| [docs/LIVE_TEST_PLAN.md](docs/LIVE_TEST_PLAN.md) | Test stages, lab topology, acceptance criteria |
| [docs/RULES.md](docs/RULES.md) | Rule schema, condition language, scoring, drift |
| [docs/STATE_MACHINES.md](docs/STATE_MACHINES.md), [docs/PROVENANCE.md](docs/PROVENANCE.md), [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | Workflows, field provenance, tables |
| [docs/FAILURE_MATRIX.md](docs/FAILURE_MATRIX.md) | Faults of the test simulator, checked by acceptance H |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decisions log for every phase |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The original POC architecture (simulated branch) |

## Repository layout

```
docker-compose.yml   api (host network, CAP_NET_RAW) · web
backend/app/         api/ · services/ · engines/ · adapters/ (base + real) · workflow/ · models/
backend/alembic/     migrations 0001–0008
backend/tests/       unit · contract · acceptance (A–K) · live · e2e · sim/ (the simulated plant, tests only)
agent-go/            Go agent (build.sh builds 14 targets)
frontend/            React + Vite + TypeScript console
rules/               classification, eligibility and compliance rules (data) + schema.json
scripts/             make_lab_tls.py, sign_release.py, lab_devices.py
docs/                design and operating documentation
```
