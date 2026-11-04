# Testing acceptance criteria E and F by hand

## 0. Start (or restart) the three processes

If you still have the Phase 3 processes running, **restart Terminals 1 and 3** so they load the Phase 4 code. The
database upgrades itself on start (migration `0003`), and existing data is kept.

```bash
# Terminal 1: API
cd backend && SPEED_FACTOR=0.5 HEARTBEAT_INTERVAL_SEC=2 .venv/bin/uvicorn app.main:app --port 8000
# Terminal 2: console (needs no restart; Vite picks up changes)
cd frontend && npm run dev
# Terminal 3: agent runtime
cd agent && OTPROBE_API_URL=http://127.0.0.1:8000 ../backend/.venv/bin/python -m otprobe_agent
```

Open http://localhost:5173. You need an **ONLINE agent on eng-ws-01** (192.168.20.13). If you don't have one, follow
D in [TESTING_D_G.md](TESTING_D_G.md): discover → probe → request → approve → precheck → deploy.

## E: first deep assessment

| # | As | Do | Expect |
|---|---|---|---|
| 1 | operator | **Assets** → 192.168.20.13 | With an agent present, the header shows **RUN DEEP ASSESSMENT**; the **Compliance** tab holds the score panel |
| 2 | operator | RUN DEEP ASSESSMENT (header) | Terminal 3 logs `task … RUN_ASSESSMENT` and `evidence uploaded`. The panel shows **75%**, *7 pass · 2 fail · 1 warning · 1 unknown*, and 3 open findings |
| 3 | operator | **Compliance** tab → **last run →** | All 11 rules with observed/expected values. Mixed results: WIN-PATCH-001 FAIL (2 missing), WIN-ADM-001 FAIL (3 admins), WIN-SW-001 WARNING (`RemoteTool Demo`), WIN-USB-001 UNKNOWN ("evidence 'usb.storage_policy' not present"), the rest PASS. *Show uploaded evidence* shows the document the agent sent |
| 4 | any | **Findings** | 3 deep-agent findings on eng-ws-01 (HIGH WIN-PATCH-001, MEDIUM WIN-SW-001, MEDIUM WIN-ADM-001). If you probed eng-ws-02, there is also an AGENTLESS finding: WIN-OS-001 (Windows 10 is unsupported) |
| 5 | any | Asset page → **Agentless vs Deep** tab | Applications *Partial 4* vs *Full*, "Only visible to the agent: … RemoteTool Demo". Firewall *Available* vs *Detailed*. Local admins *Not collected* vs *Collected*. Security policies *Limited* vs *Collected*. Continuous monitoring *No* vs *Yes*. Heartbeat *N/A* vs *Yes* |
| 6 | any | `rules/windows_engineering_baseline.yaml` | The rules that produced all of the above. Swagger `GET /api/v1/policies` shows the loaded version |

## F: drift → finding → resolved → reopened

| # | As | Do | Expect |
|---|---|---|---|
| 1 | admin | **Demo Controls** → "Host configuration" → eng-ws-01 → firewall **disabled** | Current value shows `disabled`. Audited as DEMO_CONTROL_APPLIED |
| 2 | operator | eng-ws-01 → RUN DEEP ASSESSMENT → **last run →** | Red banner *Configuration drift detected*: `WIN-FW-001 PASS → FAIL · firewall.state: enabled → disabled`. The row is highlighted, with Previous = PASS. Configuration changes list `firewall.state` and the profiles |
| 3 | any | **Findings** | `HIGH · OPEN · eng-ws-01 · WIN-FW-001 · observed disabled`. API check: `GET /api/v1/findings?ruleId=WIN-FW-001` in Swagger |
| 4 | any | **Audit Logs** → filter `CONFIGURATION_DRIFT_DETECTED` | One event with ruleId, from PASS, to FAIL, before/after |
| 5 | admin, then operator | Firewall **enabled** → RUN DEEP ASSESSMENT | WIN-FW-001 PASS. The finding (Findings → *All statuses*) is **RESOLVED** |
| 6 | admin, then operator | Firewall **disabled** → RUN DEEP ASSESSMENT | A new drift event. The finding is **REOPENED**, ×1. Its page shows the lifecycle `OPEN → RESOLVED → REOPENED` and both drift events |
| 7 | any | **Dashboard** | Continuous monitoring row (last heartbeat, last/next assessment, score, open findings) and the drift & configuration-changes feed |

Optional: as admin, **Accept risk** on a finding (reason required). It stays ACCEPTED_RISK while failing and resolves
when the check passes. Operators see the button disabled with "Only an admin can accept risk".

Faster alternative for all of the above: `API=http://127.0.0.1:8000 ./scripts/try_e_f.sh`.
