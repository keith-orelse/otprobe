# Testing acceptance criteria D and G by hand

Start the three processes (each in its own terminal), or use `docker compose up`:

```bash
cd backend && SPEED_FACTOR=0.5 HEARTBEAT_INTERVAL_SEC=2 .venv/bin/uvicorn app.main:app --port 8000
cd frontend && npm run dev
cd agent && OTPROBE_API_URL=http://127.0.0.1:8000 ../backend/.venv/bin/python -m otprobe_agent
```

`HEARTBEAT_INTERVAL_SEC=2` gives STALE after about 6 s and OFFLINE after about 12 s. With the default of 10 s, these
take 30 s and 60 s. Open http://localhost:5173. Use a private window or **Sign out** to switch users.

## D: approval → precheck → deploy → enroll → heartbeat

| # | As | Do | Expect |
|---|---|---|---|
| 1 | operator | **Discovery** → untick 192.168.10.0/24 → START DISCOVERY | 5 devices appear one by one |
| 2 | operator | **Assets** → 192.168.20.13 → RUN AGENTLESS PROBE | Windows Engineering Workstation, eligibility ELIGIBLE. DEPLOY AGENT becomes enabled |
| 3 | operator | DEPLOY AGENT → SUBMIT FOR APPROVAL | Deployment page shows PENDING APPROVAL. RUN PRECHECK and DEPLOY AGENT are disabled ("Awaiting approval") |
| 4 | operator | **Approvals** | Approve/Reject are disabled: "Only an approver or admin can decide" |
| 5 | admin | Probe 192.168.20.14, request a deployment for it, then open **Approvals** | On the admin's own request, Approve is disabled: "You requested this; another approver must decide". The API returns `403 self-approval-forbidden` if called directly, and the audit log shows `APPROVAL_SELF_DENIED` |
| 6 | approver | **Approvals** → Approve the eng-ws-01 request | Status APPROVED, decided by approver |
| 7 | operator | Open the deployment → RUN PRECHECK | 9 checks, all PASS. DEPLOY AGENT becomes enabled ("Precheck passed: ready to deploy") |
| 8 | operator | DEPLOY AGENT | Steps run live, including WinRM stages and transfer %. At AWAIT ENROLLMENT the *agent runtime process* enrolls on its own; the deployment becomes COMPLETED |
| 9 | any | **Agents** | eng-ws-01 agent ONLINE, "Last heartbeat: 0–2 seconds ago", credential prefix `agt_…`. The asset page shows the agent strip |
| 10 | any | **Audit Logs** | DEPLOYMENT_REQUESTED by operator, APPROVAL_GRANTED by approver, DEPLOYMENT_STARTED by operator, AGENT_CREDENTIAL_ISSUED / AGENT_ENROLLED by `agent:…` |

Proof that the agent runs separately: stop the agent-runtime terminal (Ctrl-C). The agent goes STALE, then OFFLINE,
while the API keeps running. Start the runtime again: it reads its saved credential from the simulated host disk and
the agent returns to ONLINE without enrolling again.

## G: heartbeat loss and recovery

| # | As | Do | Expect |
|---|---|---|---|
| 1 | admin | **Demo Controls** → row `dev-ews01` → Inject fault… → `heartbeat_blocked` | The fault chip appears. Audited as DEMO_CONTROL_APPLIED by admin |
| 2 | any | **Agents** | After 3 missed heartbeats: **STALE**. After 6: **OFFLINE**. "Last heartbeat: N seconds ago" keeps counting |
| 3 | admin | **Demo Controls** → click `heartbeat_blocked ✕` | The fault is cleared |
| 4 | any | **Agents** | Next heartbeat: **ONLINE**, missed = 0 |
| 5 | any | **Audit Logs** | AGENT_STALE and AGENT_OFFLINE by `heartbeat-watchdog`, AGENT_RECOVERED by the agent |

Try also: `agent_crashed` stops the agent process (STALE → OFFLINE), and clearing it lets the runtime restart the
agent. On a fresh deployment, `package_checksum_mismatch` gives FAILED / HASH_MISMATCH with nothing installed, and
RETRY creates a new request that needs approval again.
