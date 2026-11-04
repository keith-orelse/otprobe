# OTProbe demo script (about 20 minutes)

The story runs discovery → inventory → agentless probe → PLC → deep agent → assessment → drift → monitoring →
heartbeat failure → rollback.

**Before you start.** Start the stack (see the README; `HEARTBEAT_INTERVAL_SEC=2` keeps step 9 short) and open
http://localhost:5173. If you have demoed before: **Demo Controls → Reset POC** (type `RESET`).

The amber banner on every screen says *SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED*. The network is
simulated. The console, API, workflows, approvals, rules, findings and audit trail are real.

---

### 1. Discovery (operator): "What is on the plant network?"
**Discovery** → keep both subnets → START DISCOVERY.
- Devices appear one by one while progress goes 10, 30, 60, 100%. 192.168.10.0/24 is marked **SAFE MODE**: passive and
  read-only, at most 1 operation per second per host.
- Point out: the two sensors answered **ARP only**. ICMP is filtered, and "no ICMP reply does not mean offline".

### 2. Inventory: "What do we actually know?"
**Assets**: 9 devices, merged by MAC. The Windows hosts have **no hostname or OS yet**, because discovery alone
cannot know them (provenance). The switch and PLCs show their SNMP sysName.

### 3. Agentless probe: "Look closer without installing anything"
**eng-ws-01 → RUN AGENTLESS PROBE**: ICMP → ARP → WinRM (watch the 5 connection stages) → WMI → … → CLASSIFY.
- **Windows Engineering Workstation, 91%**, with evidence (Windows OS, WinRM, TIA Portal, hostname pattern, S7comm
  client).
- Every field carries a source badge (WMI/CIM, ARP, ICMP) and an age. Eligibility: **ELIGIBLE**.

### 4. PLC: "Not everything gets an agent"
**plc-01 → RUN AGENTLESS PROBE**: vendor, model, firmware V2.9 and mode RUN, all from SNMP (read-only, safe mode).
**DEPLOY AGENT is disabled**: "Traditional PLCs are handled agentless/read-only in this POC."

### 5. Deep agent: "Four eyes, then deploy"
eng-ws-01 → DEPLOY AGENT → SUBMIT FOR APPROVAL.
- Show that the operator **cannot approve** it. Sign in as **approver** → Approvals → Approve.
- Back as operator → RUN PRECHECK: 9 checks pass → DEPLOY AGENT. Watch the transfer %, hash verification, install,
  then *AWAIT ENROLLMENT*.
- The agent runtime is a **separate process**. It enrolls with the single-use token and heartbeats out to the
  server. **Agents** shows ONLINE, "Last heartbeat: 1 second ago".

### 6. Assessment: "Is it hardened?"
eng-ws-01 → **RUN DEEP ASSESSMENT** → **75%**: 7 pass, 2 fail, 1 warning, 1 unknown.
- **last run →**: missing patches FAIL, too many admins FAIL, `RemoteTool Demo` WARNING, USB policy **UNKNOWN**
  (UNKNOWN is excluded from the score, never guessed).
- Rules come from `rules/windows_engineering_baseline.yaml`, which is data, not code.
- **Agentless vs Deep Agent**: only the agent sees `RemoteTool Demo` (a per-user install), local admins, and the
  password and USB policies.

### 7. Drift: "Someone turned the firewall off"
**admin → Demo Controls → Host configuration → eng-ws-01 firewall: disabled.**
Operator → RUN DEEP ASSESSMENT → red banner: **WIN-FW-001 PASS → FAIL**, `firewall.state enabled → disabled`.
- **Findings**: HIGH, OPEN. **Audit Logs**: `CONFIGURATION_DRIFT_DETECTED`.
- Re-enable and reassess → **RESOLVED**. Disable and reassess → **REOPENED** (×1). The finding page shows the lifecycle.

### 8. Monitoring: "It keeps watching"
**Dashboard**: continuous monitoring (last heartbeat, last and next assessment, score), the drift feed and
configuration changes.
**MQTT Telemetry**: live sensor values from the separate telemetry simulator. Demo Controls → *Sensor temperature
97 → Raise* → `TEL-TEMP-002` **CRITICAL** appears. *Normal* → resolved.

### 9. Heartbeat failure: "What if the agent goes quiet?"
Demo Controls → `dev-ews01` → inject `heartbeat_blocked`. **Agents**: **STALE** (3 missed), then **OFFLINE** (6
missed). Clear the fault → **ONLINE**. Optional: `agent_crashed`, then **RESTART AGENT SERVICE**.

### 10. Rollback: "Take it off cleanly"
Agents → the agent → **REMOVE AGENT** → approver approves → **START ROLLBACK**: stop assessments → connect → stop
agent → uninstall → **revoke identity** → remove temp files → validate → **ROLLBACK COMPLETED**.
- Agent **REMOVED**. Its old credential is rejected (401).
- Assessments, findings, deployments and the audit log are all still there. **Audit Logs → verify**: the hash chain is
  valid.

**Wrap-up:** Settings shows each adapter as SIMULATED. Each can be replaced with a real one (pysnmp, pypsrp, aiomqtt,
…) by configuration only, with no business-logic change. See `docs/ADAPTERS.md §5`.
