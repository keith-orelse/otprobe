# Testing Phase L5 by hand

New compliance rules and drift detection on the real Windows laptop (`192.168.0.110`), using the Go agent. The MQTT
broker part of L5 is deferred. Allow about 30 minutes.

## 0. Start

Restart the API so the new rule files are loaded: Ctrl+C in Terminal 1, then the same one-line HTTPS command as in
`docs/TESTING_L4.md` §3 (with `OTPROBE_PUBLIC_URL=https://<this Mac's IP>:8000`). The laptop must be set up for
WinRM, with the `otprobe` account and both WinRM vault profiles, as in L4.

## 1. Classification

| # | Do | Expect |
|---|---|---|
| 1.1 | **Assets → DESKTOP-HSAHH95 → RUN AGENTLESS PROBE** | CLASSIFY: **Windows Workstation (100%)**, no longer "Windows Engineering Workstation". Level **L3**, criticality **MEDIUM**, eligibility **ELIGIBLE** |
| 1.2 | Asset page → **Classification** panel | The two matched signals: "Windows desktop OS" and "No engineering or SCADA software found" |

## 2. Deploy the agent again

The agent was removed at the end of L4. Repeat the L4 deployment (as operator, approver, then operator again):
DEPLOY AGENT → approve → RUN PRECHECK → DEPLOY AGENT. **Expect** COMPLETED and the agent ONLINE.

## 3. New Windows rules

| # | Do | Expect |
|---|---|---|
| 3.1 | Asset page → **RUN DEEP ASSESSMENT**, then open the assessment | Policy version **1.1.0**. New rules: **WIN-PATCH-002** (observed = days since the newest hotfix: PASS if within 90 days), **WIN-SMB-001** (SMBv1 off: PASS on an up-to-date Windows 10). **WIN-RDP-001** is not listed, because Windows 10 Home has no Remote Desktop server, so the rule does not apply |
| 3.2 | Same page | The earlier results are still there: WIN-OS-001 FAIL, WIN-PWD-001 FAIL (minimum length 0), WIN-USB-001 FAIL |

## 4. Drift on a real host

| # | Do | Expect |
|---|---|---|
| 4.1 | On the laptop, **Command Prompt as Administrator**: `netsh advfirewall set privateprofile state off` | (the Private firewall profile is now off) |
| 4.2 | **RUN DEEP ASSESSMENT** | **WIN-FW-001 FAIL** (state `partial`). A **drift** event "PASS → FAIL" appears on the asset and on the Dashboard, `CONFIGURATION_DRIFT_DETECTED` in Audit Logs, and a new HIGH finding for WIN-FW-001 |
| 4.3 | `netsh advfirewall set privateprofile state on`, then **RUN DEEP ASSESSMENT** | WIN-FW-001 **PASS**, and the finding is **RESOLVED** |
| 4.4 | **Dashboard → Configuration changes** | The evidence changes `firewall.profiles.private` on → off, then off → on, each with the assessment that saw it. These are recorded even when no rule status changes |

## 5. Heartbeat loss (missed in L4)

| # | Do | Expect |
|---|---|---|
| 5.1 | On the laptop: `net stop OTProbeAgent`, then wait 70 seconds | Agent **STALE** after about 30 s, **OFFLINE** after about 60 s (`AGENT_STALE`, `AGENT_OFFLINE` in Audit Logs) |
| 5.2 | **Agents → the agent → RESTART AGENT SERVICE** | **ONLINE** again within about 10 s (`AGENT_RECOVERED`) |

## 6. Clean up

Remove the agent (L4 §8), then the laptop clean-up commands in L4 §9.

**What cannot be tested here:** the Linux baseline needs a Linux host with the agent, and SSH deployment comes in
L6. It is covered by automated tests on Linux-shaped evidence.
