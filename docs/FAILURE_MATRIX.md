# Failure matrix

Each Demo Control writes a `sim_faults` row, or changes `sim_devices.state`, and appends `DEMO_CONTROL_APPLIED`
(actor = admin, details = control + params). OTProbe reacts **only through the adapters or the agent**, exactly as
it would on a real network. The failure-specific audit event below is written by the business service when the
failure is *observed*, not when it is injected.

Every row has an acceptance test (`tests/acceptance/test_h_failures.py::test_<fault_key>`) that injects the
fault, drives the workflow through the real API, and asserts the resulting state, the problem/UI message, the
audit event and the recovery.

## 1. Failures

| # | Demo Control (`fault_key`) | Scope | Surfaces in | Resulting state | UI message | Audit event | Recovery |
|---|---|---|---|---|---|---|---|
| 1 | Set device offline (`device_offline`) | any device | discovery, probe, precheck, heartbeat | Probe `FAILED` (all protocols `UNREACHABLE`). Asset `status=OFFLINE` once ARP and ICMP both fail. Agent → STALE → OFFLINE. Precheck REACHABLE = FAIL | "Device not reachable by ARP or ICMP" | `ASSET_UNREACHABLE` (+ `AGENT_STALE`/`AGENT_OFFLINE` if agent) | Set device online → rerun probe/precheck. Agent recovers on next heartbeat (`AGENT_RECOVERED`) |
| 2 | WinRM disabled (`winrm_disabled`) | Windows hosts | probe, precheck, deploy, removal | Probe `PARTIAL` (WinRM `DISABLED`, WMI `SKIPPED`). Precheck WINRM_AVAILABLE = FAIL → `PRECHECK_FAILED` | "WinRM service is disabled on target (5986 refused by service)" | `PRECHECK_FAILED` (detail `WINRM_DISABLED`) | Enable WinRM → Retry precheck |
| 3 | WinRM connection refused (`winrm_refused`) | Windows hosts | same | Session stops at `CONNECTING` → `REFUSED`. Precheck FAIL / deployment `FAILED` if mid-deploy | "Connection refused on 192.168.20.13:5986" | `WINRM_CONNECTION_REFUSED` | Clear fault → retry precheck / new deployment |
| 4 | WinRM timeout (`winrm_timeout`) | Windows hosts | same | Session stops at `CONNECTING` → `TIMEOUT` after `timeout_sec` | "WinRM connection timed out after 5 s" | `WINRM_TIMEOUT` | Clear fault → retry |
| 5 | WinRM wrong credentials (`winrm_bad_credentials`) | Windows hosts | probe, precheck | Stages stop at `AUTH_OK` → `AUTH_FAILED`. Precheck AUTHENTICATION = FAIL | "Authentication failed for profile OT-WINDOWS-INSTALLER (demo\agent-installer)" | `WINRM_AUTH_FAILED` | Clear fault (simulates a credential fix in the vault) → retry precheck |
| 6 | WinRM bad certificate (`winrm_bad_certificate`) | Windows hosts | probe, precheck | Stages stop at `TLS_VALIDATED` → `TLS_INVALID` | "TLS certificate validation failed: certificate not trusted (CN=eng-ws-01-selfsigned)" | `WINRM_TLS_INVALID` | Clear fault (simulates a cert reissue) → retry |
| 7 | ICMP blocked (`icmp_blocked`) | any | discovery, probe | `reachability.icmp=BLOCKED`. Asset stays `ONLINE` if ARP sees it | "No ICMP reply. This does not mean the device is offline; ARP response received." | `ICMP_BLOCKED_OBSERVED` | Informational. Clear fault to restore |
| 8 | SNMP timeout (`snmp_timeout`) | switch, PLCs, historian | discovery, probe | Discovery still `COMPLETED` (ARP data kept, SNMP fields absent). Probe `PARTIAL` | "SNMPv3 request timed out (profile OT-SNMPV3-RO). Identity fields not refreshed" | `SNMP_TIMEOUT` | Clear fault → rerun probe |
| 9 | Package checksum failure (`package_checksum_mismatch`) | deployment | deploy step VERIFY_HASH | Deployment `FAILED` (`failure_code=HASH_MISMATCH`). Transferred file removed. **Nothing installed**, no agent row | "Package hash mismatch: expected 3f2a…c91e, got 9b07…a4d2" | `DEPLOY_HASH_FAIL` | Clear fault → **Retry** (new deployment, `retry_of_id`) with a good package |
| 10 | Installation failure (`install_failure`) | deployment | deploy step INSTALL | Deployment `FAILED` (`INSTALL_FAILED`, simulated MSI exit 1603). The installer rolls itself back, so nothing remains installed | "Agent installer failed (exit code 1603). Installer rolled back" | `DEPLOY_INSTALL_FAIL` | Clear fault → Retry |
| 11 | Enrollment failure (`enrollment_failure`) | deployment / agent | `/agents/enroll` | Enroll returns `401 enrollment-token-invalid`. Agent `ERROR`. Deployment `FAILED` (`ENROLLMENT_FAILED`). The service is still installed on the host | "Agent could not enroll: enrollment token rejected" | `ENROLLMENT_TOKEN_REJECTED`, `AGENT_ENROLLMENT_FAILED` | Request **removal** to clean up the host, then Retry deployment |
| 12 | Break agent heartbeat (`heartbeat_blocked`) | agent host | watchdog | Agent `ONLINE → STALE` (3 missed) `→ OFFLINE` (6 missed). Assessments are queued, not dispatched | "Last heartbeat: 34 seconds ago. Agent STALE" | `AGENT_STALE`, `AGENT_OFFLINE` | Restore heartbeat → next heartbeat → `ONLINE` (`AGENT_RECOVERED`) |
| 13 | Crash agent (`agent_crashed`) | agent host | watchdog, agentless probe | As #12 (STALE → OFFLINE). In addition, an agentless probe shows service `OTProbeAgent: Stopped` | "Agent process not running (service stopped)" | `AGENT_STALE`, `AGENT_OFFLINE` | **Restart agent service** action (`POST /agents/{id}/restart`, via WinRM `START_SERVICE`), which clears the crash |
| 14 | Assessment timeout (`assessment_timeout`) | agent | assessment | The task is dispatched but never completes. At the deadline (`120 s × SPEED_FACTOR`), run `TIMED_OUT`, task `TIMED_OUT`. Findings are unchanged | "Assessment timed out: no evidence received from agent within 120 s" | `ASSESSMENT_TIMED_OUT` | Clear fault → Run assessment again |
| 15 | Rollback failure (`rollback_failure`) | removal | removal step UNINSTALL | Removal `FAILED`. Credential **revoked anyway** (compensation). Agent `ERROR` | "Uninstall failed (exit code 1603). Agent identity revoked; host requires cleanup" | `ROLLBACK_FAILED`, `AGENT_CREDENTIAL_REVOKED` | Clear fault → Retry removal (admin) → `ROLLBACK_COMPLETED`, agent `REMOVED` |
| 16 | PLC offline (`plc_offline`) | PLCs | discovery, probe, telemetry | PLC unreachable (as #1). MQTT `plc01/status` stops. After 3 missed status intervals: finding `TEL-PLC-001` OPEN HIGH | "PLC status telemetry stale (no message for 30 s)" | `TELEMETRY_THRESHOLD_EXCEEDED` | Set PLC online → status resumes → finding RESOLVED |
| 17 | Raise sensor temperature (`sensor_value_override`, param °C) | temperature sensor | telemetry | Readings go to the override value. > 80 °C → `TEL-TEMP-001` WARNING MEDIUM. > 95 °C → `TEL-TEMP-002` FAIL CRITICAL | "temperature-sensor-01 reported 97.0 °C (threshold 95 °C)" | `TELEMETRY_THRESHOLD_EXCEEDED` | Clear override → readings normal → findings RESOLVED |
| 18 | Inject rogue device (`inject_rogue`) | network | next discovery | New asset `is_rogue=true`. Finding `NET-ROGUE-001` OPEN HIGH | "Rogue device: unknown MAC DE:AD:BE:EF:20:66 at 192.168.20.66" | `ROGUE_DEVICE_DETECTED` | Remove the rogue (Demo Control) or **Authorize** the asset (admin) → finding RESOLVED |

## 2. Configuration changes (not failures, but drive drift)

| Demo Control | Effect on simulated host | Detected by | Expected result |
|---|---|---|---|
| Disable / enable firewall | `firewall.state = disabled/enabled` | next assessment (deep) or probe (agentless, on/off only) | `WIN-FW-001` PASS→FAIL + `CONFIGURATION_DRIFT_DETECTED` + finding OPEN HIGH; re-enable → RESOLVED; disable again → REOPENED |
| Stop / start antivirus | `antivirus.state = stopped/running` | assessment | `WIN-AV-001` FAIL CRITICAL |
| Install / remove unauthorized software | adds/removes `RemoteTool Demo 3.2` | assessment | `WIN-SW-001` WARNING MEDIUM / PASS |
| Remove a patch | moves a KB from installed to missing | assessment | `WIN-PATCH-001` observed count +1 (stays FAIL; `evidence_changes` row) |

## 3. Reset POC

| Control | Resulting state | UI message | Audit event | Recovery |
|---|---|---|---|---|
| Reset POC (typed confirmation `RESET`) | Simulated world re-seeded. Agents revoked/stopped. Knowledge tables cleared (discovery history optional). Audit log retained | "POC reset to seed state" | `POC_RESET` | n/a |
