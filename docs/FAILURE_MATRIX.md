# Failure matrix

Each Demo Control writes a `sim_faults` row or changes `sim_devices.state`, and appends `DEMO_CONTROL_APPLIED`
(actor = admin). OTProbe reacts **only through the adapters or the agent**, exactly as it would on a real network.
The failure-specific audit event is written when the failure is *observed*, not when it is injected.

Every row is automated. The **Test** column names the test that injects the fault, drives the workflow through the
real API, and checks the resulting state, message, audit event and recovery.

## 1. Failures

| # | Control (`fault`) | Surfaces in | Resulting state | Message (exact) | Audit event | Recovery | Test |
|---|---|---|---|---|---|---|---|
| 1 | Device offline (`device_offline`) | discovery, probe, precheck, heartbeat | Probe `FAILED`, asset `OFFLINE`, agent STALE → OFFLINE | "Device not reachable by ARP or ICMP" | `ASSET_UNREACHABLE` | Clear → probe again | `test_h_failures::test_row01_device_offline` |
| 2 | WinRM disabled (`winrm_disabled`) | probe, precheck, deploy | Precheck `WINRM_AVAILABLE` FAIL → `PRECHECK_FAILED`; DEPLOY AGENT disabled | "WinRM service is disabled on target (5986 refused by service)" | `WINRM_DISABLED`, `PRECHECK_FAILED` | Clear → RUN PRECHECK | `test_rows02_06_winrm_failures[winrm_disabled]` |
| 3 | WinRM refused (`winrm_refused`) | same | as #2 | "Connection refused on 192.168.20.13:5986" | `WINRM_CONNECTION_REFUSED` | Clear → RUN PRECHECK | `…[winrm_refused]` |
| 4 | WinRM timeout (`winrm_timeout`) | same | as #2 | "WinRM connection timed out after 5 s" | `WINRM_TIMEOUT` | Clear → RUN PRECHECK | `…[winrm_timeout]` |
| 5 | WinRM wrong credentials (`winrm_bad_credentials`) | probe, precheck | Precheck `AUTHENTICATION` FAIL; probe `PARTIAL`, WINRM step FAILED at AUTH_OK | "Authentication failed for profile OT-WINDOWS-INSTALLER (demo\agent-installer)" | `WINRM_AUTH_FAILED` | Clear (credential fixed) → RUN PRECHECK | `…[winrm_bad_credentials]`, `test_b::test_probe_with_wrong_credentials_is_partial` |
| 6 | WinRM bad certificate (`winrm_bad_certificate`) | probe, precheck | Precheck `AUTHENTICATION` FAIL; session stops at TLS_VALIDATED | "TLS certificate validation failed: certificate not trusted (CN=eng-ws-01-selfsigned)" | `WINRM_TLS_INVALID` | Clear (cert reissued) → RUN PRECHECK | `…[winrm_bad_certificate]`, `test_adapter_contract::test_c11` |
| 7 | ICMP blocked (`icmp_blocked`) | discovery, probe | `reachability.icmp=BLOCKED`; asset stays ONLINE (ARP answers) | "BLOCKED: no ICMP reply. This does not mean the device is offline." | `ICMP_BLOCKED_OBSERVED` | Informational; clear to restore | `test_row07_icmp_blocked` |
| 8 | SNMP timeout (`snmp_timeout`) | discovery, probe | Discovery `COMPLETED` (ARP data kept); probe `PARTIAL`; earlier identity kept | "SNMPv3 request timed out (profile OT-SNMPV3-RO). Identity fields not refreshed" | `SNMP_TIMEOUT` | Clear → probe again | `test_row08_snmp_timeout` |
| 9 | Package checksum failure (`package_checksum_mismatch`) | deploy VERIFY_HASH | Deployment `FAILED` / `HASH_MISMATCH`; staged file removed; **nothing installed**, no agent row | "Package hash mismatch: expected 894b…, got 9b07…" | `DEPLOY_HASH_FAIL` | Clear → RETRY (new request, needs approval) | `test_row09_checksum_mismatch`, `test_d::test_checksum_failure_installs_nothing` |
| 10 | Installation failure (`install_failure`) | deploy INSTALL | Deployment `FAILED` / `INSTALL_FAILED`; installer rolled back | "Agent installer failed (exit code 1603). Installer rolled back" | `DEPLOY_INSTALL_FAIL` | Clear → RETRY | `test_row10_install_failure` |
| 11 | Enrollment failure (`enrollment_failure`) | `/agents/enroll` | Token rejected (401). After `ENROLLMENT_TIMEOUT_SEC`: deployment `FAILED` / `ENROLLMENT_FAILED`, agent `ERROR`, token revoked | "No successful enrollment within 120 s" | `ENROLLMENT_TOKEN_REJECTED`, `AGENT_ENROLLMENT_FAILED` | Clear → REMOVE AGENT (cleans host) → RETRY deployment | `test_h_live_failures::test_row11_enrollment_failure` |
| 12 | Break heartbeat (`heartbeat_blocked`) | watchdog | Agent ONLINE → STALE (3 missed) → OFFLINE (6 missed); queued tasks wait | "Last heartbeat: N seconds ago" | `AGENT_STALE`, `AGENT_OFFLINE` | Clear → next heartbeat → ONLINE (`AGENT_RECOVERED`) | `test_g_heartbeat::test_heartbeat_loss_and_recovery` |
| 13 | Crash agent (`agent_crashed`) | watchdog, agentless probe | STALE → OFFLINE; simulated service `OTProbeAgent` Stopped (missing from `services.running`) | "Last heartbeat: N seconds ago" | `AGENT_STALE`, `AGENT_OFFLINE` | **RESTART AGENT SERVICE** (`POST /agents/{id}/restart`, WinRM) → ONLINE | `test_h_live_failures::test_row13_agent_crash_and_restart` |
| 14 | Assessment timeout (`assessment_timeout`) | assessment | Task dispatched, never completed → run `TIMED_OUT`; findings unchanged | "Assessment timed out: no evidence received from agent within 120 s" | `ASSESSMENT_TIMED_OUT` | Clear → RUN DEEP ASSESSMENT | `test_phase4_extras::test_scheduler_and_timeout` |
| 15 | Rollback failure (`rollback_failure`) | removal UNINSTALL | Removal `FAILED` / `UNINSTALL_FAILED`; credential **revoked anyway**; agent `ERROR` | "Uninstall failed (exit code 1603)" | `ROLLBACK_FAILED`, `AGENT_CREDENTIAL_REVOKED` | Clear → RETRY (admin, same approval) → `COMPLETED`, agent `REMOVED` | `test_i_rollback::test_rollback_failure_then_retry` |
| 16 | PLC offline (`plc_offline`) | probe, telemetry | PLC unreachable; status messages stop; after 30 s finding `TEL-PLC-001` OPEN HIGH (TELEMETRY) | observed "no message for N s" | `TELEMETRY_THRESHOLD_EXCEEDED` | Clear → status resumes → finding RESOLVED | `test_row16_plc_offline` |
| 17 | Raise sensor temperature (`sensor_value_override`, `{"value": 97}`) | telemetry | > 80 °C: `TEL-TEMP-001` WARNING MEDIUM. > 95 °C: `TEL-TEMP-002` FAIL CRITICAL | "sensor01 (sensor01) reported 97.0 C on factory/line1/sensor01/temperature; expected <= 95 C" | `TELEMETRY_THRESHOLD_EXCEEDED` | Normal → readings normal → findings RESOLVED | `test_row17_sensor_temperature`, `test_telemetry_process` |
| 18 | Inject rogue device (`POST /demo/rogue`) | next discovery | New asset `isRogue`; finding `NET-ROGUE-001` OPEN HIGH (DISCOVERY) | "Rogue device: unknown MAC DE:AD:BE:EF:20:66 at 192.168.20.66" | `ROGUE_DEVICE_DETECTED` | Admin authorizes the asset → finding RESOLVED | `test_row18_inject_rogue` |
| — | Server unreachable from host (`server_unreachable`) | precheck | `SERVER_CONNECTIVITY` FAIL | "TcpTestSucceeded=False to <server>:443" | `PRECHECK_FAILED` | Clear → RUN PRECHECK | (precheck unit path) |

## 2. Configuration changes (not failures, but they drive drift)

| Control (`POST /demo/devices/{id}/config`) | Effect on simulated host | Detected by | Expected result | Test |
|---|---|---|---|---|
| `firewall` enabled / disabled | `firewall.state`, all profiles | deep assessment; agentless probe (on/off) | `WIN-FW-001` PASS → FAIL + `CONFIGURATION_DRIFT_DETECTED` + finding OPEN HIGH; re-enable → RESOLVED; disable again → REOPENED | `test_f_drift` |
| `antivirus` running / stopped | `antivirus.state`, WinDefend service | assessment, probe | `WIN-AV-001` FAIL CRITICAL | (rule unit tests) |
| `unauthorized_software` install / remove | adds `AnyRemote Demo` (machine scope) or removes it and `RemoteTool Demo` | deep assessment | `WIN-SW-001` WARNING MEDIUM / PASS | (rule unit tests) |
| `remove_patch` latest | moves the newest KB to missing | deep assessment | `WIN-PATCH-001` observed +1 (an `evidence_changes` row) | — |

## 3. Reset POC

| Control | Resulting state | Message | Audit event | Test |
|---|---|---|---|---|
| Reset POC (`POST /demo/reset`, typed `"RESET"`) | Simulated world re-seeded; all agent credentials revoked; knowledge tables cleared; discovery history archived (or cleared); **audit log retained** | "POC reset to seed state" | `POC_RESET` | `test_j_reset` |
