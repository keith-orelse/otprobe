# Go agent

The Python agent from the POC is replaced by **one Go codebase** compiled into a separate binary for each
operating system and CPU. The agent is installed by a generated script, enrolls itself, and then runs a
**fixed, compiled-in set of read-only checks** (decision R4: no server-supplied scripts or commands).

"Different agents for different devices" is the combination of:

- a **build**: OS + CPU + toolchain variant, chosen from the target's probe data;
- a **profile**: which collectors run and which policy evaluates them, chosen from the device's classification.

## 1. Builds

All builds use `CGO_ENABLED=0`, `-trimpath` and `-ldflags "-s -w -X main.version=…"`. They are static, single files
with no runtime dependencies, about 8–12 MB.

| Build ID | GOOS/GOARCH | Toolchain | Runs on |
|---|---|---|---|
| `windows-amd64` | windows/amd64 | current Go | Windows 10, 11; Server 2016, 2019, 2022, 2025 |
| `windows-arm64` | windows/arm64 | current Go | Windows 11 on ARM |
| `windows-386` | windows/386 | current Go | 32-bit Windows 10 |
| `windows-legacy-amd64` | windows/amd64 | **Go 1.20.14** | Windows 7 SP1, 8.1; Server 2008 R2, 2012, 2012 R2 |
| `windows-legacy-386` | windows/386 | **Go 1.20.14** | 32-bit Windows 7 / Embedded Standard 7 |
| `linux-amd64`, `linux-arm64`, `linux-386` | linux/* | current Go | Linux kernel ≥ 3.2 (all current distributions) |
| `linux-armv7`, `linux-armv6` | linux/arm, `GOARM=7` / `6` | current Go | Raspberry Pi 2+ / Pi Zero and 1, ARM gateways and HMIs |
| `linux-legacy-amd64`, `linux-legacy-386` | linux/* | **Go 1.20.14** | Kernel 2.6.32–3.1 (RHEL/CentOS 6 era) |
| `darwin-amd64`, `darwin-arm64` | darwin/* | current Go | macOS (optional, decision pending) |

**Why the legacy builds:** Go 1.21 and later do not run on Windows before 10 / Server 2016. Those systems are
common on engineering workstations and SCADA servers, so a build with the last supporting toolchain (Go 1.20) is
needed.

**Trade-off:** Go 1.20 no longer gets security fixes. The agent's exposure is small: no listening port,
outbound TLS only, to a pinned CA. Even so, the console marks legacy agents with a `LEGACY BUILD` badge, and the
audit records it at deployment.

**Not supported by any build:** Windows XP, Vista, Server 2003/2008 (non-R2), and Linux kernels before 2.6.32.
These are `AGENTLESS_ONLY`.

Compatibility is enforced in CI:

- `go.mod` declares `go 1.20`.
- The code avoids Go 1.21+ features (`min`/`max` built-ins, `slices`, `maps`, `log/slog`, `clear`).
- Dependencies are pinned to versions that still build with Go 1.20.
- Every commit is built with **both** toolchains.

### Release artifacts

```
dist/1.0.0/
  otprobe-agent-1.0.0-windows-amd64.exe
  otprobe-agent-1.0.0-windows-legacy-amd64.exe
  otprobe-agent-1.0.0-linux-arm64
  …
  SHA256SUMS
  SHA256SUMS.sig        # Ed25519 signature with the offline release key
  manifest.json         # build → os, arch, variant, minOsVersion, sha256, size
```

The OTProbe server verifies `SHA256SUMS.sig` when a release is uploaded (`POST /api/v1/agent-builds`) and
refuses unsigned or tampered releases. Windows binaries are Authenticode-signed if the organisation provides a
code-signing certificate (open question O1).

## 2. Profiles

Profiles are data in `/rules/agent_profiles.yaml`:

```yaml
- id: windows-workstation
  os: windows
  collectors: [os, firewall, antivirus, patches, software, services, local_admins,
               password_policy, audit, usb, rdp, smb, network, agent]
  policy: windows-engineering-baseline
- id: windows-server
  os: windows
  collectors: [os, firewall, antivirus, patches, software, services, local_admins,
               password_policy, audit, usb, rdp, smb, network, agent]
  policy: windows-server-baseline
- id: linux-host
  os: linux
  collectors: [os, firewall, packages, patches, services, admins, password_policy,
               ssh, audit, usb, network, agent]
  policy: linux-host-baseline
```

The profile is chosen by `rules/eligibility.yaml` from the classification (see
[LIVE_PROTOCOLS.md](LIVE_PROTOCOLS.md) §5), shown on the deployment request, and can be changed by the requester
before approval. It is written into the agent's config at install. A profile can only select collectors that are
**compiled into** the binary. It cannot add new code.

## 3. Code layout

```
agent-go/
  go.mod                         module otprobe/agent, go 1.20
  cmd/otprobe-agent/main.go      subcommands: run · install · uninstall · start · stop · status · collect --dry-run · version
  internal/config/               load/validate agent.json; credential storage (DPAPI on Windows, 0600 file on Linux)
  internal/transport/            HTTPS client: pinned CA, enroll, heartbeat, long-poll tasks, evidence upload, backoff
  internal/tasks/                closed task set: RUN_ASSESSMENT · CANCEL · SET_INTERVALS
  internal/evidence/             evidence document builder (schema 1.1), size cap, gzip
  internal/collectors/
    collector.go                 interface: Name() · Collect(ctx) (map[string]any, error)
    windows/                     //go:build windows
    linux/                       //go:build linux
    darwin/                      //go:build darwin
    common/                      network interfaces, listening ports, agent self-health
  internal/service/
    windows.go                   x/sys/windows/svc: service, recovery actions (restart on failure)
    linux.go                     systemd unit / SysV init / OpenRC (detected)
  scripts/                       templates: install.ps1.tmpl · uninstall.ps1.tmpl · install.sh.tmpl · uninstall.sh.tmpl
  testdata/                      recorded outputs for collector tests (registry dumps, nft JSON, dpkg lists, …)
```

Dependencies are kept small:

- `golang.org/x/sys` for the Windows API, registry and services;
- `github.com/go-ole/go-ole` for COM (firewall policy, WMI, Windows Update Agent).

Linux uses only the standard library.

## 4. Runtime behaviour

| Aspect | Behaviour |
|---|---|
| Network | **Outbound HTTPS only**, to `OTPROBE_PUBLIC_URL`. Never listens on a port. Proxy supported (`HTTPS_PROXY`) |
| TLS | Accepts only certificates that chain to the pinned OTProbe CA (`caSha256` in config). Rejects anything else, including system-trusted certs |
| Enroll | `POST /api/v1/agents/enroll {enrollmentToken, os, arch, variant, agentVersion, hostFingerprint, profile}`. The token is wiped from `agent.json` after success |
| Host fingerprint | SHA-256 of (Windows `MachineGuid` + SMBIOS UUID) or (Linux `/etc/machine-id` + DMI `product_uuid`). If it changes (cloned VM, disk moved), the server raises `AGENT_FINGERPRINT_MISMATCH` and refuses tasks |
| Heartbeat | Interval set by the server in each response (default 10 s). Payload: version, uptime, last task, collector errors |
| Tasks | Long-poll `GET …/tasks?waitSec=20`. Unknown task types are rejected with `TASK_TYPE_UNSUPPORTED`. There is no "run command" task |
| Assessment | Runs the profile's collectors **one after another** at low priority (Windows `BELOW_NORMAL`; Linux `nice 10`, `ionice idle`). 120 s hard limit. Each collector has its own timeout; a failed collector is recorded in `collectors{}` and its section is **absent** (→ rules give UNKNOWN, as in the POC) |
| Evidence | JSON, gzip, ≤ 2 MB, schema `1.1` (adds `platform`, `profile`). Retried with backoff; the last unsent document is kept on disk until it is accepted |
| Revoked credential | `401 agent-credential-revoked` → the agent stops, sets its service start type to disabled, and exits. Removal then deletes the files |
| Resource use (target) | < 30 MB RAM idle, < 5 % of one core during an assessment. Linux unit sets `CPUQuota=20%`, `MemoryMax=128M` |
| Logs | Windows: Application event log (source `OTProbeAgent`) + rotating file. Linux: journald or `/var/log/otprobe/agent.log`. Secrets are never logged |
| Self-update | **None.** Upgrading means running a new install script through an approved deployment (`kind=UPGRADE`, keeps the agent identity) |

### File locations

| | Windows | Linux |
|---|---|---|
| Binary | `C:\Program Files\OTProbe\Agent\otprobe-agent.exe` | `/opt/otprobe/bin/otprobe-agent` |
| Config + credential | `C:\ProgramData\OTProbe\agent.json` (ACL: SYSTEM, Administrators; credential DPAPI-protected, machine scope) | `/etc/otprobe/agent.json` (0600 root) |
| State | `C:\ProgramData\OTProbe\state\` | `/var/lib/otprobe/` |
| Service | `OTProbeAgent` (LocalSystem, automatic, restart on failure ×3) | `otprobe-agent.service` (root, hardened: `NoNewPrivileges`, `ProtectSystem=full`, `PrivateTmp`) |

The agent runs as LocalSystem / root because the checks read security policy, the SAM, firewall state and
`sshd -T`. The risk is limited because it accepts **no inbound connections** and runs **no commands it receives**.

## 5. Install and uninstall scripts

The server renders a script per deployment from `agent-go/scripts/*.tmpl`. It **contains**:

- the server URL;
- the CA fingerprint;
- the build ID and SHA-256;
- a one-time enrollment token (15 min);
- a one-time download token;
- the deployment ID and the profile.

It contains **no** long-lived secrets.

### `install.ps1` (works on PowerShell 2.0+, so Windows 7 is supported)

```text
1. Check: running as Administrator; OS version ≥ the build's minimum; ≥ 200 MB free   → else exit 40/41
2. Get binary:   PULL  — HttpWebRequest with TLS 1.2 to /agent-dist/{build}?t=…  (PS 3+ / .NET 4.5+)
                 PUSH  — binary already copied by the server to %TEMP%\otprobe\ (legacy default)
3. Verify SHA-256 with [Security.Cryptography.SHA256]  (no Get-FileHash: that needs PS 4)  → mismatch: delete, exit 10
4. If an agent is already installed: stop it; keep identity only if kind=UPGRADE
5. Copy to Program Files; write agent.json; set ACLs                                   → exit 20 on failure
6. otprobe-agent.exe install   (the binary registers its own service + recovery actions)
7. otprobe-agent.exe start; wait for RUNNING (30 s)                                    → exit 30
8. Clean %TEMP%; print one JSON line: {"result":"ok","service":"RUNNING","version":"1.0.0"}
```

### `install.sh` (POSIX `sh`, so it works on busybox and Alpine)

> **As built in L6 (SSH deployment):** there is no separate `install.sh` file. The server runs the same steps as a
> fixed set of short POSIX `sh` commands over SSH (`app/adapters/real/net/ssh.py`, `deploy_command`), one per
> `RemoteOperation`, each with validated values. Root is used directly when the login is root, otherwise through
> `sudo -S` (password on stdin) or `sudo -n` (key login, NOPASSWD). The binary is uploaded by SFTP into a new private
> folder (`mktemp -d /var/tmp/otprobe.XXXXXXXXXX`), copied into `/opt/otprobe/` as root, and its SHA-256 is checked
> on that root-owned copy before it is installed. Failures map to `HASH_MISMATCH`, `INSTALL_FAILED`,
> `SERVICE_START_FAILED` and `NO_ROOT`. The step list below remains the plan for the manual one-liner.

```text
1. Check: root (or sudo); uname -m matches build arch; kernel version; free space   → exit 40/41
2. Get binary:   PULL — curl or wget with --cacert (pinned CA written by the script)
                 PUSH — already copied by the server via SFTP to /tmp/otprobe/
3. Verify: sha256sum, or busybox sha256sum, or openssl dgst                          → exit 10
4. Install to /opt/otprobe/bin; write /etc/otprobe/agent.json (0600)                 → exit 20
5. otprobe-agent install   (detects systemd / SysV / OpenRC and writes the unit)
6. otprobe-agent start; wait for active (30 s)                                       → exit 30
7. Print {"result":"ok",…}
```

### Exit codes → deployment failure reasons

| Exit | Meaning | Deployment `failure_reason` | Audit |
|---|---|---|---|
| 0 | OK | — | `AGENT_INSTALLED` |
| 10 | Hash mismatch | `HASH_MISMATCH` | `DEPLOY_HASH_FAIL` |
| 20 | Copy / config failed | `INSTALL_FAILED` | `DEPLOY_INSTALL_FAIL` |
| 30 | Service failed to start | `SERVICE_START_FAILED` | `DEPLOY_INSTALL_FAIL` |
| 40 | Not admin / not root | `INSUFFICIENT_PRIVILEGE` | `DEPLOY_INSTALL_FAIL` |
| 41 | OS / arch not supported by this build | `UNSUPPORTED_PLATFORM` | `DEPLOY_INSTALL_FAIL` |

`uninstall.ps1` / `uninstall.sh` stop the service, run `otprobe-agent uninstall`, delete the binary, config, state
and logs, and confirm that nothing is left. Exit codes: `0` OK, `50` stop failed, `60` remove failed (→ removal
`UNINSTALL_FAILED`, credential revoked anyway, as in the POC).

The scripts map one-to-one to `RemoteOperation` values: `INSTALL_AGENT`, `UNINSTALL_AGENT`,
`RESTART_AGENT_SERVICE`, `QUERY_AGENT_INSTALLED`. The precheck operations (`QUERY_DISK_FREE`,
`QUERY_SERVER_CONNECTIVITY`, …) are small fixed scripts in the same folder.

## 6. Collectors

### Windows

| Evidence path | Source | Win 7 / 2008 R2 note |
|---|---|---|
| `os.*` | `RtlGetVersion`; registry `ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR` | same |
| `firewall.state`, `firewall.profiles`, `firewall.defaultInbound` | COM `HNetCfg.FwPolicy2` | same |
| `antivirus.*` | WMI `root\Microsoft\Windows\Defender\MSFT_MpComputerStatus`; else `root\SecurityCenter2\AntiVirusProduct` (workstations) | SecurityCenter2 only. On servers without Defender: absent → UNKNOWN |
| `patches.installed[]`, `patches.last_installed_days` | WMI `Win32_QuickFixEngineering` | same |
| `patches.missing[]`, `patches.missing_count` | Windows Update Agent COM `IUpdateSearcher`, **only** if a WSUS server or an offline catalog is configured (open question O2) | same. With neither: absent → UNKNOWN |
| `software.installed[]` | Registry `Uninstall` keys: HKLM 64/32-bit + every **loaded** `HKU\<SID>` | same |
| `services.running[]` | Service Control Manager (`EnumServicesStatusEx`) | same |
| `local_admins.*` | `NetLocalGroupGetMembers` on SID `S-1-5-32-544` (works on non-English Windows) + `NetUserGetInfo` for enabled state | same |
| `password_policy.*` | `NetUserModalsGet` levels 0 and 3; complexity from `secedit /export /areas SECURITYPOLICY` (fixed command, temp file deleted) | same |
| `audit.logon_events` | `AuditQuerySystemPolicy`, Logon subcategory `{0CCE9215-69AE-11D9-BED3-505054503030}` | same |
| `usb.storage_policy` | `USBSTOR\Start` = 4 → `blocked`; `RemovableStorageDevices` deny-write policy → `read_only` | same |
| `rdp.enabled`, `rdp.nla_required` | `fDenyTSConnections`, `UserAuthentication` | same |
| `smb.v1_enabled` | `LanmanServer\Parameters\SMB1` / feature state | same |
| `network.*` | `GetAdaptersAddresses`, `GetExtendedTcpTable` | same |

### Linux

| Evidence path | Source |
|---|---|
| `os.*` | `/etc/os-release`, `uname` |
| `firewall.state`, `firewall.backend` | In order: `nft -j list ruleset`, `iptables-save`, `ufw` config, `firewall-cmd --state`. `enabled` = INPUT policy drop, or at least one INPUT filtering rule |
| `packages.installed[]` | `dpkg-query -W`, `rpm -qa`, or `apk info -v` |
| `patches.pending_security`, `patches.last_update_days` | `apt-get -s upgrade` (security origin) / `dnf updateinfo list --security` / `apk version -l '<'` from the **local** cache; last update from the dpkg log or `rpm --last`. If no repo metadata is available: absent → UNKNOWN |
| `services.running[]` | `systemctl list-units --type=service --state=running`, or SysV / OpenRC status |
| `admins.*` | Members of `sudo`, `wheel`, `admin`; accounts with UID 0 |
| `password_policy.*` | `/etc/login.defs`, `pwquality.conf`, `faillock.conf` / `pam_tally2` |
| `ssh.*` | `sshd -T`: `permitrootlogin`, `passwordauthentication`, `protocol`, `ciphers` |
| `audit.auditd` | auditd service state + loaded rules count |
| `usb.storage_policy` | `usb-storage` blacklisted or `install … /bin/false` in modprobe.d; module loaded or not |
| `network.*` | netlink / `/proc/net/*` |

Every command above is a **fixed string compiled into the binary**, run with a timeout and with no shell. Nothing
in a task or in the config can change which commands run.

## 7. Policies

- `windows_engineering_baseline.yaml`: kept. **Changes:**
  - `WIN-PATCH-001` (missing updates) stays, but gives UNKNOWN without a catalog.
  - New `WIN-PATCH-002` *Last security update within 90 days* (HIGH), from `patches.last_installed_days`.
  - New `WIN-RDP-001` *RDP requires NLA* (MEDIUM).
  - New `WIN-SMB-001` *SMBv1 disabled* (HIGH).
- `windows_server_baseline.yaml` (new): the same rules with server-appropriate parameters (for example a higher
  `max_enabled_local_admins`).
- `linux_host_baseline.yaml` (new):

| Rule | Check | Severity |
|---|---|---|
| `LNX-FW-001` | `firewall.state == 'enabled'` | HIGH |
| `LNX-PATCH-001` | `patches.pending_security == 0` | HIGH |
| `LNX-PATCH-002` | `patches.last_update_days <= 90` | MEDIUM |
| `LNX-OS-001` | `os.id + version_id not in $eol_releases` | HIGH |
| `LNX-SSH-001` | `ssh.permitrootlogin in ['no', 'prohibit-password']` | HIGH |
| `LNX-SSH-002` | `ssh.passwordauthentication == 'no'` | MEDIUM |
| `LNX-ADM-001` | `count admins.uid0 == 1` | HIGH |
| `LNX-PWD-001` | `password_policy.min_length >= 12` | MEDIUM |
| `LNX-PWD-002` | `password_policy.lockout_threshold > 0 and <= 10` | LOW |
| `LNX-AUD-001` | `audit.auditd == 'running'` | LOW |
| `LNX-USB-001` | `usb.storage_policy in ['blocked']` | MEDIUM |
| `AGT-HEALTH-001` | `agent.health == 'healthy'` | MEDIUM |

The rule engine, scoring formula and drift logic do not change ([RULES.md](RULES.md)).

## 8. Implementation notes (phase L4)

- **Windows collectors** run fixed PowerShell scripts compiled into the binary (the same shapes as the agentless
  WinRM scripts), plus `net accounts`, `secedit`, `auditpol` and registry reads. They need Windows PowerShell 3.0+.
  On a stock Windows 7 / 2008 R2 (PowerShell 2.0) the legacy build enrolls, heartbeats and reports agent health, but
  most collectors report an error and their rules stay UNKNOWN. Native API collectors for those systems are future work.
- **Transfer mode**: the server copies the verified binary into `C:\ProgramData\OTProbe\staging` over the WinRM
  session (PUSH), then runs the install script, which re-checks the SHA-256 before installing. PULL (the host
  downloads) is used only by the manual one-liner, which is not built yet (moved to L6).
- **Credential at rest (Windows)**: `C:\ProgramData\OTProbe\agent.json` is restricted to SYSTEM and Administrators
  by ACL. DPAPI encryption of the credential, as planned in §4, is not done yet.
- **Linux deployment over SSH** (built in L6): precheck (including root access and the CPU type), install, restart
  and removal over SSH, only to hosts whose SSH host key an agentless probe has pinned. Tested on a stand-in Linux
  host (a real SSH server and shell in a sandbox) with the real Go agent enrolling; the manual test on a real Linux
  machine is [TESTING_L6_LINUX.md](TESTING_L6_LINUX.md). Hosts with SFTP turned off cannot receive the binary yet.
- **macOS**: a small collector set used for development; no macOS policy and no service installation.
