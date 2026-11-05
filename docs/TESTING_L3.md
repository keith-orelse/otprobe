# Testing Phase L3 by hand

Agentless probing over **WinRM** (Windows), **SSH** (Linux / macOS) and the **read-only OT plugins**, plus the
safety controls around them. Each test lists what to do and what you should see. Allow about 45 minutes.

You need:

- **This Mac** (`192.168.0.160`) running OTProbe.
- **The Windows laptop** (`192.168.0.119`) on the same network.
- **The other MacBook** (optional, for SSH) on the same network.
- No PLC: `scripts/lab_devices.py` runs two fake industrial devices on this Mac.

Keep each laptop on the same home Wi-Fi as this Mac. Office or guest Wi-Fi isolates devices from each other, and
these tests then fail for that reason alone.

---

## 0. Start OTProbe

Terminal 1, in `backend/` (one line):

```bash
DATABASE_URL=sqlite:///./otprobe-live.db OTPROBE_ADMIN_PASSWORD='admin-pass-12345' OTPROBE_OPERATOR_PASSWORD='operator-pass-123' OTPROBE_APPROVER_PASSWORD='approver-pass-123' .venv/bin/uvicorn app.main:app --port 8000 --reload
```

Terminal 2: `cd ~/probing/frontend && npm run dev`, then open http://localhost:5173 and sign in as **admin** /
`admin-pass-12345`.

**Check:** the red banner reads `LIVE NETWORK - scope: …`. Under **Settings → Safety**, network activity is **armed**.
For these tests, turn **safe mode off** (Settings → Safety → *Turn safe mode off*, reason "L3 manual test").
Test C4 turns it back on.

---

## A. Windows laptop over WinRM

If you already ran the clean-up commands, set the laptop up again. In **PowerShell as Administrator**:

```powershell
Enable-PSRemoting -SkipNetworkProfileCheck -Force
$c=New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My
New-Item WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
New-NetFirewallRule -DisplayName W5986 -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
net user otprobe * /add
net localgroup Administrators otprobe /add
```

In OTProbe:

1. **Settings → Scan scope:** add `192.168.0.119/32`, profile **IT**, level **2**, authorization "my test laptop".
2. **Settings → Credential vault:**
   - **Protocol:** WinRM
   - **Username:** `.\otprobe`
   - **Password:** the one you set
   - **Skip certificate validation:** ticked
   - **Port:** empty

| # | Do | Expect |
|---|---|---|
| A1 | **Discovery**: tick `192.168.0.119/32`, START | Job COMPLETED. ARP finds the laptop with MAC `54:13:79:6C:4C:91`. TCP shows ports 5985 and 5986. Ping gets no reply (normal for Windows) |
| A2 | **Assets** → the laptop → **RUN AGENTLESS PROBE** → *details* | Step **WINRM** OK, with 5 stages: CONNECTING, TCP_OK, TLS_VALIDATED (`CN=DESKTOP-HSAHH95 … validation skipped`), AUTH_OK, SESSION_CREATED (PowerShell 5). Step **WMI** OK (8 groups). **EVALUATE**: 2 pass, 1 fail |
| A3 | Asset page → **Provenance** tab | OS *Windows 10 Home 22H2*, build 19045.x, Dell Inspiron 15-3567, firewall on for 3 profiles, Defender running, software and hotfix lists. Each field's source is **WinRM** or **WMI** |
| A4 | Asset page → **Compliance** tab, then **Findings** | WIN-FW-001 PASS, WIN-AV-001 PASS, **WIN-OS-001 FAIL** (Windows 10 Home is out of support). One open HIGH finding for WIN-OS-001 |
| A5 | Vault: save the WinRM profile again with a **wrong password** (same name, keep *Skip certificate validation* ticked), then probe | WINRM **FAILED** at **AUTH_OK**: "Authentication failed …". Probe PARTIAL. **Audit Logs** shows `WINRM_AUTH_FAILED`. The password appears nowhere |
| A6 | Restore the right password, **untick** *Skip certificate validation*, probe | WINRM **FAILED** at **TLS_VALIDATED**: "TLS certificate validation failed …". Stages stop there, **before AUTH_OK**, so no password was sent. Audit: `WINRM_TLS_INVALID` |
| A7 | Tick *Skip certificate validation* again and set **Port `5985`**, probe | WINRM OK over **HTTP + message encryption**. There's no TLS_VALIDATED stage, and the inventory is the same |
| A8 | Clear the port. On the laptop: `net stop winrm`. Probe | WINRM **SKIPPED**: "TCP 5986 closed …" (or "not answering"). Then `net start winrm` |

---

## B. The other MacBook over SSH (optional)

On the other Mac: **System Settings → General → Sharing → Remote Login: on**. Note its IP (**System Settings →
Wi-Fi → Details**) and its short username (`whoami` in Terminal).

In OTProbe:

1. **Scan scope:** add `<its IP>/32`, profile **IT**.
2. **Vault:**
   - **Protocol:** SSH. The name fills in as `OT-LINUX-SSH-RO`; it's used for macOS too.
   - **Username / Password:** that Mac's username and login password.

| # | Do | Expect |
|---|---|---|
| B1 | Discover it, then probe it | Step **SSH** OK: "macOS 26.x · kernel … · N packages". Provenance shows OS **macOS**, uptime, apps from /Applications with versions, running services, listening ports, firewall state. Eligibility: **NOT_SUPPORTED** ("macOS agent is not part of the first agent release") |
| B2 | **Audit Logs**, filter `SSH_HOST_KEY_PINNED` | One event with the Mac's SSH host key: trusted on first use. Probe again: no second event |
| B3 | Vault: wrong password, probe | SSH **FAILED**: "Authentication failed …". No commands ran |

---

## C. PLC plugins with the lab devices

Terminal 3, from the repository root:

```bash
backend/.venv/bin/python scripts/lab_devices.py
```

It prints each request a fake device receives. Leave it running and watch it during C1–C4. The Modbus device only
answers this Mac.

In OTProbe, under **Scan scope**, add `127.0.0.1/32` with profile **IT**.

| # | Do | Expect |
|---|---|---|
| C1 | Discover `127.0.0.1/32`, then probe the `127.0.0.1` asset | Step **OT** OK: "Modbus TCP … Schneider Electric BMX P34 2020 BMXP342020; EtherNet/IP … Rockwell Automation/Allen-Bradley 1769-L33ER/A LOGIX5333ER 103". Asset type **PLC**, eligibility **NOT_ELIGIBLE** (no agent on PLCs). **Terminal 3** shows only `function 0x2B` (Modbus) and `command 0x0063` (EtherNet/IP), with no `<-- NOT …` lines |
| C2 | Scan scope: change `127.0.0.1/32` to **OT_SENSITIVE**: remove the entry and add it again with that profile and **no plugins ticked**. Probe again | Step OT: "not enabled for this range: …". **Terminal 3 prints nothing new.** No identification request was sent |
| C3 | Tick only **modbus** on that row (click the `modbus` chip), probe | OT step: Modbus identified, EtherNet/IP "not enabled". Terminal 3: only a Modbus `0x2B` line |
| C4 | Settings → Safety: **turn safe mode on**, probe | OT step: "not enabled …" for both. Terminal 3: nothing. The banner shows `SAFE MODE` |

---

## D. Safety controls

| # | Do | Expect |
|---|---|---|
| D1 | Safe mode on (from C4). Start a probe of the Windows laptop, and click **STOP ALL** in the top bar while it runs (give a reason) | The banner turns to **STOPPED BY KILL SWITCH**. The probe ends CANCELLED or FAILED. New discovery or probes are refused: "Stopped by the kill switch" |
| D2 | As **operator** (sign out, sign in as `operator` / `operator-pass-123`): try **Re-arm** | Not offered: operators can stop but not re-arm. Sign in as admin → **Re-arm** with a reason → armed again |
| D3 | Discovery: type `192.168.0.0/24` in the "host / smaller subnet" box and START | Refused: "Target outside the scan scope". Nothing is sent |
| D4 | Scan scope: add `192.168.0.119/32` as **EXCLUDE**, then probe the laptop | Refused: "Target excluded from the scan scope". Remove the exclusion afterwards |
| D5 | **Audit Logs** | Every change above is listed with who did it and the reason: `SCOPE_CHANGED`, `SAFE_MODE_*`, `KILL_SWITCH_ENGAGED`, `SAFETY_REARMED`, `CREDENTIAL_PROFILE_*`, `CREDENTIAL_RETRIEVED` |

---

## E. Clean up

- **Terminal 3:** Ctrl+C stops the lab devices.
- **Windows laptop, Command Prompt as Administrator:**
  ```
  net user otprobe /delete
  winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
  netsh advfirewall firewall delete rule name=W5986
  powershell Disable-PSRemoting -Force
  sc config winrm start= disabled
  net stop winrm
  ```
- **Other Mac:** Remote Login off.
- **OTProbe:** delete the vault profiles you created, and remove the test ranges from the scan scope.

Send a screenshot of anything that doesn't match the "Expect" column.
