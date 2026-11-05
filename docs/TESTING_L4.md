# Testing Phase L4 by hand

Deploy the **Go agent** to the Windows laptop through the full workflow, then:

- watch it enroll over HTTPS with the CA pinned;
- run a deep assessment with real evidence;
- break and restore its heartbeat;
- remove it.

Allow about 45 minutes. Each step says what to do and what you should see.

You need:

- **This Mac** (`192.168.0.160`) running OTProbe.
- **The Windows laptop** (`192.168.0.119`) on the same home network, set up for WinRM as in Phase 3. If you cleaned
  it up, redo step 2.

---

## 1. One-time preparation on this Mac (already done once; repeat only if something changed)

```bash
cd ~/probing
agent-go/build.sh 0.4.0                                                       # builds 14 agents into agent-go/dist/0.4.0
backend/.venv/bin/python scripts/sign_release.py agent-go/dist/0.4.0 --key keys/otprobe-release.key
backend/.venv/bin/python scripts/make_lab_tls.py 192.168.0.160                # HTTPS certificates for this Mac's IP
```

- Re-run `make_lab_tls.py` only if your Mac's IP changes.
- The release key in `keys/` and the certificates in `backend/tls/` are git-ignored.

## 2. The Windows laptop (only if you cleaned it up after Phase 3)

In **PowerShell as Administrator**:

```powershell
Enable-PSRemoting -SkipNetworkProfileCheck -Force
$c=New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation cert:\LocalMachine\My
New-Item WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $c.Thumbprint -Force
New-NetFirewallRule -DisplayName W5986 -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
net user otprobe * /add
net localgroup Administrators otprobe /add
```

## 3. Start OTProbe with HTTPS

The agent only talks to OTProbe over HTTPS, and it checks the server's certificate against the pinned CA. So the API
now runs with TLS and listens on the network: the laptop must reach it.

**Terminal 1**, in `backend/` (stop the old API with Ctrl+C first). This is one line:

```bash
DATABASE_URL=sqlite:///./otprobe-live.db OTPROBE_ADMIN_PASSWORD='admin-pass-12345' OTPROBE_OPERATOR_PASSWORD='operator-pass-123' OTPROBE_APPROVER_PASSWORD='approver-pass-123' OTPROBE_PUBLIC_URL=https://192.168.0.160:8000 OTPROBE_TLS_CA_FILE=tls/otprobe-ca.pem AGENT_RELEASE_PUBKEY_FILE=../keys/otprobe-release.pub .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --ssl-certfile tls/otprobe-server.pem --ssl-keyfile tls/otprobe-server.key --reload
```

If macOS asks **"Do you want the application Python to accept incoming network connections?"**, click **Allow**.
Without it the agent can't reach the server.

**Terminal 2**:

```bash
cd ~/probing/frontend && OTPROBE_API=https://127.0.0.1:8000 npm run dev
```

Open http://localhost:5173 and sign in as **admin**.

| # | Check | Expect |
|---|---|---|
| 3.1 | **Settings → Agent builds** | 14 builds of version **0.4.0**, including `windows-amd64` and `windows-legacy-amd64` (marked LEGACY) |
| 3.2 | **Settings → Safety** | Safe mode **off** (turn it off if needed) |
| 3.3 | **Settings → Scan scope** | `192.168.0.119/32` is listed (profile IT). Add it if not |

## 4. Credentials

**Settings → Credential vault**. Both profiles use the `otprobe` account:

| Profile name | Protocol | Username | Password | Skip certificate validation |
|---|---|---|---|---|
| `OT-WINDOWS-READONLY` | WinRM | `.\otprobe` | its password | ticked |
| `OT-WINDOWS-INSTALLER` | WinRM | `.\otprobe` | its password | ticked |

Choosing **WinRM** fills in `OT-WINDOWS-READONLY`. For the second profile, overwrite the name with
`OT-WINDOWS-INSTALLER`.

## 5. Deploy the agent

| # | Do | Expect |
|---|---|---|
| 5.1 | **Assets → 192.168.0.119 → RUN AGENTLESS PROBE** | WINRM and WMI OK. Eligibility **ELIGIBLE** ("Windows host with WinRM available") |
| 5.2 | As **operator** (sign out, `operator` / `operator-pass-123`): open the laptop's asset page and click **DEPLOY AGENT** | The form preselects **OTProbe Agent (windows-amd64) 0.4.0**. Click **SUBMIT FOR APPROVAL** |
| 5.3 | As **approver** (`approver` / `approver-pass-123`): **Approvals** → approve it | Status **APPROVED**. The operator could not approve their own request |
| 5.4 | As **operator**: open the deployment → **RUN PRECHECK** | 9 checks: REACHABLE, HOSTNAME_VERIFIED (DESKTOP-HSAHH95), WINRM_AVAILABLE, AUTHENTICATION, PACKAGE_COMPATIBLE (Windows 10 Home), DISK_SPACE, EXISTING_AGENT, **SERVER_CONNECTIVITY** ("Host can reach the OTProbe server 192.168.0.160:8000"), REBOOT_REQUIRED (PASS or WARN). Status **PRECHECK_PASSED** |
| 5.5 | **DEPLOY AGENT** | Steps run in order: CONNECT, WINRM_SESSION, RETRIEVE_CREDENTIAL (one-time enrollment token), **TRANSFER_PACKAGE** (about 7 MB over WinRM; can take a minute), VERIFY_HASH, **INSTALL**, SERVICE_CREATED, START_SERVICE, **AWAIT_ENROLLMENT**. It ends **COMPLETED** |
| 5.6 | On the laptop: `sc query OTProbeAgent` | `STATE : 4 RUNNING` |
| 5.7 | **Agents** → the new agent | **ONLINE**, version **0.4.0**, platform **windows/amd64 modern**, profile **windows-workstation**. Heartbeats arrive every 10 s |
| 5.8 | **Audit Logs** | `ENROLLMENT_TOKEN_ISSUED`, `PACKAGE_TRANSFERRED`, `AGENT_CREDENTIAL_ISSUED`, `AGENT_ENROLLED`, `DEPLOYMENT_COMPLETED` |

## 6. Deep assessment with real evidence

| # | Do | Expect |
|---|---|---|
| 6.1 | Laptop's asset page → **RUN DEEP ASSESSMENT** | Status EVALUATED within about a minute |
| 6.2 | Open the assessment | Rules evaluated from **agent** evidence: firewall, antivirus, OS (WIN-OS-001 **FAIL**: Windows 10 Home is out of support), password policy, local admins, logon auditing, USB storage, software, agent health. **WIN-PATCH-001** is **UNKNOWN** (no Windows Update catalog, by design). The score ignores UNKNOWN |
| 6.3 | **Compare** (agentless vs deep) | The agent sees more than the agentless probe did, for example per-user software, the password policy and the local admins |

## 7. Heartbeat loss and recovery

| # | Do | Expect |
|---|---|---|
| 7.1 | On the laptop (admin Command Prompt): `net stop OTProbeAgent` | After about 30 s the agent is **STALE**; after about 60 s, **OFFLINE** |
| 7.2 | In OTProbe: **Agents → the agent → RESTART AGENT** | OTProbe starts the service over WinRM, and the agent goes back to **ONLINE** |

## 8. Remove the agent

| # | Do | Expect |
|---|---|---|
| 8.1 | As **operator**: **Agents → the agent → REMOVE AGENT** (purpose "test done") | A removal request awaiting approval |
| 8.2 | As **approver**: approve it. As **operator**: **START** | Steps STOP_ASSESSMENTS, CONNECT, STOP_AGENT, UNINSTALL, REVOKE_IDENTITY, REMOVE_TEMP_FILES, VALIDATE_DEVICE, ROLLBACK_COMPLETED. Ends **COMPLETED** |
| 8.3 | On the laptop: `sc query OTProbeAgent` and `dir "C:\Program Files\OTProbe"` | "The specified service does not exist", and "File Not Found" |
| 8.4 | **Agents** | The agent is **REMOVED** and its credential is revoked. Its history, findings and audit log are kept |

## 9. Clean up

On the laptop (**Command Prompt as Administrator**), the same as after Phase 3:

```
net user otprobe /delete
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
netsh advfirewall firewall delete rule name=W5986
powershell Disable-PSRemoting -Force
sc config winrm start= disabled
net stop winrm
```

In OTProbe, delete both WinRM vault profiles.

---

**If something goes wrong**, send a screenshot of the step, or run one of these on the laptop:

- `type C:\ProgramData\OTProbe\agent.json` (admin only): shows what the agent was given. After enrollment the token is
  gone and an agent ID and credential are present.
- `"C:\Program Files\OTProbe\Agent\otprobe-agent.exe" collect`: what the agent collects, without contacting the
  server.
- **Windows Security** can quarantine an unknown, unsigned program. If **INSTALL** or **START_SERVICE** fails, look in
  Windows Security → Protection history.
