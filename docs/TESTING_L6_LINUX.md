# Testing Linux agent deployment by hand (phase L6)

Deploy the **Go agent** to a Linux machine over SSH, see it enroll, run an assessment, and remove it.

Allow about 30 minutes. You need:

- **This Mac** running OTProbe with HTTPS, exactly as in [TESTING_L4.md](TESTING_L4.md) step 3.
- **A Linux machine on the same network.** Any of these works:
  - a Raspberry Pi (Raspberry Pi OS);
  - an old PC or laptop with Ubuntu or Debian;
  - a Linux virtual machine on the Mac, with its network in **bridged** mode so it gets an address on your Wi-Fi.

The agent builds you already made (version 0.4.0) include every Linux build (PC, Raspberry Pi 2+ and Pi Zero/1), so
there is nothing to rebuild.

---

## 1. Prepare the Linux machine

Run these on the Linux machine (keyboard and screen, or SSH from the Mac).

```bash
sudo apt install -y openssh-server curl      # usually already there
sudo adduser otprobe                          # choose a password; press Enter for the other questions
sudo usermod -aG sudo otprobe                 # on Fedora/RHEL use: wheel instead of sudo
hostname; hostname -I; uname -m
```

Write down:

- the **hostname**;
- the **first IP address**;
- the **CPU type** from `uname -m`: `x86_64` (PC), `aarch64` (Pi 3/4/5 with 64-bit OS), `armv7l` (Pi 2/3, 32-bit)
  or `armv6l` (Pi Zero/1).

OTProbe uses the `otprobe` account for two things:

- reading (the probe);
- installing, which needs root. For installs, OTProbe runs `sudo` with the **same password**, typed in for you; the
  password never appears on a command line.

## 2. OTProbe settings (as admin)

| # | Where | What |
|---|---|---|
| 2.1 | **Settings → Scan scope** | Add the Linux machine's IP as `/32`, profile **IT** |
| 2.2 | **Settings → Safety** | Safe mode **off** (SSH probing is skipped in safe mode) |
| 2.3 | **Settings → Credential vault** | Protocol **SSH**: name `OT-LINUX-SSH-RO`, username `otprobe`, its password |
| 2.4 | **Settings → Credential vault** | Protocol **SSH** again: overwrite the name with `OT-LINUX-SSH-INSTALLER`, same username and password |
| 2.5 | **Settings → Agent builds** | The `linux-*` builds of 0.4.0 are listed |

## 3. Probe

| # | Do | Expect |
|---|---|---|
| 3.1 | **Discovery**: the Linux IP, start | The machine appears as an asset |
| 3.2 | Open it → **RUN AGENTLESS PROBE** | The **SSH** step is OK: Linux name, kernel, number of packages |
| 3.3 | Same page | Eligibility **ELIGIBLE** ("Linux host with SSH available"). Fields include `ssh.host_key` and `hardware.arch` |
| 3.4 | **Audit Logs** | `SSH_HOST_KEY_PINNED`. From now on OTProbe only logs in to this exact machine |

## 4. Deploy (operator requests, approver approves)

| # | Do | Expect |
|---|---|---|
| 4.1 | As **operator**: asset page → **DEPLOY AGENT** | The form preselects the build for the CPU (`linux-amd64` on a PC, `linux-arm64` on a 64-bit Pi, …) and shows credential profile **OT-LINUX-SSH-INSTALLER**. **SUBMIT FOR APPROVAL** |
| 4.2 | As **approver**: **Approvals** → approve | APPROVED |
| 4.3 | As **operator**: open the deployment → **RUN PRECHECK** | 9 checks. **SSH_AVAILABLE**, **AUTHENTICATION** ("root access via sudo"), **PACKAGE_COMPATIBLE** (with "CPU …"), **SERVER_CONNECTIVITY**. Status **PRECHECK_PASSED** |
| 4.4 | **DEPLOY AGENT** | CONNECT, **SSH_SESSION**, RETRIEVE_CREDENTIAL, TRANSFER_PACKAGE, VERIFY_HASH, INSTALL, SERVICE_CREATED, START_SERVICE, AWAIT_ENROLLMENT → **COMPLETED** |
| 4.5 | On Linux: `systemctl status otprobe-agent` | **active (running)** |
| 4.6 | On Linux: `sudo cat /etc/otprobe/agent.json` | An `agentId` and a `credential`; no `enrollmentToken` (removed after enrollment) |
| 4.7 | **Agents** | **ONLINE**, platform **linux/…**, profile **linux-host** |

## 5. Assessment

| # | Do | Expect |
|---|---|---|
| 5.1 | Asset page → **RUN DEEP ASSESSMENT** | EVALUATED within about a minute |
| 5.2 | Open it | Policy **linux-host-baseline**: firewall, updates, OS support, SSH settings, accounts, password policy, auditd, USB, agent health |

## 6. Restart and removal

| # | Do | Expect |
|---|---|---|
| 6.1 | On Linux: `sudo systemctl stop otprobe-agent` | After about 60 s the agent is **OFFLINE** |
| 6.2 | **Agents → RESTART AGENT** | OTProbe starts it again over SSH; **ONLINE** |
| 6.3 | **REMOVE AGENT** (operator), approve (approver), **START** (operator) | All removal steps OK → **COMPLETED** |
| 6.4 | On Linux: `systemctl status otprobe-agent; ls /opt/otprobe /etc/otprobe` | "could not be found", "No such file or directory" |

## 7. Clean up

On Linux: `sudo deluser --remove-home otprobe` (Fedora/RHEL: `sudo userdel -r otprobe`). In OTProbe, delete the
two SSH vault profiles.

---

**If something goes wrong**, send a screenshot of the step. Common causes:

| Symptom | Cause |
|---|---|
| AUTHENTICATION: "cannot act as root" | `otprobe` is not in the `sudo` (or `wheel`) group, or sudo uses a different password |
| AUTHENTICATION: "No pinned SSH host key" | Run the agentless probe first (step 3) |
| SSH_SESSION / CONNECT: "Host key does not match" | The machine was reinstalled, or it is a different machine at that IP. Check before trusting it again |
| SERVER_CONNECTIVITY fails | The Linux machine cannot reach the Mac on port 8000: the Mac's firewall, or the Mac's IP changed (then re-run `make_lab_tls.py` with the new IP) |
| PACKAGE_COMPATIBLE: "choose the … build" | Pick the build the message names in the deploy form |
| TRANSFER_PACKAGE fails | The SSH server has SFTP turned off (rare, some embedded systems) |
