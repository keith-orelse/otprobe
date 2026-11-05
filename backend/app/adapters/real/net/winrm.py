"""WinRM / PowerShell remoting through pypsrp. Read-only in phase L3: only the scripts in ``SCRIPTS`` can run, and
callers ask for them by name. Parameters are validated against strict patterns before they are placed in a script.

Stages are checked one by one so a failure is reported precisely (docs/STATE_MACHINES.md, contract C-11):
CONNECTING -> TCP_OK (connect) -> TLS_VALIDATED (HTTPS: certificate chain against the profile's CA, or the system
store) -> AUTH_OK + SESSION_CREATED (a trivial script runs).

TLS: the certificate chain is verified by ``check_tls`` (against the profile's ``params.caPem`` or the system store,
without hostname matching because targets are addressed by IP). pypsrp's own connection then runs with certificate
validation off, moments later. That leaves a short window in which an attacker able to intercept could swap the
server; pinning the certificate fingerprint inside the pypsrp session closes it and is tracked for phase L6.

Scripts need PowerShell 3.0+ (ConvertTo-Json); hosts with only PowerShell 2.0 (stock Windows 7 / 2008 R2) report
"PowerShell 3.0 or later required" and stay agentless-partial until the Go agent (L4) covers them."""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from dataclasses import dataclass, field

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from pypsrp.client import Client
from pypsrp.exceptions import AuthenticationError, WinRMTransportError, WSManFaultError

from app.adapters.base import Credential
from app.adapters.real.net import tcp
from app.adapters.real.net.gate import NetworkGate

_J = " | ConvertTo-Json -Compress -Depth 4"
_DISK = "{ @{drive=$_.DeviceID; size_gb=[math]::Round($_.Size/1GB); free_gb=[math]::Round($_.FreeSpace/1GB)} }"
SCRIPTS: dict[str, str] = {
    "ps_version": "$PSVersionTable.PSVersion.Major",
    "os": (
        "$o = Get-CimInstance Win32_OperatingSystem; $c = Get-CimInstance Win32_ComputerSystem; "
        "$v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
        "[pscustomobject]@{caption=$o.Caption; version=$o.Version; build=$o.BuildNumber; ubr=$v.UBR; "
        "displayVersion=$v.DisplayVersion; releaseId=$v.ReleaseId; hostname=$env:COMPUTERNAME; domain=$c.Domain; "
        "partOfDomain=$c.PartOfDomain; lastBoot=$o.LastBootUpTime.ToUniversalTime().ToString('o')}" + _J),
    "hardware": (
        "$c = Get-CimInstance Win32_ComputerSystem; $p = Get-CimInstance Win32_Processor | Select-Object -First 1; "
        "$d = Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object " + _DISK + "; "
        "[pscustomobject]@{manufacturer=$c.Manufacturer; model=$c.Model; cpu=$p.Name; "
        "ram_gb=[math]::Round($c.TotalPhysicalMemory/1GB); disk=@($d)}" + _J),
    "firewall": "Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled; "
                "inbound=[string]$_.DefaultInboundAction} }" + _J,
    "antivirus": (
        "$m = $null; try { $m = Get-CimInstance -Namespace root/Microsoft/Windows/Defender MSFT_MpComputerStatus "
        "-ErrorAction Stop } catch {}; "
        "$s = @(); try { $s = @(Get-CimInstance -Namespace root/SecurityCenter2 AntiVirusProduct -ErrorAction Stop | "
        "ForEach-Object { @{name=$_.displayName; state=$_.productState} }) } catch {}; "
        "[pscustomobject]@{defender=$(if ($m) { @{service=[bool]$m.AMServiceEnabled; "
        "realtime=[bool]$m.RealTimeProtectionEnabled; signatureAge=$m.AntivirusSignatureAge} } else { $null }); "
        "securityCenter=$s}" + _J),
    "software": (
        "$k = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', "
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; "
        "@(Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and "
        "$_.SystemComponent -ne 1 } | ForEach-Object { @{name=$_.DisplayName; version=$_.DisplayVersion; "
        "publisher=$_.Publisher} })" + _J),
    "services": "@(Get-Service | Where-Object Status -eq 'Running' | ForEach-Object Name)" + _J,
    "hotfixes": "@(Get-HotFix | ForEach-Object { @{id=$_.HotFixID; installedOn=$(if ($_.InstalledOn) "
                "{ $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null })} })" + _J,
    "network": (
        "$a = @{}; Get-NetAdapter | ForEach-Object { $a[$_.ifIndex] = $_.MacAddress }; "
        "$i = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1' | ForEach-Object "
        "{ @{name=$_.InterfaceAlias; ip=$_.IPAddress; prefix=$_.PrefixLength; mac=$a[$_.InterfaceIndex]} }); "
        "$l = @(Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique); "
        "$e = @(Get-NetTCPConnection -State Established | Select-Object -First 200 | ForEach-Object "
        "{ @{remote_ip=$_.RemoteAddress; remote_port=$_.RemotePort} }); "
        "[pscustomobject]@{interfaces=$i; listening=$l; connections=$e}" + _J),
    # precheck queries (read-only)
    "q_hostname": "$env:COMPUTERNAME",
    "q_disk_free": "@(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\" | ForEach-Object " + _DISK + ")" + _J,
    "q_reboot_pending": "(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based "
                        "Servicing\\RebootPending') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
                        "\\WindowsUpdate\\Auto Update\\RebootRequired')",
    "q_agent_installed": "Test-Path 'C:\\Program Files\\OTProbe\\Agent\\otprobe-agent.exe'",
    "q_service": "$s = Get-Service -Name '{name}' -ErrorAction SilentlyContinue; if ($s) { @{name=$s.Name; "
                 "state=[string]$s.Status; startType=[string]$s.StartType}" + _J + " }",
    "q_server_connectivity": "$r = Test-NetConnection -ComputerName '{server}' -Port {port} -WarningAction "
                             "SilentlyContinue; @{TcpTestSucceeded=$r.TcpTestSucceeded; RemoteAddress="
                             "[string]$r.RemoteAddress; RemotePort=$r.RemotePort}" + _J,
}
PARAMS = {"name": re.compile(r"^[A-Za-z0-9_.-]{1,64}$"), "server": re.compile(r"^[A-Za-z0-9.-]{1,253}$"),
          "port": re.compile(r"^\d{1,5}$")}

# ---- Deployment scripts (phase L4) --------------------------------------------------------------------------------
# The only scripts that change a host. Used by the deployment / removal engines through closed RemoteOperations,
# never by probes. Every value is validated against DEPLOY_PARAMS before it is placed in a script.
STAGING = "C:\\ProgramData\\OTProbe\\staging"
INSTALL_DIR = "C:\\Program Files\\OTProbe\\Agent"
DATA_DIR = "C:\\ProgramData\\OTProbe"
DEPLOY_PARAMS = {
    "path": re.compile(r"^C:\\ProgramData\\OTProbe\\staging(\\otprobe-agent-[0-9A-Za-z.-]{1,80}\.exe)?$"),
    "sha256": re.compile(r"^[0-9a-f]{64}$"),
    "token": re.compile(r"^enr_[A-Za-z0-9_-]{20,128}$"),
    "server_url": re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:\d{1,5})?/?$"),
    "ca_sha256": re.compile(r"^([0-9a-f]{64})?$"),
    "deployment_id": re.compile(r"^[0-9a-f-]{36}$"),
    "profile": re.compile(r"^[a-z0-9-]{1,48}$"),
}
DEPLOY_SCRIPTS: dict[str, str] = {
    "make_staging": f"New-Item -ItemType Directory -Force -Path '{STAGING}' | Out-Null; 'ok'",
    "verify_hash": "(Get-FileHash -Algorithm SHA256 -LiteralPath '{path}').Hash.ToLower()",
    "install": (
        "$ErrorActionPreference = 'Stop'; $src = '{path}'; "
        "if ((Get-FileHash -Algorithm SHA256 -LiteralPath $src).Hash.ToLower() -ne '{sha256}') "
        "{ Remove-Item -LiteralPath $src -Force; throw 'HASH_MISMATCH: staged file does not match the release' }; "
        f"$dir = '{INSTALL_DIR}'; $data = '{DATA_DIR}'; "
        "New-Item -ItemType Directory -Force -Path $dir, $data | Out-Null; "
        "$exe = Join-Path $dir 'otprobe-agent.exe'; $cfg = Join-Path $data 'agent.json'; "
        "Copy-Item -LiteralPath $src -Destination $exe -Force; "
        "@{serverUrl='{server_url}'; caSha256='{ca_sha256}'; enrollmentToken='{token}'; "
        "deploymentId='{deployment_id}'; profile='{profile}'} | ConvertTo-Json | "
        "Set-Content -LiteralPath $cfg -Encoding ASCII; "
        "icacls $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; "
        "& $exe install --config $cfg; if ($LASTEXITCODE -ne 0) { throw \"INSTALL_FAILED: exit $LASTEXITCODE\" }; "
        "@{path=$exe; version=(& $exe version)} | ConvertTo-Json -Compress"),
    "start_service": "Start-Service -Name OTProbeAgent; [string](Get-Service -Name OTProbeAgent).Status",
    "stop_service": "Stop-Service -Name OTProbeAgent -Force -ErrorAction SilentlyContinue; 'stopped'",
    # Windows may hold the binary and keep the service "marked for deletion" for a few seconds after it stops:
    # retry for up to 15 s before declaring residue.
    "uninstall": (
        f"$exe = '{INSTALL_DIR}\\otprobe-agent.exe'; "
        "if (Test-Path $exe) { & $exe uninstall | Out-Null }; "
        "for ($i = 0; $i -lt 15; $i++) { "
        "Remove-Item -LiteralPath 'C:\\Program Files\\OTProbe' -Recurse -Force -ErrorAction SilentlyContinue; "
        f"Remove-Item -LiteralPath '{DATA_DIR}' -Recurse -Force -ErrorAction SilentlyContinue; "
        "if (-not (Test-Path $exe) -and -not (Get-Service -Name OTProbeAgent -ErrorAction SilentlyContinue)) "
        "{ break }; Start-Sleep -Seconds 1 }; "
        "if ((Get-Service -Name OTProbeAgent -ErrorAction SilentlyContinue) -or (Test-Path $exe)) "
        "{ throw 'UNINSTALL_FAILED: agent files or service still present' }; 'removed'"),
    "remove_staging": "Remove-Item -LiteralPath '{path}' -Recurse -Force -ErrorAction SilentlyContinue; 'ok'",
}


def render_deploy(name: str, params: dict) -> str:
    if name not in DEPLOY_SCRIPTS:
        raise ValueError(f"not a deployment script: {name}")
    script = DEPLOY_SCRIPTS[name]
    for k in re.findall(r"\{([a-z_0-9]+)\}", script):
        v = str(params.get(k, ""))
        if k not in DEPLOY_PARAMS or not DEPLOY_PARAMS[k].match(v):
            raise ValueError(f"invalid deployment parameter {k}={v[:40]!r}")
        script = script.replace("{" + k + "}", v)
    return script


@dataclass
class WinRmReply:
    status: str          # OK | REFUSED | TIMEOUT | TLS_INVALID | AUTH_FAILED | DISABLED | ERROR
    stage: str = ""      # the stage that failed
    output: str = ""
    errors: list[str] = field(default_factory=list)
    detail: str = ""


def render(name: str, params: dict | None = None) -> str:
    if name not in SCRIPTS:
        raise ValueError(f"not an allowed WinRM script: {name}")
    params = {k: str(v) for k, v in (params or {}).items()}
    for k, v in params.items():
        if k not in PARAMS or not PARAMS[k].match(v):
            raise ValueError(f"invalid parameter {k}={v!r}")
    script = SCRIPTS[name]
    for k, v in params.items():
        script = script.replace("{" + k + "}", v)
    if re.search(r"\{(name|server|port)\}", script):
        raise ValueError(f"missing parameter for {name}")
    return script


def _tls_context(cred: Credential) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cadata=cred.params.get("caPem") or None)
    ctx.check_hostname = False      # targets are addressed by IP; the chain must still verify (see module doc)
    if cred.params.get("skipCertCheck"):
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def check_tls(gate: NetworkGate, ip: str, port: int, cred: Credential, timeout_sec: float) -> tuple[bool, str]:
    async with gate.permit(ip, "TLS_HANDSHAKE"):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=_tls_context(cred)), timeout_sec)
        except ssl.SSLCertVerificationError as exc:
            return False, f"TLS certificate validation failed: {exc.verify_message}"
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            return False, f"TLS handshake failed: {exc}"
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.close()
    subject = _common_name(der)
    note = " (validation skipped by profile)" if cred.params.get("skipCertCheck") else ""
    return True, f"Server certificate chain trusted (CN={subject}){note}"


def _common_name(der: bytes | None) -> str:
    """Certificate CN, read from the raw certificate (also when validation is skipped and Python parses nothing)."""
    if not der:
        return "?"
    names = x509.load_der_x509_certificate(der).subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(names[0].value) if names else "?"


def _client(ip: str, port: int, cred: Credential, timeout_sec: float) -> Client:
    tls = port != 5985 and not cred.params.get("http")
    return Client(ip, port=port, username=cred.username, password=cred.secret, ssl=tls,
                  cert_validation=False,   # the chain is verified by check_tls during open_session (module doc)
                  auth=cred.params.get("auth", "negotiate"), connection_timeout=int(timeout_sec),
                  operation_timeout=max(20, int(timeout_sec) * 4), read_timeout=max(30, int(timeout_sec) * 5),
                  encryption="auto")


def _classify(exc: Exception) -> tuple[str, str, str]:
    if isinstance(exc, AuthenticationError) or (isinstance(exc, WinRMTransportError) and exc.code == 401):
        return "AUTH_FAILED", "AUTH_OK", "Authentication failed"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS_INVALID", "TLS_VALIDATED", f"TLS error: {exc}"
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout)):
        return "TIMEOUT", "SESSION_CREATED", f"WinRM timed out: {exc}"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "REFUSED", "CONNECTING", f"Connection failed: {exc}"
    if isinstance(exc, WSManFaultError):
        return "ERROR", "SESSION_CREATED", f"WS-Management fault: {exc.reason or exc}"
    return "ERROR", "SESSION_CREATED", f"{type(exc).__name__}: {exc}"


async def run(gate: NetworkGate, ip: str, port: int, cred: Credential, name: str, timeout_sec: float,
              params: dict | None = None, deploy: bool = False) -> WinRmReply:
    script = render_deploy(name, params or {}) if deploy else render(name, params)
    async with gate.permit(ip, "WINRM_DEPLOY" if deploy else "WINRM_PS"):
        try:
            client = _client(ip, port, cred, timeout_sec)
            output, streams, had_errors = await asyncio.wait_for(
                asyncio.to_thread(client.execute_ps, script), timeout_sec * 6)
        except asyncio.TimeoutError:
            return WinRmReply("TIMEOUT", "SESSION_CREATED", detail=f"{name} did not finish in time")
        except Exception as exc:  # noqa: BLE001 - mapped to a precise stage and status
            status, stage, detail = _classify(exc)
            return WinRmReply(status, stage, detail=f"{detail} (profile {cred.profile}, {cred.username})"
                              if status == "AUTH_FAILED" else detail)
    errors = [str(e) for e in streams.error] if had_errors else []
    return WinRmReply("OK", output=output or "", errors=errors)


async def open_session(gate: NetworkGate, ip: str, port: int, cred: Credential, timeout_sec: float,
                       emit) -> WinRmReply:
    """Runs the stages and reports each through ``emit(name, status, detail)`` (status as in WinRmReply)."""
    tls = port != 5985 and not cred.params.get("http")
    await emit("CONNECTING", "OK", f"Connecting to {ip}:{port} ({'HTTPS' if tls else 'HTTP + message encryption'})")
    state = await tcp.connect(gate, ip, port, timeout_sec)
    if state.state != "OPEN":
        status = "REFUSED" if state.state == "CLOSED" else "TIMEOUT"
        detail = f"Connection refused on {ip}:{port}" if status == "REFUSED" else \
            f"WinRM connection timed out after {timeout_sec:g} s"
        await emit("CONNECTING", status, detail)
        return WinRmReply(status, "CONNECTING", detail=detail)
    await emit("TCP_OK", "OK", f"TCP connection established to {ip}:{port}")
    if tls:
        ok, detail = await check_tls(gate, ip, port, cred, timeout_sec)
        await emit("TLS_VALIDATED", "OK" if ok else "TLS_INVALID", detail)
        if not ok:
            return WinRmReply("TLS_INVALID", "TLS_VALIDATED", detail=detail)
    reply = await run(gate, ip, port, cred, "ps_version", timeout_sec)
    if reply.status != "OK":
        await emit(reply.stage if reply.stage in ("AUTH_OK", "SESSION_CREATED") else "AUTH_OK", reply.status,
                   reply.detail)
        return reply
    version = reply.output.strip()
    await emit("AUTH_OK", "OK", f"Authenticated as {cred.username}")
    if not version.isdigit() or int(version) < 3:
        detail = f"PowerShell {version or '?'} on target: PowerShell 3.0 or later required for agentless inventory"
        await emit("SESSION_CREATED", "ERROR", detail)
        return WinRmReply("ERROR", "SESSION_CREATED", output=version, detail=detail)
    await emit("SESSION_CREATED", "OK", f"PowerShell {version} remoting session works")
    return WinRmReply("OK", output=version)


async def copy_file(gate: NetworkGate, ip: str, port: int, cred: Credential, local: str, remote: str,
                    timeout_sec: float) -> WinRmReply:
    """Copy one file to the host over the WinRM session (PSRP, base64 chunks). Used for agent binaries only;
    ``remote`` must be inside the staging folder."""
    if not DEPLOY_PARAMS["path"].match(remote):
        raise ValueError(f"refusing to copy outside the staging folder: {remote}")
    async with gate.permit(ip, "WINRM_COPY"):
        try:
            client = _client(ip, port, cred, timeout_sec)
            await asyncio.wait_for(asyncio.to_thread(client.copy, local, remote), 900)
        except asyncio.TimeoutError:
            return WinRmReply("TIMEOUT", "SESSION_CREATED", detail="File copy did not finish within 15 minutes")
        except Exception as exc:  # noqa: BLE001
            status, stage, detail = _classify(exc)
            return WinRmReply(status, stage, detail=detail)
    return WinRmReply("OK", output=remote)


def parse_json(text: str):
    text = (text or "").strip()
    return json.loads(text) if text else None
