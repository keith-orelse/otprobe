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
              params: dict | None = None) -> WinRmReply:
    script = render(name, params)
    async with gate.permit(ip, "WINRM_PS"):
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


def parse_json(text: str):
    text = (text or "").strip()
    return json.loads(text) if text else None
