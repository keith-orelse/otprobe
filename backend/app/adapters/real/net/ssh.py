"""Read-only SSH. The adapter asks for commands by NAME; only the fixed strings in ``COMMANDS`` can ever run. No sudo,
no writes, no interactive shell.

Host keys are pinned: the caller passes the key it saw last time (``expected_host_key``, an OpenSSH public key line).
A different key aborts the connection BEFORE authentication, so a password is never sent to an impostor. With no
expected key the first key is accepted and returned so it can be stored (trust on first use, audited by the engine)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import asyncssh

from app.adapters.base import Credential
from app.adapters.real.net.gate import NetworkGate

MAX_OUTPUT = 512 * 1024   # per command; package lists on big hosts stay well under this

_MAC = '[ "$(uname)" = Darwin ]'
COMMANDS: dict[str, str] = {
    "hostname": "hostname",
    "os_release": "cat /etc/os-release 2>/dev/null || sw_vers",
    "uname": "uname -srm",
    "uptime": "cat /proc/uptime 2>/dev/null || sysctl -n kern.boottime",
    "packages": ("if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}\\t${Version}\\n'; "
                 "elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'; "
                 "elif command -v apk >/dev/null 2>&1; then apk info -v; "
                 "elif [ -d /Applications ]; then for a in /Applications/*.app; do printf '%s\\t%s\\n' "
                 "\"$(basename \"$a\" .app)\" \"$(defaults read \"$a/Contents/Info\" CFBundleShortVersionString "
                 "2>/dev/null)\"; done; fi"),
    "services": (f"if {_MAC}; then launchctl list; else systemctl list-units --type=service --state=running "
                 "--no-legend --plain 2>/dev/null || service --status-all 2>/dev/null; fi"),
    "listening": (f"if {_MAC}; then netstat -anp tcp | grep LISTEN; else ss -Hltn 2>/dev/null || netstat -ltn "
                  "2>/dev/null; fi"),
    "firewall": (f"if {_MAC}; then /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate; else "
                 "for s in firewalld ufw nftables iptables; do printf '%s %s\\n' \"$s\" "
                 "\"$(systemctl is-active $s 2>/dev/null)\"; done; fi"),
}


@dataclass
class SshReply:
    status: str                          # OK | AUTH_FAILED | HOST_KEY_CHANGED | REFUSED | TIMEOUT | ERROR
    outputs: dict[str, tuple[int | None, str]] = field(default_factory=dict)   # name -> (exit status, stdout)
    host_key: str | None = None          # OpenSSH public key line of the server
    error: str | None = None


def _connect_options(ip: str, cred: Credential, expected_host_key: str | None, timeout_sec: float) -> dict:
    params = cred.params or {}
    opts: dict = {"username": cred.username, "connect_timeout": timeout_sec, "agent_path": None,
                  "known_hosts": None, "client_keys": None, "password": None}
    if expected_host_key:
        opts["known_hosts"] = asyncssh.import_known_hosts(f"{ip} {expected_host_key}\n")
    if params.get("auth") == "key":
        opts["client_keys"] = [asyncssh.import_private_key(cred.secret, params.get("passphrase"))]
    else:
        opts["password"] = cred.secret
    return opts


async def run(gate: NetworkGate, ip: str, port: int, cred: Credential, names: list[str], timeout_sec: float,
              expected_host_key: str | None = None) -> SshReply:
    unknown = [n for n in names if n not in COMMANDS]
    if unknown:
        raise ValueError(f"not an allowed SSH command: {unknown}")
    async with gate.permit(ip, "SSH_SESSION"):
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(ip, port, **_connect_options(ip, cred, expected_host_key, timeout_sec)),
                timeout_sec + 1)
        except asyncssh.HostKeyNotVerifiable as exc:
            return SshReply("HOST_KEY_CHANGED", error=f"Host key does not match the pinned key: {exc}")
        except asyncssh.PermissionDenied:
            return SshReply("AUTH_FAILED", error=f"Authentication failed for {cred.username} (profile {cred.profile})")
        except ConnectionRefusedError:
            return SshReply("REFUSED", error=f"Connection refused on {ip}:{port}")
        except (asyncio.TimeoutError, TimeoutError):
            return SshReply("TIMEOUT", error=f"SSH connection to {ip}:{port} timed out")
        except (OSError, asyncssh.Error) as exc:
            return SshReply("ERROR", error=f"SSH error: {exc}")
        reply = SshReply("OK", host_key=conn.get_server_host_key().export_public_key().decode().strip())
        try:
            for name in names:
                try:
                    res = await asyncio.wait_for(conn.run(COMMANDS[name], check=False), timeout_sec * 4)
                    out = res.stdout if isinstance(res.stdout, str) else (res.stdout or b"").decode(errors="replace")
                    reply.outputs[name] = (res.exit_status, out[:MAX_OUTPUT])
                except (asyncio.TimeoutError, asyncssh.Error) as exc:
                    reply.outputs[name] = (None, f"error: {exc}")
        finally:
            conn.close()
            await conn.wait_closed()
        return reply
