"""SSH. Probes are read-only: the adapter asks for commands by NAME, and only the fixed strings in ``COMMANDS`` can
run, with no sudo, no writes and no interactive shell. Agent deployment (phase L6) has its own separate, closed set
in ``deploy_command``; it is only used by the deployment, removal and restart engines, never by probes.

Host keys are pinned: the caller passes the key it saw last time (``expected_host_key``, an OpenSSH public key line).
A different key aborts the connection BEFORE authentication, so a password is never sent to an impostor. With no
expected key the first key is accepted and returned so it can be stored (trust on first use, audited by the engine)."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import asyncssh

from app.adapters.base import Credential
from app.adapters.real.net.agent_params import AGENT_PARAMS
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
    status: str     # OK | AUTH_FAILED | HOST_KEY_CHANGED | NO_HOST_KEY | REFUSED | TIMEOUT | ERROR
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


# ---- Agent deployment (phase L6) ------------------------------------------------------------------------------------
# The only commands that change a Linux host. Every value is validated (``AGENT_PARAMS`` and the patterns below) and
# shell-quoted before it is placed in a command. Commands that need root run through sudo unless the login is root:
# ``sudo -S`` with the account password on stdin for password logins, ``sudo -n`` (NOPASSWD) for key logins.

ROOT = ""   # always "" on a real host; the tests point it at a sandbox folder so the commands can run on any machine
SERVICE = "otprobe-agent"
UPLOAD_GLOB = "/var/tmp/otprobe.*"      # what the removal engine asks to clean up: every upload folder we made
NEEDS_ROOT = {"q_root", "install", "start_service", "stop_service", "uninstall", "remove_upload", "remove_uploads"}
GOARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm",
          "armv6l": "arm", "armhf": "arm", "i686": "386", "i386": "386"}


def paths() -> dict[str, str]:
    return {"agent": f"{ROOT}/opt/otprobe/otprobe-agent", "agent_dir": f"{ROOT}/opt/otprobe",
            "config": f"{ROOT}/etc/otprobe/agent.json", "config_dir": f"{ROOT}/etc/otprobe",
            "uploads": f"{ROOT}/var/tmp", "unit": f"{ROOT}/etc/systemd/system/{SERVICE}.service",
            "initd": f"{ROOT}/etc/init.d/{SERVICE}", "opt": f"{ROOT}/opt", "root": ROOT or "/"}


def _patterns() -> dict[str, re.Pattern]:
    uploads = re.escape(paths()["uploads"])
    return {**AGENT_PARAMS,
            "path": re.compile(rf"^{uploads}/otprobe\.[A-Za-z0-9]{{10}}(/otprobe-agent-[0-9A-Za-z.-]{{1,80}})?$"),
            "server": re.compile(r"^[A-Za-z0-9.-]{1,253}$"), "port": re.compile(r"^\d{1,5}$")}


def _check(params: dict[str, str]) -> dict[str, str]:
    patterns, out = _patterns(), {}
    for key, value in params.items():
        if not patterns[key].fullmatch(str(value)):
            raise ValueError(f"{key}={value!r}")
        out[key] = str(value)
    return out


def deploy_command(name: str, params: dict[str, str] | None = None) -> str:
    """The shell command for one deploy step. Raises ValueError on an unknown name or an invalid value."""
    p = {k: shlex.quote(v) for k, v in paths().items()}
    v = _check(params or {})
    q = {k: shlex.quote(x) for k, x in v.items()}
    agent, cfg = p["agent"], p["config"]
    if name == "q_hostname":
        return "hostname"
    if name == "q_arch":
        return "uname -m"
    if name == "q_root":
        return "id -u"
    if name == "q_disk_free":
        return f"df -Pk {p['opt']} 2>/dev/null || df -Pk {p['root']}"
    if name == "q_reboot_pending":
        return ("if [ -f /var/run/reboot-required ]; then echo true; elif command -v needs-restarting >/dev/null 2>&1 "
                "&& ! needs-restarting -r >/dev/null 2>&1; then echo true; else echo false; fi")
    if name == "q_agent_installed":
        return f"if [ -e {agent} ]; then echo true; else echo false; fi"
    if name == "q_service":
        return (f"if [ -e {p['unit']} ]; then printf '{SERVICE} %s %s\\n' \"$(systemctl is-active {SERVICE} "
                f"2>/dev/null)\" \"$(systemctl is-enabled {SERVICE} 2>/dev/null)\"; elif [ -e {p['initd']} ]; then "
                f"if {p['initd']} status >/dev/null 2>&1; then echo '{SERVICE} active enabled'; "
                f"else echo '{SERVICE} inactive enabled'; fi; fi")
    if name == "q_server_connectivity":
        server, port = v["server"], v["port"]       # validated: letters, digits, dots, hyphens / digits only
        return (f"if command -v curl >/dev/null 2>&1 && curl -sk -o /dev/null --connect-timeout 5 "
                f"https://{server}:{port}/; then echo ok; "
                f"elif command -v nc >/dev/null 2>&1 && nc -z -w 5 {server} {port}; then echo ok; "
                f"elif command -v bash >/dev/null 2>&1 && timeout 5 bash -c 'exec 3<>/dev/tcp/{server}/{port}' "
                f"2>/dev/null; then echo ok; else echo failed; exit 1; fi")
    if name == "make_upload_dir":
        return f"mkdir -p {p['uploads']} && mktemp -d {shlex.quote(paths()['uploads'] + '/otprobe.XXXXXXXXXX')}"
    if name == "verify_hash":
        return f"sha256sum {q['path']} | cut -d' ' -f1"
    if name == "install":
        config = json.dumps({"serverUrl": v["server_url"], "caSha256": v["ca_sha256"], "enrollmentToken": v["token"],
                             "deploymentId": v["deployment_id"], "profile": v["profile"]})
        new = shlex.quote(paths()["agent_dir"] + "/.otprobe-agent.new")
        # The release is copied into a root-owned folder FIRST and its hash checked there, so nothing can swap the
        # file between the check and the install.
        return (f"set -e; mkdir -p {p['agent_dir']} {p['config_dir']}; chmod 0700 {p['config_dir']}; "
                f"cp {q['path']} {new}; "
                f"if [ \"$(sha256sum {new} | cut -d' ' -f1)\" != {q['sha256']} ]; then rm -f {new} {q['path']}; "
                "echo 'HASH_MISMATCH: staged file does not match the release' >&2; exit 2; fi; "
                f"chmod 0755 {new}; mv -f {new} {agent}; umask 077; "
                f"printf '%s\\n' {shlex.quote(config)} > {cfg}; chmod 0600 {cfg}; "
                f"{agent} install --config {cfg} || {{ echo \"INSTALL_FAILED: exit $?\" >&2; exit 3; }}; "
                f"printf '{{\"path\":\"%s\",\"version\":\"%s\"}}\\n' {agent} \"$({agent} version)\"")
    if name == "start_service":
        return f"{agent} start && echo running"
    if name == "stop_service":
        return f"if [ -x {agent} ]; then {agent} stop || true; fi; echo stopped"
    if name == "uninstall":
        return (f"if [ -x {agent} ]; then {agent} uninstall || true; fi; rm -rf {p['agent_dir']} {p['config_dir']}; "
                f"if [ -e {agent} ] || [ -e {p['unit']} ] || [ -e {p['initd']} ]; then "
                "echo 'UNINSTALL_FAILED: agent files or service still present' >&2; exit 1; fi; echo removed")
    if name == "remove_upload":       # the whole private upload folder, also when given the file inside it
        m = _patterns()["path"].fullmatch(v["path"])
        folder = v["path"][:m.start(1)] if m.group(1) else v["path"]
        return f"rm -rf -- {shlex.quote(folder)}"
    if name == "remove_uploads":
        return f"rm -rf -- {shlex.quote(paths()['uploads'])}/otprobe.??????????"
    raise ValueError(f"not an allowed deploy command: {name}")


def with_privilege(command: str, cred: Credential) -> tuple[str, str]:
    """(command, stdin): root as is; otherwise through sudo, never through an interactive prompt."""
    if cred.username == "root":
        return command, ""
    if (cred.params or {}).get("auth") == "key":
        return f"sudo -n sh -c {shlex.quote(command)}", ""
    return f"sudo -S -p '' sh -c {shlex.quote(command)}", f"{cred.secret}\n"


@dataclass
class CommandReply:
    status: str                  # OK | NO_ROOT | ERROR | TIMEOUT
    exit_status: int | None = None
    stdout: str = ""
    stderr: str = ""

    @property
    def detail(self) -> str:
        return (self.stderr.strip() or self.stdout.strip() or f"exit {self.exit_status}")[:500]


SUDO_DENIED = ("a password is required", "incorrect password", "Sorry, try again", "not in the sudoers",
               "is not allowed to execute", "no tty present", "a terminal is required")


class SshSession:
    """One authenticated connection, kept open for the steps of a precheck, deployment or removal. Each command still
    goes through the network gate (kill switch, scope, rate limits)."""

    def __init__(self, gate: NetworkGate, ip: str, cred: Credential, conn, timeout_sec: float) -> None:
        self.gate, self.ip, self.cred, self.conn, self.timeout_sec = gate, ip, cred, conn, timeout_sec

    async def run(self, name: str, params: dict[str, str] | None = None) -> CommandReply:
        command, stdin = deploy_command(name, params), ""
        if name in NEEDS_ROOT:
            command, stdin = with_privilege(command, self.cred)
        async with self.gate.permit(self.ip, "SSH_COMMAND"):
            try:
                # No input: stdin is closed at once, so nothing on the host can ever wait for it.
                run = self.conn.run(command, input=stdin, check=False) if stdin else \
                    self.conn.run(command, stdin=asyncssh.DEVNULL, check=False)
                res = await asyncio.wait_for(run, self.timeout_sec * 6)
            except (asyncio.TimeoutError, TimeoutError):
                return CommandReply("TIMEOUT", stderr=f"{name} timed out")
            except asyncssh.Error as exc:
                return CommandReply("ERROR", stderr=f"SSH error: {exc}")
        out = res.stdout if isinstance(res.stdout, str) else (res.stdout or b"").decode(errors="replace")
        err = res.stderr if isinstance(res.stderr, str) else (res.stderr or b"").decode(errors="replace")
        if res.exit_status != 0 and name in NEEDS_ROOT and any(m in err for m in SUDO_DENIED):
            return CommandReply("NO_ROOT", res.exit_status, out, f"root access through sudo refused: {err.strip()}")
        return CommandReply("OK" if res.exit_status == 0 else "ERROR", res.exit_status, out[:MAX_OUTPUT], err[:4000])

    async def put(self, local: str) -> CommandReply:
        """Uploads a file into a new private folder (mktemp -d, mode 0700) as the login user; returns its path."""
        made = await self.run("make_upload_dir")
        folder = made.stdout.strip()
        if made.status != "OK" or not _patterns()["path"].fullmatch(folder):
            return CommandReply("ERROR", made.exit_status, folder, made.detail)
        remote = f"{folder}/{PurePosixPath(local).name}"
        _check({"path": remote})
        async with self.gate.permit(self.ip, "SSH_COPY"):
            try:
                async with self.conn.start_sftp_client() as sftp:
                    await sftp.put(local, remote)
            except (OSError, asyncssh.Error) as exc:
                return CommandReply("ERROR", stderr=f"SFTP upload failed: {exc}")
        return CommandReply("OK", 0, remote)

    async def close(self) -> None:
        self.conn.close()
        await self.conn.wait_closed()


async def open_session(gate: NetworkGate, ip: str, port: int, cred: Credential, timeout_sec: float,
                       expected_host_key: str) -> tuple[SshReply, SshSession | None]:
    """Deployment sessions need the host key pinned by an earlier probe: an unknown host is never logged in to."""
    if not expected_host_key:
        return SshReply("NO_HOST_KEY", error="No pinned SSH host key for this host: run an agentless probe with an "
                                             "SSH profile first, so the key is recorded"), None
    async with gate.permit(ip, "SSH_SESSION"):
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(ip, port, **_connect_options(ip, cred, expected_host_key, timeout_sec)),
                timeout_sec + 1)
        except asyncssh.HostKeyNotVerifiable as exc:
            return SshReply("HOST_KEY_CHANGED", error=f"Host key does not match the pinned key: {exc}"), None
        except asyncssh.PermissionDenied:
            return SshReply("AUTH_FAILED",
                            error=f"Authentication failed for {cred.username} (profile {cred.profile})"), None
        except ConnectionRefusedError:
            return SshReply("REFUSED", error=f"Connection refused on {ip}:{port}"), None
        except (asyncio.TimeoutError, TimeoutError):
            return SshReply("TIMEOUT", error=f"SSH connection to {ip}:{port} timed out"), None
        except (OSError, asyncssh.Error) as exc:
            return SshReply("ERROR", error=f"SSH error: {exc}"), None
    key = conn.get_server_host_key().export_public_key().decode().strip()
    return SshReply("OK", host_key=key), SshSession(gate, ip, cred, conn, timeout_sec)
