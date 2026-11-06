"""A stand-in Linux host for the SSH deployment tests, on any machine: a real asyncssh server on 127.0.0.1 that runs
every command it receives with a real /bin/sh, plus SFTP. The adapter's paths are pointed at a sandbox folder
(``net.ssh.ROOT``), so /opt/otprobe, /etc/otprobe and /var/tmp live under it.

Stand-ins, on the server's PATH only:
- ``sudo``: checks the password ``sudo -S`` reads from stdin (or allows ``-n`` when NOPASSWD is on) and then runs the
  command as the same user, marked as root, so ``id -u`` answers 0;
- the agent "binary" in the signed release is a shell script (``agent_script``) whose install/start/stop/uninstall
  manage a SysV-style init script and a pid file inside the sandbox, the way ``otprobe-agent`` does on a host
  without systemd. Its ``run`` and ``version`` can delegate to the real Go agent.
Everything else the commands use (mktemp, sha256sum, cp, df, curl) is the real tool."""

from __future__ import annotations

import asyncio
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

SUDO = r'''#!/bin/sh
printf '%s\n' "sudo $*" >> "$LAB_ROOT/sudo.log"
if [ "$1" = "-n" ]; then
  shift
  [ -n "$LAB_NOPASSWD" ] || { echo "sudo: a password is required" >&2; exit 1; }
elif [ "$1" = "-S" ]; then
  shift
  [ "$1" = "-p" ] && shift 2
  IFS= read -r pw
  if [ "$pw" != "$LAB_SUDO_PASSWORD" ]; then
    echo "Sorry, try again." >&2; echo "sudo: 1 incorrect password attempt" >&2; exit 1
  fi
else
  echo "sudo: refusing an interactive prompt" >&2; exit 1
fi
LAB_AS_ROOT=1 exec "$@"
'''
ID = '''#!/bin/sh
if [ "$1" = "-u" ] && [ -n "$LAB_AS_ROOT" ]; then echo 0; else exec /usr/bin/id "$@"; fi
'''


def agent_script(root: Path, real: Path | None = None, version: str = "otprobe-agent 9.9.9 (linux/amd64)") -> str:
    """The stand-in agent binary. With ``real``, ``start`` runs the real Go agent in the background."""
    run = f'nohup "{real}" run --config "$CFG" >"$ROOT/agent.log" 2>&1 </dev/null &' if real else \
        '(while :; do sleep 1; done) >/dev/null 2>&1 </dev/null &'
    ver = f'exec "{real}" version' if real else f'echo "{version}"'
    return f'''#!/bin/sh
ROOT="{root}"; CFG="$ROOT/etc/otprobe/agent.json"; INITD="$ROOT/etc/init.d/otprobe-agent"
PID="$ROOT/var/run/otprobe-agent.pid"
printf '%s\\n' "$*" >> "$ROOT/agent-calls.log"
case "$1" in
  install)
    mkdir -p "$ROOT/etc/init.d" "$ROOT/var/run"
    printf '#!/bin/sh\\n[ -f "%s" ] && kill -0 "$(cat "%s")" 2>/dev/null\\n' "$PID" "$PID" > "$INITD"
    chmod 0755 "$INITD" ;;
  start) {run} echo $! > "$PID" ;;
  stop) [ -f "$PID" ] && kill "$(cat "$PID")" 2>/dev/null; rm -f "$PID"; true ;;
  uninstall) "$0" stop; rm -f "$INITD" ;;
  version) {ver} ;;
  *) echo "unexpected: $*" >&2; exit 1 ;;
esac
'''


@dataclass
class LinuxLab:
    root: Path
    port: int = 0
    user: str = "otprobe"
    password: str = "lab-ssh-pass-1"
    sudo_password: str = "lab-ssh-pass-1"
    nopasswd: bool = False
    key: asyncssh.SSHKey = field(default_factory=lambda: asyncssh.generate_private_key("ssh-ed25519"))
    received: list[str] = field(default_factory=list)
    server: asyncssh.SSHAcceptor | None = None

    @property
    def host_key(self) -> str:
        return self.key.export_public_key().decode().strip()

    def env(self, username: str) -> dict[str, str]:
        shims = self.root / ".shims"
        env = {"PATH": f"{shims}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin",
               "HOME": str(self.root), "LAB_ROOT": str(self.root), "LAB_SUDO_PASSWORD": self.sudo_password}
        if self.nopasswd:
            env["LAB_NOPASSWD"] = "1"
        if username == "root":
            env["LAB_AS_ROOT"] = "1"
        return env

    async def __aenter__(self) -> "LinuxLab":
        shims = self.root / ".shims"
        shims.mkdir(parents=True)
        for name, text in (("sudo", SUDO), ("id", ID)):
            (shims / name).write_text(text)
            (shims / name).chmod(0o755)
        for d in ("opt", "etc", "var/tmp", "var/run"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        lab = self

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, username, password):
                return username in (lab.user, "root") and password == lab.password

        async def handle(process: asyncssh.SSHServerProcess) -> None:
            lab.received.append(process.command)
            stdin = await process.stdin.read()
            proc = await asyncio.create_subprocess_exec(
                "/bin/sh", "-c", process.command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=lab.env(process.get_extra_info("username")), cwd=lab.root)
            out, err = await proc.communicate(stdin.encode())
            process.stdout.write(out.decode(errors="replace"))
            process.stderr.write(err.decode(errors="replace"))
            process.exit(proc.returncode)

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.server = await asyncssh.create_server(Server, "127.0.0.1", self.port, server_host_keys=[self.key],
                                                   process_factory=handle, sftp_factory=True, encoding="utf-8")
        return self

    async def __aexit__(self, *exc) -> None:
        pid = self.root / "var" / "run" / "otprobe-agent.pid"
        if pid.exists():
            try:
                os.kill(int(pid.read_text().strip()), 15)
            except (ValueError, ProcessLookupError):
                pass
        self.server.close()
        await self.server.wait_closed()

    def calls(self) -> list[str]:
        log = self.root / "agent-calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def sudo_calls(self) -> list[str]:
        log = self.root / "sudo.log"
        return log.read_text().splitlines() if log.exists() else []
