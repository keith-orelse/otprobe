"""Real SSH against an in-process asyncssh server that behaves like a Debian host and records every command it is
sent. Proves: read-only allow-list, host-key pinning (TOFU, then mismatch refused before authentication), wrong
password, parsing, and the probe engine end to end."""

from __future__ import annotations

import socket

import asyncssh
import pytest

from app.adapters.base import Credential
from app.adapters.real.net import ssh as ssh_net
from app.adapters.real.net.gate import NetworkGate
from app.adapters.real.ssh import parse_listening, parse_os_release, parse_packages, parse_services
from tests.live.test_live_loopback import add_scope, safe_mode

pytestmark = pytest.mark.live
USER, PASSWORD = "otprobe-ro", "ssh-lab-pass-1"

DEBIAN = {
    "hostname": "hmi-line1\n",
    "os_release": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
                  'ID=debian\n',
    "uname": "Linux 6.1.0-26-amd64 x86_64\n",
    "uptime": "86400.55 172000.10\n",
    "packages": "openssh-server\t1:9.2p1-2+deb12u3\nbash\t5.2.15-2+b7\nanydesk\t6.3.2\n",
    "services": "cron.service loaded active running Regular background program processing daemon\n"
                "ssh.service loaded active running OpenBSD Secure Shell server\n",
    "listening": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 4096 [::]:502 [::]:*\n",
    "firewall": "firewalld inactive\nufw active\nnftables inactive\niptables inactive\n",
}


def test_parsers_on_recorded_outputs():
    assert parse_os_release(DEBIAN["os_release"])["PRETTY_NAME"] == "Debian GNU/Linux 12 (bookworm)"
    assert parse_packages("musl-1.2.5-r0\nbusybox-1.36.1-r29\n") == [
        {"name": "musl", "version": "1.2.5-r0"}, {"name": "busybox", "version": "1.36.1-r29"}]      # Alpine
    assert parse_packages("bash\t5.1.8-9.el9\n")[0] == {"name": "bash", "version": "5.1.8-9.el9"}  # RHEL
    assert parse_services(" [ + ]  cron\n [ - ]  nginx\n") == ["cron"]                              # SysV
    assert parse_listening("tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n"
                           "tcp6 0 0 :::8080 :::* LISTEN\n") == [22, 8080]                           # netstat


class LabServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == USER and password == PASSWORD


MACOS = {
    "hostname": "Keiths-MacBook-Air.local\n",
    "os_release": "ProductName:\t\tmacOS\nProductVersion:\t\t26.5\nBuildVersion:\t\t25F71\n",
    "uname": "Darwin 25.5.0 arm64\n",
    "uptime": "{ sec = %d, usec = 160251 } Fri Oct 23 21:14:35 2026\n",
    "packages": "Safari\t26.5\nAnyDesk\t9.0.4\nUtilities\t\n",
    "services": "PID\tStatus\tLabel\n-\t0\tcom.apple.SafariHistoryServiceAgent\n412\t0\tcom.apple.Finder\n",
    "listening": "tcp4       0      0  *.22                   *.*                    LISTEN     \n"
                 "tcp6       0      0  *.5900                 *.*                    LISTEN     \n",
    "firewall": "Firewall is disabled. (State = 0)\n",
}


async def start_lab_server(outputs: dict[str, str]):
    received: list[str] = []
    by_command = {ssh_net.COMMANDS[name]: out for name, out in outputs.items()}

    async def handle(process: asyncssh.SSHServerProcess):
        received.append(process.command)
        out = by_command.get(process.command)
        if out is None:
            process.stderr.write("not allowed in this lab\n")
            process.exit(127)
        else:
            process.stdout.write(out)
            process.exit(0)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(LabServer, "127.0.0.1", port, server_host_keys=[key],
                                          process_factory=handle)
    return server, {"port": port, "received": received, "key": key}


@pytest.fixture
async def ssh_server():
    server, info = await start_lab_server(DEBIAN)
    yield info
    server.close()
    await server.wait_closed()


def gate() -> NetworkGate:
    g = NetworkGate()
    g.load([{"id": "lo", "cidr": "127.0.0.1/32", "kind": "INCLUDE", "profile": "IT"}], armed=True, safe_mode=False)
    return g


async def test_only_allow_listed_commands_run_and_host_key_is_pinned(ssh_server):
    cred = Credential("lab", USER, PASSWORD)
    first = await ssh_net.run(gate(), "127.0.0.1", ssh_server["port"], cred, list(DEBIAN), 5.0)
    assert first.status == "OK" and first.outputs["hostname"] == (0, "hmi-line1\n")
    assert set(ssh_server["received"]) == {ssh_net.COMMANDS[n] for n in DEBIAN}
    with pytest.raises(ValueError):
        await ssh_net.run(gate(), "127.0.0.1", ssh_server["port"], cred, ["rm -rf /"], 5.0)

    pinned = await ssh_net.run(gate(), "127.0.0.1", ssh_server["port"], cred, ["hostname"], 5.0, first.host_key)
    assert pinned.status == "OK"
    impostor = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    seen = len(ssh_server["received"])
    changed = await ssh_net.run(gate(), "127.0.0.1", ssh_server["port"], cred, ["hostname"], 5.0, impostor)
    assert changed.status == "HOST_KEY_CHANGED" and len(ssh_server["received"]) == seen   # nothing ran

    wrong = await ssh_net.run(gate(), "127.0.0.1", ssh_server["port"], Credential("lab", USER, "nope-nope"),
                              ["hostname"], 5.0)
    assert wrong.status == "AUTH_FAILED" and "nope" not in (wrong.error or "")


async def test_probe_collects_linux_inventory_over_ssh(live, ssh_server):
    await add_scope(live)
    await safe_mode(live, False)
    await live.login("admin")
    r = await live.client.put("/api/v1/vault/profiles/OT-LINUX-SSH-RO", json={
        "protocol": "SSH", "username": USER, "secret": PASSWORD, "params": {"port": ssh_server["port"]}})
    assert r.status_code == 200, r.text
    await live.login("operator")
    await live.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
    await live.idle()
    asset = await live.asset_by_ip("127.0.0.1")
    r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
    await live.idle()
    probe = await live.get(f"/probes/{r.json()['id']}")
    step = next(s for s in probe["steps"] if s["name"] == "SSH")
    assert step["status"] == "OK", step
    assert "Debian GNU/Linux 12" in step["detail"] and "3 packages" in step["detail"]

    detail = await live.get(f"/assets/{asset['id']}")
    fields = {f["path"]: f["value"] for g in detail["groups"].values() for f in g}
    assert fields["identity.hostname"] == "hmi-line1" and fields["os.family"] == "linux"
    assert fields["os.kernel"] == "6.1.0-26-amd64" and fields["network.listening"] == [22, 502]
    assert {"name": "anydesk", "version": "6.3.2"} in fields["software.installed"]
    assert fields["services.running"] == ["cron", "ssh"] and fields["firewall.state"] == "enabled"
    assert fields["services.ssh.banner"].startswith("SSH-2.0-")
    pinned = await live.get("/audit-events", params={"action": "SSH_HOST_KEY_PINNED"})
    assert len(pinned["items"]) == 1


async def test_macos_inventory_over_ssh():
    import time

    from app.adapters.base import Query, ResultStatus, Target
    from app.adapters.real.ssh import RealSshAdapter

    outputs = {**MACOS, "uptime": MACOS["uptime"] % (int(time.time()) - 86400)}
    server, info = await start_lab_server(outputs)
    try:
        res = await RealSshAdapter(gate()).probe(
            Target("127.0.0.1", port=info["port"], credential=Credential("mac", USER, PASSWORD)),
            Query(["identity", "packages", "services", "network", "firewall"]))
    finally:
        server.close()
        await server.wait_closed()
    assert res.status == ResultStatus.OK, res.error_detail
    d = res.data
    assert d["os.family"] == "macos" and d["os.name"] == "macOS 26.5" and d["os.build"] == "25F71"
    assert d["os.kernel"] == "25.5.0" and 86390 <= d["hardware.uptime_sec"] <= 86500
    assert {"name": "AnyDesk", "version": "9.0.4"} in d["software.installed"]
    assert d["services.running"] == ["com.apple.Finder"]               # PID present = running
    assert d["network.listening"] == [22, 5900] and d["firewall.state"] == "disabled"
