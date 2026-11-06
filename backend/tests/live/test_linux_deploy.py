"""Linux agent deployment over SSH (phase L6), command by command, against LinuxLab: a real SSH server on 127.0.0.1
running every command with a real shell in a sandbox (tests/live/linux_lab.py). Proves the install, service and
uninstall commands work, run as root through sudo, refuse an unpinned or changed host key, refuse a tampered file,
and stop at the kill switch."""

from __future__ import annotations

import hashlib
import json
import platform as host_platform

import pytest

from app.adapters.base import Credential, RemoteOperation, ResultStatus, Target
from app.adapters.real.net import ssh as ssh_net
from app.adapters.real.net.gate import NetworkGate
from app.adapters.real.ssh import RealSshAdapter
from tests.live.linux_lab import LinuxLab, agent_script

pytestmark = pytest.mark.live
TOKEN = "enr_" + "a" * 40
DEP_ID = "01a1afa2-3be4-706f-90a1-5ae0e71eb3a1"
SERVER_URL = "https://127.0.0.1:1/"


def gate() -> NetworkGate:
    g = NetworkGate()
    g.load([{"id": "lo", "cidr": "127.0.0.1/32", "kind": "INCLUDE", "profile": "IT"}], armed=True, safe_mode=False)
    return g


@pytest.fixture
async def lab(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_net, "ROOT", str(tmp_path / "host"))
    async with LinuxLab(tmp_path / "host") as lab:
        yield lab


def release(tmp_path, lab: LinuxLab) -> tuple[str, str]:
    """The stand-in agent as a release file; returns (local path, sha256)."""
    f = tmp_path / "otprobe-agent-9.9.9-linux-amd64"
    f.write_text(agent_script(lab.root))
    return str(f), hashlib.sha256(f.read_bytes()).hexdigest()


async def session(lab: LinuxLab, adapter: RealSshAdapter, user: str | None = None, password: str | None = None,
                  host_key: str | None = "pinned"):
    cred = Credential("OT-LINUX-SSH-INSTALLER", user or lab.user, password or lab.password)
    key = lab.host_key if host_key == "pinned" else host_key
    return await adapter.open_session(Target("127.0.0.1", port=lab.port, credential=cred,
                                             options={"host_key": key}))


async def test_install_start_stop_uninstall_through_sudo(tmp_path, lab):
    adapter = RealSshAdapter(gate())
    res, s = await session(lab, adapter)
    assert s is not None, res.error_detail
    try:
        root = await adapter.execute(s, RemoteOperation.QUERY_ROOT_ACCESS, {})
        assert root.ok and root.raw["via"] == "sudo", root.error_detail
        arch = await adapter.execute(s, RemoteOperation.QUERY_ARCH, {})
        assert arch.data["hardware.arch"] == host_platform.machine()
        disk = await adapter.execute(s, RemoteOperation.QUERY_DISK_FREE, {})
        assert disk.data["hardware.disk"][0]["free_gb"] > 0
        assert (await adapter.execute(s, RemoteOperation.QUERY_AGENT_INSTALLED, {})).raw == {"installed": False}
        assert (await adapter.execute(s, RemoteOperation.QUERY_SERVICE, {"name": "otprobe-agent"})).raw == \
            {"service": None}
        assert (await adapter.execute(s, RemoteOperation.QUERY_REBOOT_PENDING, {})).ok

        local, sha = release(tmp_path, lab)
        copied = await adapter.copy(s, local)
        assert copied.status == "OK", copied.detail
        staged = copied.stdout
        assert staged.startswith(str(lab.root / "var" / "tmp" / "otprobe.")) and staged.endswith("-linux-amd64")
        assert (await adapter.execute(s, RemoteOperation.VERIFY_FILE_HASH, {"path": staged, "sha256": sha})).ok

        r = await adapter.execute(s, RemoteOperation.INSTALL_AGENT, {
            "path": staged, "sha256": sha, "enrollment_token": TOKEN, "server_url": SERVER_URL, "ca_sha256": "ab" * 32,
            "deployment_id": DEP_ID, "profile": "linux-host"})
        assert r.ok, r.error_detail
        assert r.raw == {"path": str(lab.root / "opt/otprobe/otprobe-agent"),
                         "version": "otprobe-agent 9.9.9 (linux/amd64)"}
        config = lab.root / "etc/otprobe/agent.json"
        assert json.loads(config.read_text()) == {"serverUrl": SERVER_URL, "caSha256": "ab" * 32,
                                                  "enrollmentToken": TOKEN, "deploymentId": DEP_ID,
                                                  "profile": "linux-host"}
        assert oct(config.stat().st_mode)[-3:] == "600" and oct(config.parent.stat().st_mode)[-3:] == "700"
        assert lab.calls()[0] == f"install --config {config}"
        assert (await adapter.execute(s, RemoteOperation.QUERY_AGENT_INSTALLED, {})).raw == {"installed": True}

        svc = await adapter.execute(s, RemoteOperation.QUERY_SERVICE, {"name": "otprobe-agent"})
        assert svc.raw["service"] == {"name": "otprobe-agent", "state": "stopped", "start_type": "enabled"}
        assert (await adapter.execute(s, RemoteOperation.START_SERVICE, {"name": "otprobe-agent"})).ok
        svc = await adapter.execute(s, RemoteOperation.QUERY_SERVICE, {"name": "otprobe-agent"})
        assert svc.raw["service"]["state"] == "running"
        assert (await adapter.execute(s, RemoteOperation.STOP_SERVICE, {"name": "otprobe-agent"})).ok
        assert (await adapter.execute(s, RemoteOperation.QUERY_SERVICE, {"name": "otprobe-agent"})
                ).raw["service"]["state"] == "stopped"

        assert (await adapter.execute(s, RemoteOperation.UNINSTALL_AGENT, {})).ok
        await adapter.execute(s, RemoteOperation.REMOVE_FILES, {"paths": [ssh_net.UPLOAD_GLOB]})
        assert not (lab.root / "opt/otprobe").exists() and not (lab.root / "etc/otprobe").exists()
        assert not (lab.root / "etc/init.d/otprobe-agent").exists()
        assert not list((lab.root / "var/tmp").glob("otprobe.*"))
        assert (await adapter.execute(s, RemoteOperation.QUERY_SERVICE, {"name": "otprobe-agent"})).raw == \
            {"service": None}

        # Everything that needs root went through sudo -S, with the password on stdin and never in the command.
        assert lab.sudo_calls() and all(c.startswith("sudo -S -p  sh -c") for c in lab.sudo_calls())
        assert not any(lab.password in c for c in lab.received)
        bad = await adapter.execute(s, RemoteOperation.STOP_SERVICE, {"name": "sshd"})
        assert bad.error_code == "INVALID_PARAMETER"
    finally:
        await adapter.close_session(s)


async def test_root_login_runs_without_sudo(tmp_path, lab):
    adapter = RealSshAdapter(gate())
    _, s = await session(lab, adapter, user="root")
    try:
        root = await adapter.execute(s, RemoteOperation.QUERY_ROOT_ACCESS, {})
        assert root.ok and root.raw["via"] == "login"
        assert lab.sudo_calls() == []
    finally:
        await adapter.close_session(s)


async def test_unpinned_or_changed_host_key_is_never_logged_in_to(lab):
    adapter = RealSshAdapter(gate())
    res, s = await session(lab, adapter, host_key=None)
    assert s is None and res.error_code == "NO_HOST_KEY" and "agentless probe" in res.error_detail
    impostor = __import__("asyncssh").generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    res, s = await session(lab, adapter, host_key=impostor)
    assert s is None and res.status == ResultStatus.TLS_INVALID and res.error_code == "HOST_KEY_CHANGED"
    assert lab.received == []                                   # no command ever ran


async def test_sudo_refused_is_reported_as_no_root(lab):
    lab.sudo_password = "a-different-password"                   # login works, sudo does not accept the password
    adapter = RealSshAdapter(gate())
    _, s = await session(lab, adapter)
    try:
        r = await adapter.execute(s, RemoteOperation.QUERY_ROOT_ACCESS, {})
        assert not r.ok and r.error_code == "NO_ROOT" and "sudo" in r.error_detail
        r = await adapter.execute(s, RemoteOperation.UNINSTALL_AGENT, {})
        assert r.error_code == "NO_ROOT"
    finally:
        await adapter.close_session(s)


async def test_key_login_uses_passwordless_sudo_only(lab):
    lab.nopasswd = True
    adapter = RealSshAdapter(gate())
    _, s = await session(lab, adapter)
    try:
        conn = adapter._sessions[s.session_id]
        conn.cred = Credential("OT-LINUX-SSH-INSTALLER", lab.user, "unused", {"auth": "key"})
        assert (await adapter.execute(s, RemoteOperation.QUERY_ROOT_ACCESS, {})).ok
        assert lab.sudo_calls()[-1].startswith("sudo -n sh -c")
    finally:
        await adapter.close_session(s)


async def test_tampered_file_is_refused_and_nothing_is_installed(tmp_path, lab):
    adapter = RealSshAdapter(gate())
    _, s = await session(lab, adapter)
    try:
        local, sha = release(tmp_path, lab)
        staged = (await adapter.copy(s, local)).stdout
        with open(staged, "a") as f:                             # changed on the host after the upload
            f.write("\n# extra\n")
        assert (await adapter.execute(s, RemoteOperation.VERIFY_FILE_HASH, {"path": staged, "sha256": sha})
                ).error_code == "HASH_MISMATCH"
        r = await adapter.execute(s, RemoteOperation.INSTALL_AGENT, {
            "path": staged, "sha256": sha, "enrollment_token": TOKEN, "server_url": SERVER_URL, "ca_sha256": "",
            "deployment_id": DEP_ID, "profile": "linux-host"})
        assert r.error_code == "HASH_MISMATCH"
        assert not (lab.root / "opt/otprobe/otprobe-agent").exists() and not (lab.root / "etc/otprobe/agent.json"
                                                                              ).exists()
        assert lab.calls() == []
    finally:
        await adapter.close_session(s)


async def test_kill_switch_stops_an_open_session(lab):
    g = gate()
    adapter = RealSshAdapter(g)
    _, s = await session(lab, adapter)
    try:
        g.load([{"id": "lo", "cidr": "127.0.0.1/32", "kind": "INCLUDE", "profile": "IT"}], armed=False,
               safe_mode=False)
        seen = len(lab.received)
        r = await adapter.execute(s, RemoteOperation.UNINSTALL_AGENT, {})
        assert r.status == ResultStatus.BLOCKED and len(lab.received) == seen
    finally:
        await adapter.close_session(s)
