"""Linux deployment end to end (phase L6): request -> approval -> precheck -> deploy -> enrollment -> removal, through
the API, over real SSH to LinuxLab (tests/live/linux_lab.py), with the real Go agent enrolling over HTTPS with the CA
pinned. The release's "Linux binary" is the lab's stand-in script, which installs a SysV-style service in the
sandbox and starts the real Go agent built for this machine; the host's systemd/SysV integration itself
(agent-go/internal/service/service_linux.go) is exercised by the manual test on a real Linux host
(docs/TESTING_L6_LINUX.md)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import platform as host_platform
import shutil
import socket
import ssl
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.adapters.real.net import ssh as ssh_net
from app.engines.inventory import refresh_asset, upsert_fields
from app.main import create_app
from app.models import Asset
from tests.conftest import free_port
from tests.flows import approve, precheck, remove_agent
from tests.live.conftest import LiveHarness, live_settings
from tests.live.linux_lab import LinuxLab, agent_script
from tests.live.test_go_agent_e2e import VERSION, agent_binary, load_tls_helper  # noqa: F401 (fixture)

pytestmark = pytest.mark.live
ARCH = ssh_net.GOARCH.get(host_platform.machine(), "amd64")
BUILD = f"linux-{ARCH}"


def signed_linux_release(dist: Path, script: str) -> str:
    key = Ed25519PrivateKey.generate()
    folder = dist / VERSION
    folder.mkdir(parents=True)
    name = f"otprobe-agent-{VERSION}-{BUILD}"
    (folder / name).write_text(script)
    sha = hashlib.sha256((folder / name).read_bytes()).hexdigest()
    sums = f"{sha}  {name}\n".encode()
    (folder / "SHA256SUMS").write_bytes(sums)
    (folder / "SHA256SUMS.sig").write_text(base64.b64encode(key.sign(sums)).decode())
    (folder / "manifest.json").write_text(json.dumps({"version": VERSION, "builds": [
        {"id": BUILD, "file": name, "os": "linux", "arch": ARCH, "variant": "modern", "sha256": sha,
         "size": (folder / name).stat().st_size, "minOs": "glibc/musl, kernel 3.2"}]}))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


async def test_linux_host_deploy_enroll_remove_over_ssh(tmp_path, agent_binary, monkeypatch):  # noqa: F811
    if shutil.which("curl") is None:
        pytest.skip("curl not installed (used by the SERVER_CONNECTIVITY check)")
    root = tmp_path / "host"
    monkeypatch.setattr(ssh_net, "ROOT", str(root))
    tls = load_tls_helper()
    pin = tls.main(["127.0.0.1"], tmp_path / "tls")
    async with LinuxLab(root) as lab:
        pubkey = signed_linux_release(tmp_path / "dist", agent_script(root, real=agent_binary))
        port = free_port()
        settings = live_settings(tmp_path / "linux.db", public_url=f"https://127.0.0.1:{port}",
                                 tls_ca_file=str(tmp_path / "tls" / "otprobe-ca.pem"),
                                 agent_dist_dir=str(tmp_path / "dist"), agent_release_pubkey=pubkey,
                                 heartbeat_interval_sec=1.0)
        app = create_app(settings)
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning",
                                               ssl_certfile=str(tmp_path / "tls" / "otprobe-server.pem"),
                                               ssl_keyfile=str(tmp_path / "tls" / "otprobe-server.key")))
        task = asyncio.create_task(server.serve())
        try:
            while not server.started:
                await asyncio.sleep(0.02)
            trust = ssl.create_default_context(cafile=str(tmp_path / "tls" / "otprobe-ca.pem"))
            async with httpx.AsyncClient(base_url=f"https://127.0.0.1:{port}", verify=trust, timeout=30) as client:
                h = await LiveHarness(app, client).login("admin")
                ctx = app.state.ctx
                await h.post("/scope", {"cidr": "127.0.0.1/32", "profile": "IT", "level": "2"}, expect=201)
                await h.post("/safety/safe-mode", {"enabled": False, "reason": "linux e2e"}, expect=200)
                r = await client.put("/api/v1/vault/profiles/OT-LINUX-SSH-INSTALLER", json={
                    "protocol": "SSH", "username": lab.user, "secret": lab.password, "params": {"port": lab.port}})
                assert r.status_code == 200, r.text

                # The asset as an agentless SSH probe of a Debian host leaves it (host key pinned on first use).
                await h.login("operator")
                await h.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
                await h.idle()
                with ctx.db.session() as s:
                    asset = s.query(Asset).filter_by(ip="127.0.0.1").one()
                    upsert_fields(s, asset.id, {
                        "os.family": "linux", "os.name": "Debian GNU/Linux 12 (bookworm)",
                        "os.product": "Debian GNU/Linux", "identity.hostname": socket.gethostname(),
                        "services.ssh.available": True, "ssh.host_key": lab.host_key,
                        "hardware.arch": host_platform.machine()}, "SSH", "AGENTLESS", "PROBE", "seed")
                    refresh_asset(s, asset, ctx.rules)
                    asset_id, eligibility = asset.id, asset.eligibility
                assert eligibility == "ELIGIBLE"

                dep = (await h.post("/deployments", {"assetId": asset_id, "packageId": f"agent-{VERSION}-{BUILD}",
                                                     "purpose": "Linux agent end to end"}, expect=201)).json()
                assert dep["credentialProfile"] == "OT-LINUX-SSH-INSTALLER"       # chosen from the host's OS
                await approve(h, dep)
                checked = await precheck(h, dep["id"])
                results = {c["check"]: (c["status"], c["detail"]) for c in checked["precheck"]}
                assert checked["status"] == "PRECHECK_PASSED", results
                assert list(results) == ["REACHABLE", "HOSTNAME_VERIFIED", "SSH_AVAILABLE", "AUTHENTICATION",
                                         "PACKAGE_COMPATIBLE", "DISK_SPACE", "EXISTING_AGENT", "SERVER_CONNECTIVITY",
                                         "REBOOT_REQUIRED"]
                assert "root access via sudo" in results["AUTHENTICATION"][1]
                assert f"CPU {ARCH}" in results["PACKAGE_COMPATIBLE"][1]

                await h.login("operator")
                await h.post(f"/deployments/{dep['id']}/deploy", expect=202)
                done = await h.wait_for(f"/deployments/{dep['id']}",
                                        lambda d: d["status"] in ("COMPLETED", "FAILED"), timeout=60)
                log = (root / "agent.log").read_text() if (root / "agent.log").exists() else ""
                assert done["status"] == "COMPLETED", (done["failureCode"], done["failureDetail"], log)
                steps = [(st["name"], st["status"]) for st in done["steps"]]
                assert steps == [(n, "OK") for n in ("CONNECT", "SSH_SESSION", "RETRIEVE_CREDENTIAL",
                                                     "TRANSFER_PACKAGE", "VERIFY_HASH", "INSTALL", "SERVICE_CREATED",
                                                     "START_SERVICE", "AWAIT_ENROLLMENT")]
                config = json.loads((root / "etc/otprobe/agent.json").read_text())
                assert "enrollmentToken" not in config and config["agentId"] == done["agentId"]  # wiped
                assert config["caSha256"] == pin and config["profile"] == "linux-host"
                assert not list((root / "var/tmp").glob("otprobe.*"))     # upload folder removed after install

                agent = await h.wait_for(f"/agents/{done['agentId']}", lambda a: a["status"] == "ONLINE")
                assert agent["version"] == VERSION and agent["profile"] == "linux-host"

                removal = await remove_agent(h, done["agentId"])
                assert removal["status"] == "COMPLETED", removal
                assert not (root / "opt/otprobe").exists() and not (root / "etc/otprobe").exists()
                assert not (root / "etc/init.d/otprobe-agent").exists()
                assert (await h.get(f"/agents/{done['agentId']}"))["status"] == "REMOVED"
                assert not any(lab.password in c for c in lab.received)   # never on a command line
        finally:
            server.should_exit = True
            await task
