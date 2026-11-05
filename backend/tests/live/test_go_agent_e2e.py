"""The real Go agent through the real deployment workflow (LIVE_TEST_PLAN acceptance D, E, I at stage 2).

A test stand-in for the Windows host (FakeHost) replaces only the WinRM transport: where a real host would run the
install script, it writes the same agent.json and starts the compiled Go agent on this machine. Everything else is
real: signed release verification, package transfer, hash check, the enrollment token, HTTPS with the CA pinned,
enrollment, heartbeats, a deep assessment with real evidence, removal and credential revocation.
The PowerShell scripts themselves are covered by test_winrm.py and by the Windows lab test (docs/TESTING_L4.md)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import shutil
import socket
import ssl
import subprocess
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Mapping

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.adapters.base import (
    AdapterDescriptor,
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    RemoteOperation,
    RemoteSession,
    ResultStatus,
    Target,
    WinRmAdapter,
)
from app.adapters.real.net.winrm import WinRmReply
from app.core.clock import utcnow
from app.engines.inventory import refresh_asset, upsert_fields
from app.main import create_app
from app.models import Asset
from tests.conftest import free_port
from tests.flows import approve, precheck, remove_agent
from tests.live.conftest import LiveHarness, live_settings

pytestmark = pytest.mark.live
REPO = Path(__file__).resolve().parents[3]
VERSION = "9.9.9"
BUILD = "windows-amd64"     # the manifest labels this machine's binary as the Windows build the test host asks for


def load_tls_helper():
    spec = importlib.util.spec_from_file_location("make_lab_tls", REPO / "scripts" / "make_lab_tls.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def agent_binary(tmp_path_factory) -> Path:
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not installed")
    out = tmp_path_factory.mktemp("agent") / "otprobe-agent"
    subprocess.run(["go", "build", "-ldflags", f"-X otprobe/agent/internal/collectors.Version={VERSION}", "-o",
                    str(out), "./cmd/otprobe-agent"], cwd=REPO / "agent-go", check=True,
                   env={**__import__("os").environ, "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"})
    return out


def signed_release(dist: Path, binary: Path) -> str:
    key = Ed25519PrivateKey.generate()
    folder = dist / VERSION
    folder.mkdir(parents=True)
    name = f"otprobe-agent-{VERSION}-{BUILD}.exe"
    shutil.copy(binary, folder / name)
    sha = hashlib.sha256((folder / name).read_bytes()).hexdigest()
    sums = f"{sha}  {name}\n".encode()
    (folder / "SHA256SUMS").write_bytes(sums)
    (folder / "SHA256SUMS.sig").write_text(base64.b64encode(key.sign(sums)).decode())
    (folder / "manifest.json").write_text(json.dumps({"version": VERSION, "builds": [
        {"id": BUILD, "file": name, "os": "windows", "arch": "amd64", "variant": "modern", "sha256": sha,
         "size": (folder / name).stat().st_size, "minOs": "Windows 10"}]}))
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


class FakeHost(WinRmAdapter):
    """Stands in for a Windows host's WinRM endpoint. Installing = writing agent.json and starting the real agent."""

    def __init__(self, root: Path, binary: Path) -> None:
        self.root, self.binary = root, binary
        self.staging = root / "staging"
        self.config = root / "agent.json"
        self.proc: subprocess.Popen | None = None
        self.ops: list[str] = []
        self.install_params: dict[str, Any] = {}
        self.explode_on: set[str] = set()

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(Protocol.WINRM, "fakehost", False, "WinRM (test host)")

    def _ok(self, ip: str, data=None, raw=None) -> AdapterResult:
        return AdapterResult(Protocol.WINRM, ip, ResultStatus.OK, data or {}, raw or {}, collected_at=utcnow(),
                             latency_ms=1.0)

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover

    async def health_check(self, target: Target) -> AdapterResult:
        return self._ok(target.address, {"services.winrm.available": True, "services.winrm.port": 5986})

    async def probe(self, target: Target, query: Query, on_stage=None) -> AdapterResult:
        return await self.health_check(target)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.health_check(target)

    async def open_session(self, target: Target, on_stage=None):
        return self._ok(target.address), RemoteSession("s1", target.address, [])

    async def close_session(self, session: RemoteSession) -> None:
        return None

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.running():
            self.proc.terminate()
            self.proc.wait(10)

    async def copy(self, session: RemoteSession, local: str, remote: str) -> WinRmReply:
        self.staging.mkdir(parents=True, exist_ok=True)
        shutil.copy(local, self.staging / Path(local).name)
        return WinRmReply("OK", output=remote)

    async def execute(self, session: RemoteSession, op: RemoteOperation, params: Mapping[str, Any]) -> AdapterResult:
        self.ops.append(op.value)
        if op.value in self.explode_on:
            raise RuntimeError(f"simulated engine-side failure at {op.value}")
        ip = session.target
        staged = self.staging / str(params.get("path", "")).replace("\\", "/").rsplit("/", 1)[-1]
        if op == RemoteOperation.QUERY_HOSTNAME:
            return self._ok(ip, {"identity.hostname": socket.gethostname()})
        if op == RemoteOperation.QUERY_DISK_FREE:
            return self._ok(ip, {"hardware.disk": [{"drive": "C:", "size_gb": 120, "free_gb": 80}]})
        if op == RemoteOperation.QUERY_AGENT_INSTALLED:
            return self._ok(ip, raw={"installed": self.config.exists()})
        if op in (RemoteOperation.QUERY_SERVER_CONNECTIVITY, RemoteOperation.START_SERVICE):
            return self._ok(ip)
        if op == RemoteOperation.QUERY_REBOOT_PENDING:
            return self._ok(ip, raw={"reboot_pending": False})
        if op == RemoteOperation.VERIFY_FILE_HASH:
            actual = hashlib.sha256(staged.read_bytes()).hexdigest()
            ok = actual == params["sha256"]
            return AdapterResult(Protocol.WINRM, ip, ResultStatus.OK if ok else ResultStatus.ERROR,
                                 collected_at=utcnow(), error_code=None if ok else "HASH_MISMATCH")
        if op == RemoteOperation.INSTALL_AGENT:
            self.install_params = dict(params)
            self.config.write_text(json.dumps({
                "serverUrl": params["server_url"], "caSha256": params["ca_sha256"],
                "enrollmentToken": params["enrollment_token"], "deploymentId": params["deployment_id"],
                "profile": params["profile"]}))
            self.proc = subprocess.Popen([str(self.binary), "run", "--config", str(self.config)],
                                         stdout=open(self.root / "agent.log", "w"), stderr=subprocess.STDOUT)
            return self._ok(ip, raw={"path": str(self.binary)})
        if op == RemoteOperation.QUERY_SERVICE:
            svc = {"name": "OTProbeAgent", "state": "running", "start_type": "auto"} if self.running() else None
            return self._ok(ip, raw={"service": svc})
        if op == RemoteOperation.STOP_SERVICE:
            self.stop()
            return self._ok(ip)
        if op == RemoteOperation.UNINSTALL_AGENT:
            self.stop()
            self.config.unlink(missing_ok=True)
            return self._ok(ip)
        if op == RemoteOperation.REMOVE_FILES:
            shutil.rmtree(self.staging, ignore_errors=True)
            return self._ok(ip)
        return AdapterResult(Protocol.WINRM, ip, ResultStatus.NOT_SUPPORTED, collected_at=utcnow())


@asynccontextmanager
async def stack(tmp_path, agent_binary, host):
    tls = load_tls_helper()
    pin = tls.main(["127.0.0.1"], tmp_path / "tls")
    pubkey = signed_release(tmp_path / "dist", agent_binary)
    port = free_port()
    settings = live_settings(tmp_path / "e2e.db", public_url=f"https://127.0.0.1:{port}",
                             tls_ca_file=str(tmp_path / "tls" / "otprobe-ca.pem"),
                             agent_dist_dir=str(tmp_path / "dist"), agent_release_pubkey=pubkey,
                             heartbeat_interval_sec=1.0, adapter_overrides="winrm=fakehost")
    app = create_app(settings, adapter_plugins=[lambda reg, ctx: reg.register(Protocol.WINRM, "fakehost", host)])
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
            assert ctx.settings.ca_sha256 == pin
            await h.post("/scope", {"cidr": "127.0.0.1/32", "profile": "IT", "level": "2"}, expect=201)
            await h.post("/safety/safe-mode", {"enabled": False, "reason": "agent e2e"}, expect=200)
            r = await client.put("/api/v1/vault/profiles/OT-WINDOWS-INSTALLER", json={
                "protocol": "WinRM", "username": ".\\otprobe", "secret": "installer-pass-1"})
            assert r.status_code == 200, r.text
            packages = {p["id"]: p for p in await h.get("/packages")}
            assert packages[f"agent-{VERSION}-{BUILD}"]["status"] == "ACTIVE"

            # The asset as an agentless probe of a Windows 11 host would leave it.
            await h.login("operator")
            await h.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
            await h.idle()
            with ctx.db.session() as s:
                asset = s.query(Asset).filter_by(ip="127.0.0.1").one()
                upsert_fields(s, asset.id, {"os.family": "windows", "os.name": "Microsoft Windows 11 Enterprise",
                                            "os.product": "Windows 11 Enterprise",
                                            "identity.hostname": socket.gethostname(),
                                            "services.winrm.available": True}, "WMI", "AGENTLESS", "PROBE", "seed")
                refresh_asset(s, asset, ctx.rules)
                asset_id, eligibility = asset.id, asset.eligibility
            assert eligibility == "ELIGIBLE"

            yield h, ctx, port, pin, asset_id
    finally:
        host.stop()
        server.should_exit = True
        await task


async def request_and_precheck(h, asset_id: str) -> dict:
    dep = (await h.post("/deployments", {"assetId": asset_id, "packageId": f"agent-{VERSION}-{BUILD}",
                                         "purpose": "Go agent end to end"}, expect=201)).json()
    await approve(h, dep)
    checked = await precheck(h, dep["id"])
    assert checked["status"] == "PRECHECK_PASSED", checked
    await h.login("operator")
    return dep


async def test_real_go_agent_deploy_enroll_assess_remove(tmp_path, agent_binary):
    host = FakeHost(tmp_path / "host", agent_binary)
    host.root.mkdir()
    async with stack(tmp_path, agent_binary, host) as (h, ctx, port, pin, asset_id):
        dep = await request_and_precheck(h, asset_id)
        await h.post(f"/deployments/{dep['id']}/deploy", expect=202)
        done = await h.wait_for(f"/deployments/{dep['id']}", lambda d: d["status"] in ("COMPLETED", "FAILED"),
                                timeout=60)
        assert done["status"] == "COMPLETED", (done["failureCode"], done["failureDetail"],
                                               (host.root / "agent.log").read_text())
        p = host.install_params
        assert p["server_url"] == f"https://127.0.0.1:{port}" and p["ca_sha256"] == pin
        assert p["profile"] == "windows-workstation" and p["enrollment_token"].startswith("enr_")
        assert "enrollmentToken" not in json.loads(host.config.read_text())    # wiped after enrollment

        agent = await h.wait_for(f"/agents/{done['agentId']}", lambda a: a["status"] == "ONLINE")
        assert agent["version"] == VERSION
        with ctx.db.session() as s:
            from app.models import Agent
            a = s.get(Agent, done["agentId"])
            assert a.platform and a.platform.endswith("modern") and a.profile == "windows-workstation"

        r = await h.post(f"/assets/{asset_id}/assessments", expect=202)
        run = await h.wait_for(f"/assessments/{r.json()['id']}",
                               lambda d: d["status"] not in ("QUEUED", "RUNNING"), timeout=60)
        assert run["status"] != "TIMED_OUT", run
        uploads = (await h.get("/audit-events", params={"action": "ASSESSMENT_EVIDENCE_UPLOADED"}))["items"]
        assert uploads and uploads[0]["details"]["collectors"]["os"] == "ok"

        removal = await remove_agent(h, done["agentId"])
        assert removal["status"] == "COMPLETED", removal
        assert not host.running() and not host.config.exists()
        gone = await h.get(f"/agents/{done['agentId']}")
        assert gone["status"] == "REMOVED"
        assert host.ops.index("VERIFY_FILE_HASH") < host.ops.index("INSTALL_AGENT")


async def test_failure_after_install_uninstalls_from_the_host(tmp_path, agent_binary):
    """Found on a real laptop: an engine error right after INSTALL left the agent half-installed on the host."""
    host = FakeHost(tmp_path / "host", agent_binary)
    host.root.mkdir()
    host.explode_on = {"QUERY_SERVICE"}
    async with stack(tmp_path, agent_binary, host) as (h, ctx, port, pin, asset_id):
        dep = await request_and_precheck(h, asset_id)
        await h.post(f"/deployments/{dep['id']}/deploy", expect=202)
        done = await h.wait_for(f"/deployments/{dep['id']}", lambda d: d["status"] in ("COMPLETED", "FAILED"),
                                timeout=60)
        assert done["status"] == "FAILED" and done["failureCode"] == "ENGINE_ERROR"
        assert host.ops.index("UNINSTALL_AGENT") > host.ops.index("INSTALL_AGENT")
        assert not host.running() and not host.config.exists()
        rolled = (await h.get("/audit-events", params={"action": "DEPLOY_ROLLED_BACK"}))["items"]
        assert rolled and rolled[0]["details"]["uninstalled"] is True
