from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

TEST_SPEED = 0.002
BOTH_SUBNETS = ["192.168.20.0/24", "192.168.10.0/24"]
PASSWORDS = {"operator": "operator-demo", "approver": "approver-demo", "admin": "admin-demo"}
AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"


class Harness:
    def __init__(self, app, client: httpx.AsyncClient, prefix: str = "/api/v1") -> None:
        self.app, self.client, self.prefix = app, client, prefix
        self.tokens: dict[str, str] = {}

    @property
    def ctx(self):
        return self.app.state.ctx

    async def login(self, username: str = "operator") -> "Harness":
        if username not in self.tokens:
            r = await self.client.post(f"{self.prefix}/auth/login",
                                       json={"username": username, "password": PASSWORDS[username]})
            assert r.status_code == 200, r.text
            self.tokens[username] = r.json()["accessToken"]
        self.client.headers["Authorization"] = f"Bearer {self.tokens[username]}"
        return self

    async def get(self, path: str, **kw) -> Any:
        r = await self.client.get(f"{self.prefix}{path}", **kw)
        assert r.status_code == 200, r.text
        return r.json()

    async def post(self, path: str, json: Any = None, key: str | None = None, expect: int | None = None
                   ) -> httpx.Response:
        r = await self.client.post(f"{self.prefix}{path}", json=json,
                                   headers={"Idempotency-Key": key or str(uuid.uuid4())})
        if expect is not None:
            assert r.status_code == expect, r.text
        return r

    async def idle(self) -> None:
        await self.ctx.runner.wait_idle(60)

    async def discover(self, targets: list[str] | None = None, methods: list[str] | None = None) -> dict:
        body = {"targets": targets or BOTH_SUBNETS}
        if methods:
            body["methods"] = methods
        r = await self.post("/discovery/jobs", body, expect=202)
        await self.idle()
        return await self.get(f"/discovery/jobs/{r.json()['id']}")

    async def assets(self) -> list[dict]:
        return (await self.get("/assets", params={"limit": 500}))["items"]

    async def asset_by_ip(self, ip: str) -> dict:
        a = next(a for a in await self.assets() if a["ip"] == ip)
        return await self.get(f"/assets/{a['id']}")

    async def probe(self, ip: str) -> dict:
        asset = await self.asset_by_ip(ip)
        r = await self.post(f"/assets/{asset['id']}/probes", expect=202)
        await self.idle()
        return await self.get(f"/probes/{r.json()['id']}")

    async def wait_for(self, path: str, pred, timeout: float = 30.0, interval: float = 0.05) -> dict:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            data = await self.get(path)
            if pred(data):
                return data
            if asyncio.get_running_loop().time() > deadline:
                raise AssertionError(f"timeout waiting on {path}: last={data}")
            await asyncio.sleep(interval)


def make_settings(db_path: Path, **overrides) -> Settings:
    return Settings.from_env(**{"database_url": f"sqlite:///{db_path}", "speed_factor": TEST_SPEED, **overrides})


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "otprobe-test.db"


@pytest.fixture
async def h(db_path: Path):
    app = create_app(make_settings(db_path))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield await Harness(app, client).login("operator")


@pytest.fixture
async def discovered(h: Harness) -> Harness:
    job = await h.discover()
    assert job["status"] == "COMPLETED", job
    return h


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    """The real API served over loopback HTTP by uvicorn, so a separate agent process can call it."""

    def __init__(self, db_path: Path, **settings) -> None:
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.app = create_app(make_settings(db_path, agent_server_url=self.url, **settings))
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="warning"))
        self.task: asyncio.Task | None = None

    async def __aenter__(self) -> "LiveServer":
        self.task = asyncio.create_task(self.server.serve())
        while not self.server.started:
            await asyncio.sleep(0.02)
        return self

    async def __aexit__(self, *exc) -> None:
        self.server.should_exit = True
        await self.task


def spawn_agent_runtime(api_url: str, log_path: Path) -> subprocess.Popen:
    env = {**os.environ, "OTPROBE_API_URL": api_url, "SIM_SERVICE_TOKEN": "change-me-sim-token",
           "RUNTIME_POLL_SEC": "0.2", "TASK_POLL_WAIT_SEC": "1", "PYTHONUNBUFFERED": "1"}
    return subprocess.Popen([sys.executable, "-m", "otprobe_agent"], cwd=AGENT_DIR, env=env,
                            stdout=open(log_path, "w"), stderr=subprocess.STDOUT)


@pytest.fixture
async def live(db_path: Path, tmp_path: Path):
    """Live API (heartbeat every 0.5 s) + agent runtime in a SEPARATE OS process. Yields (harness, process)."""
    async with LiveServer(db_path, heartbeat_interval_sec=0.5) as srv:
        async with httpx.AsyncClient(base_url=srv.url, timeout=30) as client:
            proc = spawn_agent_runtime(srv.url, tmp_path / "agent-runtime.log")
            try:
                yield await Harness(srv.app, client).login("operator"), proc
            finally:
                proc.terminate()
                proc.wait(5)
