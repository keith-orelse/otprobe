from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402

TEST_SPEED = 0.002
BOTH_SUBNETS = ["192.168.20.0/24", "192.168.10.0/24"]


class Harness:
    def __init__(self, app, client: httpx.AsyncClient) -> None:
        self.app, self.client = app, client

    @property
    def ctx(self):
        return self.app.state.ctx

    async def get(self, path: str, **kw) -> Any:
        r = await self.client.get(f"/api/v1{path}", **kw)
        assert r.status_code == 200, r.text
        return r.json()

    async def post(self, path: str, json: Any = None, key: str | None = None, expect: int | None = None
                   ) -> httpx.Response:
        r = await self.client.post(f"/api/v1{path}", json=json,
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
            yield Harness(app, client)


@pytest.fixture
async def discovered(h: Harness) -> Harness:
    job = await h.discover()
    assert job["status"] == "COMPLETED", job
    return h
