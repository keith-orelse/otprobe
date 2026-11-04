"""Live-mode fixtures. Everything runs against 127.0.0.1 only: a real TCP listener and a real SNMP agent (pysnmp
command responder) on loopback, and the API with real adapters behind the network gate. Nothing leaves the host."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import httpx
import pytest
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context

from app.adapters.real.tcp import PORTS
from app.core.config import Settings
from app.main import create_app
from tests.conftest import Harness

LIVE_PASSWORDS = {"admin": "admin-live-pass-1", "operator": "operator-live-pass-1",
                  "approver": "approver-live-pass-1"}
V3_USER, V3_AUTH, V3_PRIV = "lab-ro", "lab-auth-pass-1", "lab-priv-pass-1"


class LiveHarness(Harness):
    async def login(self, username: str = "operator") -> "LiveHarness":
        if username not in self.tokens:
            r = await self.client.post(f"{self.prefix}/auth/login",
                                       json={"username": username, "password": LIVE_PASSWORDS[username]})
            assert r.status_code == 200, r.text
            self.tokens[username] = r.json()["accessToken"]
        self.client.headers["Authorization"] = f"Bearer {self.tokens[username]}"
        return self


def live_settings(db_path: Path, **overrides) -> Settings:
    return Settings.from_env(**{"database_url": f"sqlite:///{db_path}", "adapter_mode": "real",
                                "admin_password": LIVE_PASSWORDS["admin"],
                                "operator_password": LIVE_PASSWORDS["operator"],
                                "approver_password": LIVE_PASSWORDS["approver"], **overrides})


@pytest.fixture
async def live(tmp_path: Path):
    app = create_app(live_settings(tmp_path / "live.db"))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            yield await LiveHarness(app, client).login("operator")


@pytest.fixture
async def tcp_listener():
    """A real listening socket on one of the ports the TCP adapter checks."""
    for port in (44818, 20000, 18245, 9600, 4840, 8443, 8080):
        assert port in PORTS
        try:
            server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", port)
        except OSError:
            continue
        yield port
        server.close()
        await server.wait_closed()
        return
    pytest.skip("no candidate TCP port free on 127.0.0.1")


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def snmp_agent():
    """A real SNMP agent: v2c community 'lab-public' and v3 user lab-ro (SHA-256 / AES-128), read-only view."""
    port = _free_udp_port()
    eng = engine.SnmpEngine()
    config.add_transport(eng, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(("127.0.0.1", port)))
    config.add_v1_system(eng, "lab-area", "lab-public")
    config.add_v3_user(eng, V3_USER, config.USM_AUTH_HMAC192_SHA256, V3_AUTH, config.USM_PRIV_CFB128_AES, V3_PRIV)
    config.add_vacm_user(eng, 2, "lab-area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1))
    config.add_vacm_user(eng, 3, V3_USER, "authPriv", (1, 3, 6, 1, 2, 1))
    ctx = context.SnmpContext(eng)
    for responder in (cmdrsp.GetCommandResponder, cmdrsp.NextCommandResponder, cmdrsp.BulkCommandResponder):
        responder(eng, ctx)
    eng.transport_dispatcher.job_started(1)
    yield port
    eng.transport_dispatcher.close_dispatcher()
