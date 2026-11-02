"""K: swapping an adapter is configuration only; no business-service change."""

from __future__ import annotations

from typing import AsyncIterator

import httpx
import pytest

from app.adapters.base import (
    AdapterDescriptor,
    AdapterResult,
    DiscoveredHost,
    Protocol,
    Query,
    ResultStatus,
    SnmpAdapter,
    Target,
)
from app.main import build_context, create_app
from tests.conftest import Harness, make_settings

pytestmark = pytest.mark.acceptance


class FakeSnmpAdapter(SnmpAdapter):
    """Stand-in for a future real implementation."""

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(Protocol.SNMP, "fake", False, "SNMP (fake)")

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        if target.address == "192.168.20.0/24":
            yield DiscoveredHost("192.168.20.1", None, Protocol.SNMP, {"snmp.sys_name": "fake-switch"})

    async def probe(self, target: Target, query: Query, on_stage=None) -> AdapterResult:
        return AdapterResult(Protocol.SNMP, target.address, ResultStatus.TIMEOUT)

    async def health_check(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query([]))

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query([]))


def plugin(registry, ctx) -> None:
    registry.register(Protocol.SNMP, "fake", FakeSnmpAdapter())


async def test_override_selects_alternative_adapter(db_path):
    app = create_app(make_settings(db_path, adapter_overrides="snmp=fake"), adapter_plugins=[plugin])
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            h = await Harness(app, c).login()
            await h.discover(["192.168.20.0/24"])
            switch = await h.asset_by_ip("192.168.20.1")
            assert switch["sysName"] == "fake-switch"
            label = next(f["sourceLabel"] for f in switch["groups"]["Identity"] if f["path"] == "snmp.sys_name")
            assert label == "SNMP (fake)"
            health = await h.get("/health")
            assert health["adapters"]["overrides"] == {"snmp": "fake"}


def test_real_mode_fails_fast_without_real_adapters(db_path):
    with pytest.raises(RuntimeError, match="No real adapter registered for protocol 'icmp'"):
        build_context(make_settings(db_path, adapter_mode="real"))
