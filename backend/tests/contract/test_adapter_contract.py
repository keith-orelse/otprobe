"""Adapter contract suite (docs/ADAPTERS.md §4). Parametrised over every registered implementation, so a
future real adapter must pass the same tests against a lab target."""

from __future__ import annotations

import inspect

import pytest

from app.adapters.base import (
    Credential,
    Protocol,
    ProtocolAdapter,
    Query,
    RemoteOperation,
    ResultStatus,
    Target,
)
from app.core.fields import PROVENANCE_FIELDS
from app.main import build_context
from tests.conftest import make_settings
from tests.sim import SimEnvironment
from tests.sim import demo_credentials as dc

pytestmark = pytest.mark.contract

GOOD = {
    Protocol.SNMP: ("192.168.20.1", dc.SNMPV3_RO),
    Protocol.WINRM: ("192.168.20.13", dc.WINDOWS_READONLY),
    Protocol.WMI: ("192.168.20.13", dc.WINDOWS_READONLY),
    Protocol.SSH: ("192.168.20.149", dc.LINUX_SSH_RO),
    Protocol.ICMP: ("192.168.20.13", None),
    Protocol.ARP: ("192.168.20.13", None),
    Protocol.MQTT: ("192.168.10.20", None),
}
NO_DEVICE = "192.168.20.250"


def cred(entry) -> Credential | None:
    return Credential(entry[0], entry[2], entry[3]) if entry else None


@pytest.fixture
def ctx(db_path):
    c = build_context(make_settings(db_path), environment=SimEnvironment())
    yield c
    c.db.dispose()


def impls(ctx):
    return [(p, name, a) for p in Protocol for name, a in ctx.registry.implementations(p).items()]


async def test_c01_descriptor(ctx):
    for p, name, a in impls(ctx):
        d = a.descriptor()
        assert d.protocol == p and d.implementation == name and d.display_label


async def test_c02_async_signatures(ctx):
    for _, _, a in impls(ctx):
        assert isinstance(a, ProtocolAdapter)
        for m in ("probe", "health_check", "get_device_info"):
            assert inspect.iscoroutinefunction(getattr(a, m)), m
        assert inspect.isasyncgenfunction(a.discover)


async def test_c03_unknown_target_is_a_result_not_an_exception(ctx):
    for p, _, a in impls(ctx):
        res = await a.probe(Target(NO_DEVICE, credential=cred(GOOD[p][1])), Query([]))
        assert res.status in {ResultStatus.UNREACHABLE, ResultStatus.TIMEOUT, ResultStatus.BLOCKED,
                              ResultStatus.NOT_SUPPORTED}, (p, res.status)


async def test_c04_c05_normalised_fields_and_metadata(ctx):
    for p, _, a in impls(ctx):
        ip, c = GOOD[p]
        res = await a.probe(Target(ip, credential=cred(c)), Query([]))
        assert res.ok, (p, res.error_detail)
        assert set(res.data) <= PROVENANCE_FIELDS, (p, set(res.data) - PROVENANCE_FIELDS)
        assert res.collected_at is not None and res.collected_at.tzinfo is not None
        assert res.latency_ms is not None and res.latency_ms >= 0


@pytest.mark.parametrize("protocol", [Protocol.SNMP, Protocol.WINRM, Protocol.WMI, Protocol.SSH])
async def test_c06_wrong_credential_and_no_secret_leak(ctx, protocol):
    ip, c = GOOD[protocol]
    bad = Credential(c[0], c[2], "Wrong-Secret-123")
    for a in ctx.registry.implementations(protocol).values():
        res = await a.probe(Target(ip, credential=bad), Query([]))
        assert res.status == ResultStatus.AUTH_FAILED
        blob = repr(res) + str(res.raw) + str(res.error_detail) + repr(bad)
        assert "Wrong-Secret-123" not in blob and c[3] not in blob


async def test_c07_safe_mode_rate_limit(ctx, monkeypatch):
    waits: list[float] = []
    original = ctx.pacer.sleep

    async def record(seconds: float) -> None:
        waits.append(seconds)
        await original(seconds)

    monkeypatch.setattr(ctx.pacer, "sleep", record)
    for p in (Protocol.ARP, Protocol.ICMP, Protocol.SNMP):
        for a in ctx.registry.implementations(p).values():
            waits.clear()
            async for _ in a.discover(Target("192.168.10.0/24", credential=cred(dc.SNMPV3_RO), safe_mode=True)):
                pass
            assert waits and min(waits) >= 1.0, (p, waits)


async def test_c08_timeout_honoured(ctx, monkeypatch):
    waits: list[float] = []
    original = ctx.pacer.sleep

    async def record(seconds: float) -> None:
        waits.append(seconds)
        await original(seconds)

    monkeypatch.setattr(ctx.pacer, "sleep", record)
    snmp = ctx.registry.get(Protocol.SNMP)
    res = await snmp.probe(Target("192.168.20.13", credential=cred(dc.SNMPV3_RO), timeout_sec=1.5), Query([]))
    assert res.status == ResultStatus.TIMEOUT and 1.5 in waits


async def test_c09_deterministic(ctx):
    for p, _, a in impls(ctx):
        ip, c = GOOD[p]
        r1 = await a.probe(Target(ip, credential=cred(c)), Query([]))
        r2 = await a.probe(Target(ip, credential=cred(c)), Query([]))
        assert r1.data == r2.data, p


async def test_c10_discover_unique(ctx):
    for _, _, a in impls(ctx):
        for cidr in ("192.168.20.0/24", "192.168.10.0/24"):
            ips = [h.ip async for h in a.discover(Target(cidr, credential=cred(dc.SNMPV3_RO)))]
            assert len(ips) == len(set(ips))


async def test_c11_winrm_stage_order(ctx):
    winrm = ctx.registry.get(Protocol.WINRM)
    target = Target("192.168.20.13", port=5986, credential=cred(dc.WINDOWS_READONLY))
    res, session = await winrm.open_session(target)
    assert [s.name for s in res.stages] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED", "AUTH_OK", "SESSION_CREATED"]
    assert session is not None
    await winrm.close_session(session)
    ctx.extras["world"].set_fault("dev-ews01", "winrm_bad_certificate")
    res, session = await winrm.open_session(target)
    assert session is None and res.status == ResultStatus.TLS_INVALID
    assert [s.name for s in res.stages] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED"]
    assert res.stages[-1].status == ResultStatus.TLS_INVALID


async def test_c12_winrm_rejects_free_form_commands(ctx):
    winrm = ctx.registry.get(Protocol.WINRM)
    res, session = await winrm.open_session(Target("192.168.20.13", credential=cred(dc.WINDOWS_READONLY)))
    with pytest.raises(ValueError):
        await winrm.execute(session, "Remove-Item C:\\ -Recurse", {})
    ok = await winrm.execute(session, RemoteOperation.QUERY_HOSTNAME, {})
    assert ok.data == {"identity.hostname": "eng-ws-01"}


async def test_c13_mqtt_wildcards(ctx):
    mqtt = ctx.registry.get(Protocol.MQTT)
    got = []

    async def handler(m):
        got.append(m.topic)

    sid = await mqtt.subscribe("factory/+/sensor01/#", handler)
    broker = ctx.extras["broker"]
    await broker.publish("factory/line1/sensor01/temperature", {"temperature": 42.5, "unit": "C"}, "sensor01")
    await broker.publish("factory/line1/sensor02/pressure", {"pressure": 4.2}, "sensor02")
    await mqtt.unsubscribe(sid)
    await broker.publish("factory/line1/sensor01/temperature", {"temperature": 43}, "sensor01")
    assert got == ["factory/line1/sensor01/temperature"]


async def test_c14_vault_masks_and_audits(ctx):
    from sqlalchemy import select

    from app.models import AuditEvent
    profiles = await ctx.vault.list_profiles()
    assert {p.profile for p in profiles} >= {"OT-WINDOWS-READONLY", "OT-WINDOWS-INSTALLER"}
    assert all(p.secret == "••••••••" for p in profiles)
    assert all(c[3] not in repr(profiles) for c in dc.ALL)
    c = await ctx.vault.resolve("OT-WINDOWS-INSTALLER", purpose="contract test", correlation_id="x")
    assert c.username == "demo\\agent-installer" and c.secret not in repr(c)
    with ctx.db.session() as s:
        ev = s.scalars(select(AuditEvent).where(AuditEvent.action == "CREDENTIAL_RETRIEVED")).all()
    assert ev and all(dc.WINDOWS_INSTALLER[3] not in str(e.details) for e in ev)
