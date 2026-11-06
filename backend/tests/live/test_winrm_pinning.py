"""WinRM certificate pinning (phase L6) against real TLS servers on 127.0.0.1: the pin is checked in the TLS stage
and again inside every pypsrp connection, before any credential is sent; a server that swaps its certificate after
the check is refused; installs need a pin; the probe pins on first use, detects a change, and an admin can reset."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from contextlib import asynccontextmanager

import pytest
from cryptography import x509

from app.adapters.base import Credential, ResultStatus, Target
from app.adapters.real.net import winrm
from app.adapters.real.winrm import RealWinRmAdapter
from tests.conftest import free_port
from tests.live.test_winrm import gate, self_signed

pytestmark = pytest.mark.live
SECRET = "s3cret-pass"


def fingerprint(cert_pem: str) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding
    return hashlib.sha256(x509.load_pem_x509_certificate(cert_pem.encode()).public_bytes(Encoding.DER)).hexdigest()


def context(tmp_path, name: str, cn: str) -> tuple[ssl.SSLContext, str]:
    cert, key = self_signed(cn)
    (tmp_path / f"{name}.pem").write_text(cert)
    (tmp_path / f"{name}.key").write_text(key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(tmp_path / f"{name}.pem", tmp_path / f"{name}.key")
    return ctx, cert


@asynccontextmanager
async def tls_host(contexts, port: int | None = None):
    """A TLS server that presents contexts[0] on its first successful handshake and contexts[-1] afterwards
    (one context = a normal host; two = a host swapped right after OTProbe checked it). Records what it receives."""
    received: list[bytes] = []
    handshakes = 0

    async def handle(reader, writer):
        nonlocal handshakes
        try:
            await writer.start_tls(contexts[min(handshakes, len(contexts) - 1)])
            handshakes += 1
            received.append(await asyncio.wait_for(reader.read(4096), 2))
        except (asyncio.TimeoutError, ConnectionError, ssl.SSLError, OSError):
            pass
        writer.close()

    port = port or free_port()
    server = await asyncio.start_server(handle, "127.0.0.1", port)
    async with server:
        yield {"port": port, "received": received}


async def open_with(port: int, **options):
    adapter, seen = RealWinRmAdapter(gate()), []

    async def on_stage(st):
        seen.append((st.name, st.status.value, st.detail))

    cred = Credential("OT-WINDOWS-INSTALLER", "svc-otprobe", SECRET, {"skipCertCheck": True})
    res, session = await adapter.open_session(Target("127.0.0.1", port=port, credential=cred, options=options),
                                              on_stage)
    return res, session, seen


async def test_pinned_certificate_passes_and_a_different_one_is_refused_before_login(tmp_path):
    ctx, cert = context(tmp_path, "a", "eng-ws-07")
    pin = fingerprint(cert)
    async with tls_host([ctx]) as host:
        res, _, seen = await open_with(host["port"], cert_sha256=pin)
        tls = next(s for s in seen if s[0] == "TLS_VALIDATED")
        assert tls[1] == "OK" and "matches the pinned SHA-256" in tls[2]
        assert res.status != ResultStatus.TLS_INVALID           # gets as far as authentication (not a real WinRM)

        res, session, seen = await open_with(host["port"], cert_sha256="ab" * 32)
        assert session is None and res.status == ResultStatus.TLS_INVALID and res.error_code == "CERT_CHANGED"
        assert seen[-1][0] == "TLS_VALIDATED" and "certificate changed" in seen[-1][2].lower()
        assert res.raw["seen_cert_sha256"] == pin and "services.winrm.cert_sha256" not in res.data
    assert all(SECRET.encode() not in r for r in host["received"])


async def test_pin_is_enforced_inside_the_winrm_connection_itself(tmp_path):
    """The check above runs on its own connection; this proves pypsrp's connection checks the pin too."""
    ctx, cert = context(tmp_path, "a", "eng-ws-07")
    cred = Credential("OT-WINDOWS-INSTALLER", "svc-otprobe", SECRET, {"skipCertCheck": True})
    async with tls_host([ctx]) as host:
        wrong = await winrm.run(gate(), "127.0.0.1", host["port"], cred, "ps_version", 3.0, pin="cd" * 32)
        assert wrong.status == "CERT_CHANGED", wrong.detail
        assert host["received"] == []                           # refused in the handshake: no HTTP request at all
        right = await winrm.run(gate(), "127.0.0.1", host["port"], cred, "ps_version", 3.0, pin=fingerprint(cert))
        assert right.status not in ("CERT_CHANGED", "TLS_INVALID"), right.detail
        assert host["received"]                                  # this time the request was sent


async def test_server_swapped_after_the_check_is_refused(tmp_path):
    first, _ = context(tmp_path, "a", "eng-ws-07")
    impostor, _ = context(tmp_path, "b", "eng-ws-07")             # same name, different key
    async with tls_host([first, impostor]) as host:
        res, session, seen = await open_with(host["port"])        # first contact: trust what the check sees
        assert session is None and res.error_code == "CERT_CHANGED", seen
        assert [s[0] for s in seen][:3] == ["CONNECTING", "TCP_OK", "TLS_VALIDATED"] and seen[2][1] == "OK"
    assert all(SECRET.encode() not in r for r in host["received"])


async def test_install_sessions_need_a_pinned_certificate(tmp_path):
    ctx, _ = context(tmp_path, "a", "eng-ws-07")
    async with tls_host([ctx]) as host:
        res, session, seen = await open_with(host["port"], require_cert_pin=True)
        assert session is None and res.error_code == "NO_CERT_PIN" and "agentless probe" in res.error_detail
        assert [s[0] for s in seen] == ["TLS_VALIDATED"]          # stopped before even connecting
        assert host["received"] == []


async def test_probe_pins_on_first_use_detects_a_change_and_admin_can_reset(live, tmp_path):
    from tests.live.test_live_loopback import add_scope, safe_mode

    ctx_a, cert_a = context(tmp_path, "a", "eng-ws-07")
    ctx_b, cert_b = context(tmp_path, "b", "eng-ws-07")
    port = free_port()
    await add_scope(live)
    await safe_mode(live, False)
    await live.login("admin")
    r = await live.client.put("/api/v1/vault/profiles/OT-WINDOWS-READONLY", json={
        "protocol": "WinRM", "username": "svc-otprobe", "secret": SECRET,
        "params": {"port": port, "skipCertCheck": True}})
    assert r.status_code == 200, r.text
    await live.login("operator")
    await live.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP"]}, expect=202)
    await live.idle()
    asset_id = (await live.asset_by_ip("127.0.0.1"))["id"]

    async def probe() -> dict:
        r = await live.post(f"/assets/{asset_id}/probes", expect=202)
        await live.idle()
        p = await live.get(f"/probes/{r.json()['id']}")
        return next(s for s in p["steps"] if s["name"] == "WINRM")

    async def pinned() -> str | None:
        detail = await live.get(f"/assets/{asset_id}")
        return next((f["value"] for g in detail["groups"].values() for f in g
                     if f["path"] == "services.winrm.cert_sha256"), None)

    async with tls_host([ctx_a], port):
        await probe()
    assert await pinned() == fingerprint(cert_a)
    first = (await live.get("/audit-events", params={"action": "WINRM_CERT_PINNED"}))["items"]
    assert len(first) == 1 and fingerprint(cert_a) in first[0]["details"]["message"]

    async with tls_host([ctx_b], port):                          # same address, different certificate
        step = await probe()
    assert step["status"] == "FAILED" and "certificate changed" in step["detail"].lower()
    assert await pinned() == fingerprint(cert_a)                  # the pin is not overwritten
    assert (await live.get("/audit-events", params={"action": "WINRM_CERT_CHANGED"}))["items"]

    r = await live.post(f"/assets/{asset_id}/trust/reset", {"reason": "host reinstalled, checked on site"})
    assert r.status_code == 403                                   # operators cannot reset trust
    await live.login("admin")
    r = await live.post(f"/assets/{asset_id}/trust/reset", {"reason": "host reinstalled, checked on site"},
                        expect=200)
    assert r.json()["cleared"] == ["services.winrm.cert_sha256"]
    reset = (await live.get("/audit-events", params={"action": "ASSET_TRUST_RESET"}))["items"][0]
    assert reset["details"]["cleared"]["services.winrm.cert_sha256"] == fingerprint(cert_a)
    await live.post(f"/assets/{asset_id}/trust/reset", {"reason": "again"}, expect=409)
    await live.login("operator")

    async with tls_host([ctx_b], port):
        await probe()
    assert await pinned() == fingerprint(cert_b)                  # re-pinned on the next first contact
