"""Live mode end to end on 127.0.0.1: scope, safe mode, exclusions, kill switch, discovery (ICMP, ARP, TCP, SNMP),
probe, credential vault. Mirrors LIVE_TEST_PLAN.md L-SAFE-1/3 and acceptance A at stage 1/2."""

from __future__ import annotations

import asyncio

import pytest

from tests.live.conftest import V3_AUTH, V3_PRIV, V3_USER

pytestmark = pytest.mark.live
LOOPBACK = "127.0.0.1/32"


async def add_scope(h, cidr=LOOPBACK, kind="INCLUDE", profile="IT", expect=201, **extra):
    await h.login("admin")
    r = await h.post("/scope", {"cidr": cidr, "kind": kind, "profile": profile, "level": "3",
                                "label": "loopback lab", "authorization": "test suite", **extra}, expect=expect)
    await h.login("operator")
    return r.json()


async def safe_mode(h, enabled: bool):
    await h.login("admin")
    await h.post("/safety/safe-mode", {"enabled": enabled, "reason": "lab test"}, expect=200)
    await h.login("operator")


async def put_snmp_profile(h, name, port, **params):
    await h.login("admin")
    body = {"protocol": "SNMP", "username": V3_USER, "secret": V3_AUTH, "description": "lab agent",
            "params": {"version": "3", "auth": "SHA-256", "priv": "AES-128", "privSecret": V3_PRIV, "port": port,
                       **params}}
    r = await h.client.put(f"/api/v1/vault/profiles/{name}", json=body)
    assert r.status_code == 200, r.text
    await h.login("operator")
    return r.json()


async def test_nothing_is_scanned_until_a_scope_exists(live):
    env = (await live.client.get("/api/v1/environment")).json()            # public: no token needed
    assert env["mode"] == "LIVE" and "NO SCAN SCOPE" in env["banner"] and env["safeMode"] is True
    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK]}, expect=409)
    assert r.json()["type"].endswith("/scan-scope-empty")
    assert live.ctx.gate.totals.as_dict()["sent"] == 0
    r = await live.client.get("/api/v1/health")
    assert r.headers["x-otprobe-environment"] == "LIVE"


async def test_scope_rules(live):
    r = await live.post("/scope", {"cidr": LOOPBACK}, expect=403)                      # operators cannot change scope
    await add_scope(live, "10.0.0.0/8", expect=422)                                     # wider than /16
    entry = await add_scope(live)
    await add_scope(live, expect=409)                                                   # duplicate
    r = await live.post("/discovery/jobs", {"targets": ["10.99.0.0/24"]}, expect=422)
    assert r.json()["type"].endswith("/target-out-of-scope")
    env = (await live.client.get("/api/v1/environment")).json()
    assert env["scope"] == [LOOPBACK] and "127.0.0.1/32" in env["banner"]
    audit = await live.get("/audit-events", params={"action": "SCOPE_CHANGED"})
    assert any(e["entityId"] == entry["id"] for e in audit["items"])


async def test_live_discovery_and_probe_on_loopback(live, tcp_listener, snmp_agent):
    await add_scope(live)
    await safe_mode(live, False)
    masked = await put_snmp_profile(live, "LAB-SNMP", snmp_agent)
    assert masked["secret"] == "••••••••" and V3_AUTH not in str(await live.get("/vault/profiles"))

    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK], "snmpProfile": "LAB-SNMP"}, expect=202)
    await live.idle()
    job = await live.get(f"/discovery/jobs/{r.json()['id']}")
    assert job["status"] == "COMPLETED", job
    assert [s["name"] for s in job["steps"]] == ["VALIDATE", "ICMP", "ARP", "TCP", "SNMP", "MERGE"]

    asset = await live.asset_by_ip("127.0.0.1")
    fields = {f["path"]: f for group in asset["groups"].values() for f in group}
    assert fields["reachability.icmp"]["value"] == "ONLINE"
    assert tcp_listener in fields["network.open_ports"]["value"]
    assert fields["network.open_ports"]["sourceLabel"] == "TCP connect"
    assert "PySNMP" in fields["snmp.sys_descr"]["value"]
    assert {"ICMP", "TCP", "SNMP"} <= set(asset["discoveredBy"])

    safety = await live.get("/safety")
    assert safety["traffic"]["sent"] > 0 and safety["traffic"]["byOperation"]["SNMP_GET"] >= 1

    r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
    await live.idle()
    probe = await live.get(f"/probes/{r.json()['id']}")
    steps = {s["name"]: s for s in probe["steps"]}
    assert steps["ICMP"]["status"] == "OK" and steps["TCP"]["status"] == "OK"
    assert steps["WINRM"]["status"] == "SKIPPED" and "TCP 5986 closed" in steps["WINRM"]["detail"]
    assert steps["SNMP"]["status"] == "SKIPPED" and "OT-SNMPV3-RO" in steps["SNMP"]["detail"]


async def test_wrong_snmp_password_is_reported_not_crashed(live, snmp_agent):
    await add_scope(live)
    await safe_mode(live, False)
    await put_snmp_profile(live, "LAB-SNMP-BAD", snmp_agent)
    await live.login("admin")
    await live.client.put("/api/v1/vault/profiles/LAB-SNMP-BAD", json={
        "protocol": "SNMP", "username": V3_USER, "secret": "wrong-password-1",
        "params": {"version": "3", "auth": "SHA-256", "priv": "AES-128", "privSecret": V3_PRIV, "port": snmp_agent}})
    await live.login("operator")
    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK], "methods": ["ICMP", "SNMP"],
                                            "snmpProfile": "LAB-SNMP-BAD"}, expect=202)
    await live.idle()
    job = await live.get(f"/discovery/jobs/{r.json()['id']}")
    snmp_step = next(s for s in job["steps"] if s["name"] == "SNMP")
    assert job["status"] == "COMPLETED" and snmp_step["detail"] == "0 SNMP agent(s) responded"


async def test_exclusion_wins_over_inclusion(live):
    await add_scope(live, "127.0.0.0/30")
    await safe_mode(live, False)
    await add_scope(live, "127.0.0.1/32", kind="EXCLUDE")
    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK]}, expect=422)
    assert r.json()["type"].endswith("/target-excluded")
    r = await live.post("/discovery/jobs", {"targets": ["127.0.0.0/30"], "methods": ["ICMP"]}, expect=202)
    await live.idle()
    job = await live.get(f"/discovery/jobs/{r.json()['id']}")
    assert job["status"] == "COMPLETED"
    assert "127.0.0.1" not in {a["ip"] for a in await live.assets()}
    assert live.ctx.gate.totals.blocked["excluded"] >= 1


async def test_kill_switch_stops_a_running_discovery_and_blocks_new_work(live, tcp_listener):
    await add_scope(live)          # safe mode stays ON: 1 s between operations, so the TCP step is slow
    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK], "methods": ["ICMP", "TCP"]}, expect=202)
    job_id = r.json()["id"]
    await live.wait_for(f"/discovery/jobs/{job_id}", lambda j: j["phase"] == "TCP", timeout=20)

    r = await live.post("/safety/stop", {"reason": "operator saw an alarm"}, expect=200)
    assert r.json()["armed"] is False
    sent_at_stop = live.ctx.gate.totals.as_dict()["sent"]
    await live.idle()
    await asyncio.sleep(1.5)
    assert live.ctx.gate.totals.as_dict()["sent"] <= sent_at_stop + 1     # at most the operation already in flight
    job = await live.get(f"/discovery/jobs/{job_id}")
    assert job["status"] in ("CANCELLED", "FAILED")

    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK]}, expect=409)
    assert r.json()["type"].endswith("/safety-stopped")
    env = (await live.client.get("/api/v1/environment")).json()
    assert "STOPPED BY KILL SWITCH" in env["banner"] and env["severity"] == "danger"

    await live.post("/safety/rearm", {"reason": "all clear"}, expect=403)          # operators cannot re-arm
    await live.login("admin")
    await live.post("/safety/rearm", {"reason": "all clear"}, expect=200)
    await live.login("operator")
    r = await live.post("/discovery/jobs", {"targets": [LOOPBACK], "methods": ["ICMP"]}, expect=202)
    await live.idle()
    assert (await live.get(f"/discovery/jobs/{r.json()['id']}"))["status"] == "COMPLETED"


async def test_kill_switch_survives_a_restart(tmp_path):
    import httpx

    from app.main import create_app
    from tests.live.conftest import LiveHarness, live_settings

    for round_ in (1, 2):
        app = create_app(live_settings(tmp_path / "restart.db"))
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
                h = await LiveHarness(app, c).login("operator")
                if round_ == 1:
                    await h.post("/safety/stop", {"reason": "before restart"}, expect=200)
                else:
                    assert (await h.get("/safety"))["armed"] is False
                    assert app.state.ctx.gate.armed is False


async def test_several_ranges_can_be_added_back_to_back(live):
    """Regression: zone ids were built from the first 8 characters of a time-ordered id, which repeat for about a
    minute, so a second range added within that minute failed with 500."""
    for cidr in ("127.0.0.1/32", "127.0.0.2/32", "127.0.0.3/32"):
        await add_scope(live, cidr)
    assert (await live.client.get("/api/v1/environment")).json()["scope"] == ["127.0.0.1/32", "127.0.0.2/32",
                                                                              "127.0.0.3/32"]
