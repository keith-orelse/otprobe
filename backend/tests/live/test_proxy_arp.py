"""Proxy ARP (Wi-Fi client isolation, firewalls): one router MAC answers for several IPs. That MAC must never become
a device identity, or inventory merges unrelated devices (found on a real office Wi-Fi, see DECISIONS.md L2-10)."""

from __future__ import annotations

import pytest

from app.adapters.real.net import neighbors
from tests.live.test_live_loopback import add_scope, safe_mode

pytestmark = pytest.mark.live
ROUTER = "A8:5B:F7:CC:12:A0"
MACOS_ARP = """? (172.31.98.1) at a8:5b:f7:cc:12:a0 on en0 ifscope [ethernet]
? (172.31.98.77) at aa:33:e4:4c:ce:62 on en0 ifscope [ethernet]
? (172.31.99.166) at a8:5b:f7:cc:12:a0 on en0 ifscope [ethernet]
? (172.31.99.183) at a8:5b:f7:cc:12:a0 on en0 ifscope [ethernet]
? (172.31.99.200) at (incomplete) on en0 ifscope [ethernet]
"""


def test_shared_macs_are_detected_in_a_real_macos_table():
    table = neighbors._parse_bsd(MACOS_ARP)
    assert table["172.31.98.77"] == "AA:33:E4:4C:CE:62" and "172.31.99.200" not in table
    assert neighbors.shared_macs(table) == {ROUTER: 3}


@pytest.fixture
def fake_table(monkeypatch):
    table: dict[str, str] = {}

    async def read_table():
        return dict(table)

    monkeypatch.setattr(neighbors, "read_table", read_table)
    return table


async def test_proxy_arp_mac_is_never_used_as_identity(live, fake_table):
    await add_scope(live, "127.0.0.0/30")
    await safe_mode(live, False)
    fake_table.update({"127.0.0.1": ROUTER, "127.0.0.2": ROUTER, "127.0.0.3": "02:11:22:33:44:55"})
    r = await live.post("/discovery/jobs", {"targets": ["127.0.0.0/30"], "methods": ["ARP"]}, expect=202)
    await live.idle()
    assert (await live.get(f"/discovery/jobs/{r.json()['id']}"))["status"] == "COMPLETED"

    assets = {a["ip"]: a for a in await live.assets()}
    assert set(assets) == {"127.0.0.1", "127.0.0.2", "127.0.0.3"}          # two proxied devices stay separate
    assert assets["127.0.0.1"]["mac"] is None and assets["127.0.0.2"]["mac"] is None
    assert assets["127.0.0.3"]["mac"] == "02:11:22:33:44:55"
    detail = await live.get(f"/assets/{assets['127.0.0.2']['id']}")
    via = next(f for g in detail["groups"].values() for f in g if f["path"] == "network.arp_via")
    assert via["value"] == ROUTER

    # Next scan: the router now answers for a third address. Nothing moves, nothing conflicts.
    fake_table["127.0.0.3"] = ROUTER
    r = await live.post("/discovery/jobs", {"targets": ["127.0.0.0/30"], "methods": ["ARP"]}, expect=202)
    await live.idle()
    for action in ("ASSET_IP_CHANGED", "IP_MAC_CONFLICT"):
        assert (await live.get("/audit-events", params={"action": action}))["items"] == []


async def test_probe_explains_proxy_arp(live, fake_table):
    await add_scope(live)
    await safe_mode(live, False)
    fake_table.update({"127.0.0.1": ROUTER, "10.0.0.1": ROUTER})
    r = await live.post("/discovery/jobs", {"targets": ["127.0.0.1/32"], "methods": ["ICMP", "ARP"]}, expect=202)
    await live.idle()
    asset = await live.asset_by_ip("127.0.0.1")
    r = await live.post(f"/assets/{asset['id']}/probes", expect=202)
    await live.idle()
    probe = await live.get(f"/probes/{r.json()['id']}")
    arp = next(s for s in probe["steps"] if s["name"] == "ARP")
    assert arp["status"] == "OK" and "proxy ARP" in arp["detail"] and "expected" not in arp["detail"]
    icmp = next(r for r in probe["results"] if r["protocol"] == "ICMP")
    assert icmp["latencyMs"] > 0
