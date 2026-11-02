"""Cross-cutting API conventions: RFC 7807, correlation IDs, idempotency, pagination, safety guards."""

import pytest

pytestmark = pytest.mark.acceptance


async def test_correlation_and_environment_headers(h):
    r = await h.client.get("/api/v1/health", headers={"X-Correlation-ID": "demo-123"})
    assert r.headers["x-correlation-id"] == "demo-123"
    assert r.headers["x-otprobe-environment"] == "SIMULATED"
    assert (await h.client.get("/api/v1/health")).headers["x-correlation-id"]


async def test_problem_details(h):
    r = await h.client.get("/api/v1/assets/nope", headers={"X-Correlation-ID": "cid-404"})
    assert r.status_code == 404 and r.headers["content-type"] == "application/problem+json"
    body = r.json()
    assert body["type"].endswith("/not-found") and body["correlationId"] == "cid-404"
    r = await h.client.post("/api/v1/discovery/jobs", json={"targets": []}, headers={"Idempotency-Key": "k"})
    assert r.status_code == 422 and r.json()["errors"]


async def test_targets_outside_simulated_network_rejected(h):
    for target, slug in (("10.0.0.0/8", "target-not-in-simulated-network"),
                         ("192.168.35.0/24", "zone-not-scannable"), ("not-a-cidr", "invalid-target")):
        r = await h.post("/discovery/jobs", {"targets": [target]})
        assert r.status_code == 422 and r.json()["type"].endswith(slug), r.text


async def test_idempotency(h):
    r = await h.client.post("/api/v1/discovery/jobs", json={"targets": ["192.168.20.0/24"]})
    assert r.status_code == 400 and r.json()["type"].endswith("idempotency-key-required")
    first = await h.post("/discovery/jobs", {"targets": ["192.168.20.0/24"]}, key="same-key", expect=202)
    replay = await h.post("/discovery/jobs", {"targets": ["192.168.20.0/24"]}, key="same-key", expect=202)
    assert replay.json()["id"] == first.json()["id"] and replay.headers["idempotent-replayed"] == "true"
    reused = await h.post("/discovery/jobs", {"targets": ["192.168.10.0/24"]}, key="same-key")
    assert reused.status_code == 422 and reused.json()["type"].endswith("idempotency-key-reused")
    await h.idle()
    jobs = await h.get("/discovery/jobs")
    assert jobs["total"] == 1


async def test_invalid_transition_is_409(discovered):
    h = discovered
    job = (await h.get("/discovery/jobs"))["items"][0]
    r = await h.post(f"/discovery/jobs/{job['id']}/cancel")
    assert r.status_code == 409 and "cannot go from COMPLETED to CANCELLED" in r.json()["detail"]


async def test_pagination(discovered):
    h = discovered
    page1 = await h.get("/assets", params={"limit": 4})
    assert page1["total"] == 9 and len(page1["items"]) == 4 and page1["nextCursor"]
    ips = [a["ip"] for a in page1["items"]]
    page2 = await h.get("/assets", params={"limit": 4, "cursor": page1["nextCursor"]})
    page3 = await h.get("/assets", params={"limit": 4, "cursor": page2["nextCursor"]})
    ips += [a["ip"] for a in page2["items"]] + [a["ip"] for a in page3["items"]]
    assert page3["nextCursor"] is None and len(ips) == 9
    assert ips[:2] == ["192.168.10.10", "192.168.10.11"] and ips[-1] == "192.168.20.149"


async def test_audit_chain_and_correlation(discovered):
    h = discovered
    await h.client.post("/api/v1/assets/" + (await h.asset_by_ip("192.168.20.1"))["id"] + "/probes",
                            headers={"Idempotency-Key": "p", "X-Correlation-ID": "corr-probe-1"})
    await h.idle()
    events = (await h.get("/audit-events", params={"correlationId": "corr-probe-1", "limit": 100}))["items"]
    actions = {e["action"] for e in events}
    assert {"PROBE_REQUESTED", "PROBE_STARTED", "CREDENTIAL_RETRIEVED", "ASSET_CLASSIFIED",
            "PROBE_COMPLETED"} <= actions
    assert (await h.get("/audit-events/verify"))["valid"] is True


async def test_vault_masked_and_topology(discovered):
    h = discovered
    profiles = await h.get("/vault/profiles")
    assert all(p["secret"] == "••••••••" for p in profiles)
    await h.probe("192.168.20.1")
    topo = await h.get("/topology")
    kinds = {n["kind"] for n in topo["nodes"]}
    assert kinds == {"zone", "server", "conduit", "asset"}
    assert any(e["source"] == "fw-conduit-01" for e in topo["edges"])
    assert sum(1 for e in topo["edges"] if e["kind"] == "LINK" and e["source"] != "fw-conduit-01"
               and e["protocol"] != "management") == 8


async def test_ui_decisions_are_server_computed(discovered):
    """The console renders these; it must not decide them itself."""
    h = discovered
    methods = await h.get("/discovery/methods")
    assert [m["method"] for m in methods] == ["ARP", "ICMP", "SNMP"] and all(m["label"] for m in methods)
    job = (await h.get("/discovery/jobs"))["items"][0]
    assert job["actions"]["cancel"] == {"enabled": False, "reason": "Job is COMPLETED"}
    ews = await h.asset_by_ip("192.168.20.13")
    await h.post(f"/assets/{ews['id']}/probes", expect=202)
    busy = await h.get(f"/assets/{ews['id']}")
    assert busy["agentless"] == {"enabled": False, "reason": "An agentless probe is already running"}
    await h.idle()
    assert (await h.get(f"/assets/{ews['id']}"))["agentless"]["enabled"] is True
    await h.probe("192.168.20.1")
    topo = await h.get("/topology")
    zones = [n for n in topo["nodes"] if n["kind"] == "zone"]
    assert [z["order"] for z in zones] == list(range(len(zones)))
    tiers = {n["ip"]: n["tier"] for n in topo["nodes"] if n["kind"] == "asset"}
    assert tiers["192.168.20.1"] == "infrastructure" and tiers["192.168.20.13"] == "host"
