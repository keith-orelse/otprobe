"""Reusable end-to-end flows through the real API."""

from __future__ import annotations

from tests.conftest import Harness

WINDOW_HOURS = 2


async def request_deployment(h: Harness, ip: str, requester: str = "operator", **extra) -> dict:
    await h.login(requester)
    asset = await h.asset_by_ip(ip)
    body = {"assetId": asset["id"], "packageId": "pkg-probe-agent-1.1.0", "purpose": "Deep compliance monitoring",
            **extra}
    r = await h.post("/deployments", body, expect=201)
    return r.json()


async def approve(h: Harness, dep: dict, approver: str = "approver", reason: str | None = None) -> dict:
    await h.login(approver)
    r = await h.post(f"/approvals/{dep['approval']['id']}/approve", {"reason": reason} if reason else None, expect=200)
    return r.json()


async def precheck(h: Harness, dep_id: str, user: str = "operator") -> dict:
    await h.login(user)
    await h.post(f"/deployments/{dep_id}/precheck", expect=202)
    return await h.wait_for(f"/deployments/{dep_id}", lambda d: d["status"] in ("PRECHECK_PASSED", "PRECHECK_FAILED"))


async def deploy(h: Harness, dep_id: str, user: str = "operator", until=("COMPLETED", "FAILED")) -> dict:
    await h.login(user)
    await h.post(f"/deployments/{dep_id}/deploy", expect=202)
    return await h.wait_for(f"/deployments/{dep_id}", lambda d: d["status"] in until, timeout=60)


async def prepared(h: Harness, ip: str = "192.168.20.13") -> None:
    await h.login("operator")
    await h.discover(["192.168.20.0/24"])
    await h.probe(ip)


async def deployed_agent(h: Harness, ip: str = "192.168.20.13") -> tuple[str, str]:
    """Discover, probe, request, approve, precheck, deploy; wait for ONLINE. Returns (asset_id, agent_id)."""
    await prepared(h, ip)
    dep = await request_deployment(h, ip)
    await approve(h, dep)
    await precheck(h, dep["id"])
    done = await deploy(h, dep["id"])
    assert done["status"] == "COMPLETED", (done["failureCode"], done["failureDetail"])
    await h.wait_for(f"/agents/{done['agentId']}", lambda a: a["status"] == "ONLINE")
    await h.login("operator")
    return dep["assetId"], done["agentId"]


async def assess(h: Harness, asset_id: str, until=("EVALUATED", "TIMED_OUT", "FAILED"), timeout: float = 30) -> dict:
    r = await h.post(f"/assets/{asset_id}/assessments", expect=202)
    return await h.wait_for(f"/assessments/{r.json()['id']}", lambda d: d["status"] in until, timeout=timeout)


async def set_config(h: Harness, device: str, control: str, value: str) -> None:
    user = h.client.headers.get("Authorization")
    await h.login("admin")
    await h.post(f"/demo/devices/{device}/config", {"control": control, "value": value}, expect=200)
    h.client.headers["Authorization"] = user


async def publish(h: Harness, client_id: str, topic: str, payload: dict, expect: int = 202) -> None:
    from tests.conftest import SIM_HEADERS
    r = await h.client.post("/sim/v1/mqtt/publish", json={"clientId": client_id, "topic": topic, "payload": payload},
                            headers=SIM_HEADERS)
    assert r.status_code == expect, r.text


async def as_admin(h: Harness, method: str, path: str, json=None, expect: int | None = 200):
    prev = h.client.headers.get("Authorization")
    await h.login("admin")
    try:
        if method == "post":
            return await h.post(path, json, expect=expect)
        return await h.get(path)
    finally:
        h.client.headers["Authorization"] = prev


async def fault(h: Harness, device: str, name: str, enabled: bool = True, params: dict | None = None) -> None:
    await as_admin(h, "post", f"/demo/devices/{device}/faults",
                   {"fault": name, "enabled": enabled, "params": params or {}})


async def remove_agent(h: Harness, agent_id: str, until=("COMPLETED", "FAILED")) -> dict:
    await h.login("operator")
    rem = (await h.post(f"/agents/{agent_id}/removals", {"purpose": "Decommission POC agent"}, expect=201)).json()
    await h.login("approver")
    await h.post(f"/approvals/{rem['approval']['id']}/approve", expect=200)
    await h.login("operator")
    await h.post(f"/removals/{rem['id']}/start", expect=202)
    return await h.wait_for(f"/removals/{rem['id']}", lambda r: r["status"] in until, timeout=30)
