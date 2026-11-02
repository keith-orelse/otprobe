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
