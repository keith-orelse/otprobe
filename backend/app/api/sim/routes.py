"""Simulator-facing API (/sim/v1). Stands in for physics: a host's local disk/registry and plant MQTT clients.
NOT part of the product API; never called by the console. Requires X-Sim-Token."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel

from app.core.errors import ProblemError

router = APIRouter(prefix="/sim/v1", tags=["simulator-internal"])


def sim_auth(request: Request, x_sim_token: str | None = Header(None, alias="X-Sim-Token")) -> None:
    if x_sim_token != request.app.state.ctx.settings.sim_service_token:
        raise ProblemError(401, "sim-token-invalid", "Simulator token required")


def _world(request: Request):
    return request.app.state.ctx.extras["world"]


def _host(request: Request, device_id: str):
    d = _world(request).device(device_id)
    if d is None:
        raise ProblemError(404, "not-found", "Simulated host not found", device_id)
    return d


@router.get("/hosts/agent-installs", dependencies=[Depends(sim_auth)])
async def agent_installs(request: Request) -> list[dict[str, Any]]:
    """Which virtual hosts have the agent installed, and is its service set to run."""
    out = []
    for d in _world(request).all_devices():
        files = d.state.get("files", {})
        if not files.get("agent"):
            continue
        svc = next((s for s in d.state.get("services", []) if s["name"] == "OTProbeAgent"), None)
        out.append({"deviceId": d.device_id, "hostname": d.hostname, "ip": d.ip,
                    "serviceState": svc["state"] if svc else "missing", "version": files["agent"]["version"],
                    "online": d.online, "faults": sorted(d.faults)})
    return out


@router.get("/hosts/{device_id}/install-bundle", dependencies=[Depends(sim_auth)])
async def install_bundle(device_id: str, request: Request) -> dict[str, Any]:
    d = _host(request, device_id)
    bundle = d.state.get("files", {}).get("enroll_bundle")
    if not bundle:
        raise ProblemError(404, "not-found", "No enrollment bundle on host")
    return {**bundle, "hostname": d.hostname, "hostFingerprint": f"sha256:{d.mac.replace(':', '').lower()}"}


@router.get("/hosts/{device_id}/local-state", dependencies=[Depends(sim_auth)])
async def local_state(device_id: str, request: Request) -> dict[str, Any]:
    d = _host(request, device_id)
    return {"deviceId": d.device_id, "online": d.online, "faults": sorted(d.faults),
            "identity": dict(d.state.get("files", {}).get("agent_identity") or {})}


class AgentIdentity(BaseModel):
    agentId: str
    credential: str


@router.put("/hosts/{device_id}/agent-identity", dependencies=[Depends(sim_auth)])
async def save_identity(device_id: str, body: AgentIdentity, request: Request) -> dict[str, str]:
    """The agent persisting its credential on its own disk (a real agent would DPAPI-protect this file)."""
    _host(request, device_id)
    _world(request).update_state(device_id, lambda st: st.setdefault("files", {}).update(
        agent_identity={"agentId": body.agentId, "credential": body.credential}))
    return {"status": "saved"}
