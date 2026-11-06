from fastapi import APIRouter

from app.api.v1 import (
    agents,
    assessments,
    assets,
    audit,
    auth,
    dashboard,
    deployments,
    discovery,
    events,
    probes,
    safety,
    telemetry,
    topology,
    vault,
)

router = APIRouter(prefix="/api/v1")
for module in (auth, dashboard, discovery, assets, probes, deployments, agents, assessments, telemetry, topology,
               vault, audit, events, safety):
    router.include_router(module.router)
