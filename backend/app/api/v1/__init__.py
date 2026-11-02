from fastapi import APIRouter

from app.api.v1 import (
    agents,
    assets,
    audit,
    auth,
    dashboard,
    demo,
    deployments,
    discovery,
    events,
    probes,
    topology,
    vault,
)

router = APIRouter(prefix="/api/v1")
for module in (auth, dashboard, discovery, assets, probes, deployments, agents, topology, vault, audit, demo, events):
    router.include_router(module.router)
