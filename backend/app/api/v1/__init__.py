from fastapi import APIRouter

from app.api.v1 import assets, audit, dashboard, discovery, events, probes, topology, vault

router = APIRouter(prefix="/api/v1")
for module in (dashboard, discovery, assets, probes, topology, vault, audit, events):
    router.include_router(module.router)
