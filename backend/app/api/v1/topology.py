from fastapi import APIRouter, Depends
from sqlalchemy import select

from app import schemas
from app.api.deps import get_ctx
from app.context import AppContext
from app.models import Zone
from app.services import topology

router = APIRouter(tags=["topology"])


@router.get("/topology", response_model=schemas.Topology)
async def get_topology(ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return topology.build(s)


@router.get("/zones", response_model=list[schemas.Zone])
async def zones(ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return [schemas.Zone.model_validate(z) for z in s.scalars(select(Zone).order_by(Zone.cidr))]
