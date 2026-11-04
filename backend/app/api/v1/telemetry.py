from fastapi import APIRouter, Depends, Query

from app import schemas
from app.api.deps import any_user, get_ctx
from app.context import AppContext
from app.services import telemetry

router = APIRouter(prefix="/telemetry", tags=["telemetry"], dependencies=[Depends(any_user)])


@router.get("/topics", response_model=list[schemas.TelemetryTopic],
            summary="MQTT topics with last value, publishing client, asset and recent values")
async def topics(ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return telemetry.topics(s)


@router.get("/messages", response_model=list[schemas.TelemetryRecord])
async def messages(topic: str | None = None, limit: int = Query(100, ge=1, le=1000),
                   ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return telemetry.messages(s, topic, limit)
