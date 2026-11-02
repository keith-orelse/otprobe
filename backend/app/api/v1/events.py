from fastapi import APIRouter, Depends, Header, Query
from sse_starlette.sse import EventSourceResponse

from app.api.deps import get_ctx
from app.context import AppContext
from app.core.events import normalize_topics, sse_payload

router = APIRouter(prefix="/events", tags=["events"])


@router.get("/stream", summary="Server-Sent Events (stream tickets arrive with auth in Phase 3)")
async def stream(topics: str | None = Query(None, examples=["discovery,assets,probes"]),
                 last_event_id: str | None = Header(None, alias="Last-Event-ID"),
                 ctx: AppContext = Depends(get_ctx)):
    last = int(last_event_id) if last_event_id and last_event_id.isdigit() else None

    async def gen():
        async for e in ctx.hub.stream(normalize_topics(topics), last):
            yield sse_payload(e)

    return EventSourceResponse(gen(), ping=15)
