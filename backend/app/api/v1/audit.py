from fastapi import APIRouter, Depends, Query

from app import schemas
from app.api.deps import CursorQ, LimitQ, any_user, get_ctx
from app.context import AppContext
from app.core import audit
from app.services import audit_log

router = APIRouter(prefix="/audit-events", tags=["audit"], dependencies=[Depends(any_user)])


@router.get("", response_model=schemas.Page[schemas.AuditEvent])
async def list_events(limit: int = LimitQ, cursor: str | None = CursorQ, action: str | None = None,
                      entity_id: str | None = Query(None, alias="entityId"),
                      correlation_id: str | None = Query(None, alias="correlationId"), actor: str | None = None,
                      ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return audit_log.list_events(s, limit, cursor, action, entity_id, correlation_id, actor)


@router.get("/verify", summary="Verify the audit hash chain")
async def verify(ctx: AppContext = Depends(get_ctx)) -> dict:
    with ctx.db.session() as s:
        return audit.verify(s)
