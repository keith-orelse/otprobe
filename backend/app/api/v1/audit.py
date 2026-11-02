from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import CursorQ, LimitQ, get_ctx
from app.context import AppContext
from app.core import audit
from app.services import audit_log

router = APIRouter(prefix="/audit-events", tags=["audit"])


@router.get("", response_model=schemas.Page[schemas.AuditEvent])
async def list_events(limit: int = LimitQ, cursor: str | None = CursorQ, action: str | None = None,
                      entity_id: str | None = None, correlation_id: str | None = None, actor: str | None = None,
                      ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return audit_log.list_events(s, limit, cursor, action, entity_id, correlation_id, actor)


@router.get("/verify", summary="Verify the audit hash chain")
async def verify(ctx: AppContext = Depends(get_ctx)) -> dict:
    with ctx.db.session() as s:
        return audit.verify(s)
