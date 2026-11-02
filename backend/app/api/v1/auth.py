from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import current_user, get_ctx
from app.context import AppContext
from app.core.principal import CurrentUser
from app.core.security import STREAM_TICKET_TTL_SEC
from app.services import auth

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=schemas.LoginResponse, summary="Log in with a seeded demo user")
async def login(req: schemas.LoginRequest, ctx: AppContext = Depends(get_ctx)):
    return auth.login(ctx, req)


@router.get("/me", response_model=schemas.User)
async def me(user: CurrentUser = Depends(current_user)):
    return schemas.User(id=user.id, username=user.username, display_name=user.display_name, role=user.role,
                        permissions=user.permissions)


@router.post("/stream-ticket", response_model=schemas.StreamTicket,
             summary="Single-use 30 s ticket for the SSE stream (EventSource cannot send headers)")
async def stream_ticket(user: CurrentUser = Depends(current_user), ctx: AppContext = Depends(get_ctx)):
    return schemas.StreamTicket(ticket=ctx.tickets.issue(user.id), expires_in_sec=STREAM_TICKET_TTL_SEC)
