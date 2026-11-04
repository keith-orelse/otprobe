from fastapi import APIRouter, Depends
from sqlalchemy import text

from app import schemas
from app.api.deps import any_user, get_ctx
from app.context import AppContext
from app.services import dashboard

router = APIRouter(tags=["topology"])


@router.get("/health")
async def health(ctx: AppContext = Depends(get_ctx)) -> dict:
    with ctx.db.session() as s:
        s.execute(text("select 1"))
    return {"status": "ok", "environment": "SIMULATED", "db": "ok",
            "adapters": {"mode": ctx.registry.mode, "overrides": ctx.registry.overrides}}


@router.get("/nav/counts", response_model=schemas.NavCounts,
            summary="Counters for the console navigation (pending approvals, open findings, agents needing attention)")
async def nav_counts(ctx: AppContext = Depends(get_ctx), user=Depends(any_user)):
    with ctx.db.session() as s:
        return dashboard.nav_counts(ctx, s)


@router.get("/dashboard/summary", response_model=schemas.DashboardSummary)
async def summary(ctx: AppContext = Depends(get_ctx), user=Depends(any_user)):
    with ctx.db.session() as s:
        return dashboard.summary(ctx, s, ctx.registry)
