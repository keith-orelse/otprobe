from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import CursorQ, LimitQ, any_user, get_ctx
from app.context import AppContext
from app.services import assets

router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[Depends(any_user)])


@router.get("", response_model=schemas.Page[schemas.AssetSummary])
async def list_assets(limit: int = LimitQ, cursor: str | None = CursorQ, q: str | None = None,
                      status: str | None = None, level: str | None = None, sort: str | None = "ip",
                      ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assets.list_assets(s, limit, cursor, q, status, level, sort)


@router.get("/{asset_id}", response_model=schemas.AssetDetail)
async def get_asset(asset_id: str, ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assets.get_asset(ctx, s, ctx.registry, asset_id)


@router.get("/{asset_id}/fields", response_model=list[schemas.FieldValue],
            summary="All field values with provenance (every source, not just the effective one)")
async def fields(asset_id: str, stage: str | None = None, ctx: AppContext = Depends(get_ctx)):
    with ctx.db.session() as s:
        return assets.list_fields(s, ctx.registry, asset_id, stage)
