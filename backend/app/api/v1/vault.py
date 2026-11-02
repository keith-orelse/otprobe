from fastapi import APIRouter, Depends

from app import schemas
from app.api.deps import any_user, get_ctx
from app.context import AppContext

router = APIRouter(prefix="/vault", tags=["vault"], dependencies=[Depends(any_user)])


@router.get("/profiles", response_model=list[schemas.VaultProfile], summary="Credential profiles (always masked)")
async def profiles(ctx: AppContext = Depends(get_ctx)):
    return [schemas.VaultProfile(name=p.profile, protocol=p.protocol, username=p.username, secret=p.secret,
                                 secret_set=p.secret_set) for p in await ctx.vault.list_profiles()]
