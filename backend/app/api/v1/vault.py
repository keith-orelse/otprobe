from fastapi import APIRouter, Depends, Path

from app import schemas
from app.api.deps import admin_only, any_user, get_ctx
from app.context import AppContext
from app.core.principal import CurrentUser
from app.services import credentials

router = APIRouter(prefix="/vault", tags=["vault"], dependencies=[Depends(any_user)])
ProfileName = Path(pattern=credentials.PROFILE_NAME, examples=["OT-SNMPV3-RO"])


@router.get("/profiles", response_model=list[schemas.VaultProfile], summary="Credential profiles (always masked)")
async def profiles(ctx: AppContext = Depends(get_ctx)):
    return [schemas.VaultProfile(name=p.profile, protocol=p.protocol, username=p.username, secret=p.secret,
                                 secret_set=p.secret_set) for p in await ctx.vault.list_profiles()]


@router.put("/profiles/{name}", response_model=schemas.VaultProfile,
            summary="Create or update a credential profile (admin). The secret is write-only and never returned")
async def put_profile(req: schemas.VaultProfileWrite, name: str = ProfileName, user: CurrentUser = Depends(admin_only),
                      ctx: AppContext = Depends(get_ctx)):
    return await credentials.put_profile(ctx, name, req, user.actor)


@router.delete("/profiles/{name}", status_code=204, summary="Delete a credential profile (admin)")
async def delete_profile(name: str = ProfileName, user: CurrentUser = Depends(admin_only),
                         ctx: AppContext = Depends(get_ctx)):
    await credentials.delete_profile(ctx, name, user.actor)
