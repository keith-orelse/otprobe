"""Credential profile administration. Secrets are write-only: stored encrypted, never returned."""

from __future__ import annotations

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.audit import Actor
from app.core.errors import ProblemError, not_found

PROFILE_NAME = r"^[A-Z0-9][A-Z0-9-]{1,63}$"


def _masked(m) -> schemas.VaultProfile:
    return schemas.VaultProfile(name=m.profile, protocol=m.protocol, username=m.username, secret=m.secret,
                                secret_set=m.secret_set)


async def put_profile(ctx: AppContext, name: str, req: schemas.VaultProfileWrite, actor: Actor) -> schemas.VaultProfile:
    try:
        existing = await ctx.vault.describe(name)
    except KeyError:
        existing = None
    if existing is None and not req.secret:
        raise ProblemError(422, "secret-required", "Secret required", "A new credential profile needs a secret")
    masked = await ctx.vault.store(name, req.protocol, req.username, req.secret, req.params, req.description)
    with ctx.db.session() as s:
        audit.record(s, actor, "CREDENTIAL_PROFILE_CREATED" if existing is None else "CREDENTIAL_PROFILE_UPDATED",
                     "credential_profile", name, {"protocol": req.protocol, "username": req.username,
                                                  "secretChanged": bool(req.secret), "params": req.params})
    return _masked(masked)


async def delete_profile(ctx: AppContext, name: str, actor: Actor) -> None:
    try:
        await ctx.vault.delete(name)
    except KeyError:
        raise not_found("Credential profile", name) from None
    with ctx.db.session() as s:
        audit.record(s, actor, "CREDENTIAL_PROFILE_DELETED", "credential_profile", name, {})
