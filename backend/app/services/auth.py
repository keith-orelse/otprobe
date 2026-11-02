from __future__ import annotations

from sqlalchemy import select

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.audit import Actor
from app.core.errors import ProblemError
from app.core.principal import CurrentUser
from app.core.security import issue_jwt, verify_password
from app.models import User


def login(ctx: AppContext, req: schemas.LoginRequest) -> schemas.LoginResponse:
    with ctx.db.session() as s:
        user = s.scalar(select(User).where(User.username == req.username))
        if user is None or not user.active or not verify_password(req.password, user.password_hash):
            audit.record(s, Actor("USER", req.username[:64]), "AUTH_LOGIN_FAILED", "user", None,
                         {"username": req.username[:64]})
            failed = True
        else:
            audit.record(s, Actor("USER", user.username, user.id), "AUTH_LOGIN", "user", user.id, {"role": user.role})
            token, ttl = issue_jwt(ctx.settings.jwt_secret, user.id, user.username, user.role)
            failed = False
            principal = CurrentUser(user.id, user.username, user.display_name, user.role)
            out = schemas.LoginResponse(access_token=token, expires_in_sec=ttl,
                                        user=schemas.User(id=user.id, username=user.username,
                                                          display_name=user.display_name, role=user.role,
                                                          permissions=principal.permissions))
    if failed:  # audit committed above, then reject
        raise ProblemError(401, "invalid-credentials", "Invalid username or password")
    return out
