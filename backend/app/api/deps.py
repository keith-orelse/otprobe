from __future__ import annotations

import jwt
from fastapi import Depends, Query, Request

from app.context import AppContext
from app.core.crypto import sha256_hex
from app.core.errors import ProblemError
from app.core.principal import CurrentAgent, CurrentUser
from app.core.security import decode_jwt
from app.models import Agent, User

ROLES = ("OPERATOR", "APPROVER", "ADMIN")


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx



def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def unauthorized(detail: str, slug: str = "unauthorized") -> ProblemError:
    return ProblemError(401, slug, "Authentication required", detail)


def current_user(request: Request, ctx: AppContext = Depends(get_ctx)) -> CurrentUser:
    token = _bearer(request)
    if not token:
        raise unauthorized("Missing bearer token. Log in via POST /api/v1/auth/login.")
    try:
        claims = decode_jwt(ctx.settings.jwt_secret, token)
    except jwt.PyJWTError as exc:
        raise unauthorized(f"Invalid token: {exc}", "invalid-token") from None
    with ctx.db.session() as s:
        user = s.get(User, claims["sub"])
        if user is None or not user.active:
            raise unauthorized("User no longer exists or is disabled", "invalid-token")
        cu = CurrentUser(user.id, user.username, user.display_name, user.role)
    request.state.principal = cu.username
    return cu


def require_role(*roles: str):
    def dep(user: CurrentUser = Depends(current_user)) -> CurrentUser:
        if user.role not in roles:
            raise ProblemError(403, "forbidden", "Insufficient role",
                               f"Requires role {' or '.join(roles)}; you are {user.role}")
        return user
    return dep


any_user = current_user
operator_or_admin = require_role("OPERATOR", "ADMIN")
approver_or_admin = require_role("APPROVER", "ADMIN")
admin_only = require_role("ADMIN")



def current_agent(agent_id: str, request: Request, ctx: AppContext = Depends(get_ctx)) -> CurrentAgent:
    token = _bearer(request)
    if not token:
        raise unauthorized("Missing agent credential", "agent-credential-missing")
    with ctx.db.session() as s:
        agent = s.get(Agent, agent_id)
        if agent is None or agent.credential_hash != sha256_hex(token):
            raise ProblemError(401, "agent-credential-invalid", "Agent credential invalid",
                               "Credential does not match this agent")
        if agent.revoked_at is not None:
            raise ProblemError(401, "agent-credential-revoked", "Agent credential revoked",
                               f"Credential for agent {agent_id} was revoked at {agent.revoked_at.isoformat()}")
        request.state.principal = f"agent:{agent.id}"
        return CurrentAgent(agent.id, agent.asset_id)


LimitQ = Query(50, ge=1, le=500)
CursorQ = Query(None)
