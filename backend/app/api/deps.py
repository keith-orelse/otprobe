from __future__ import annotations

from fastapi import Query, Request

from app.context import AppContext
from app.core.audit import ANONYMOUS, Actor


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_actor(request: Request) -> Actor:
    # Phase 3 replaces this with the authenticated user (JWT) and RBAC checks.
    return ANONYMOUS


LimitQ = Query(50, ge=1, le=500)
CursorQ = Query(None)
