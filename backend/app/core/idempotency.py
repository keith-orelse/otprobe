"""Idempotency-Key handling for action POST endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable

from fastapi import Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.clock import utcnow
from app.core.crypto import sha256_hex
from app.core.errors import ProblemError
from app.models import IdempotencyKey

TTL = timedelta(hours=24)

# An action returns (response body, optional callable to run after commit, e.g. launching a job).
Action = Callable[[Session], "tuple[Any, Callable[[], None] | None]"]


@dataclass(frozen=True)
class Idempotency:
    key: str
    principal: str
    method: str
    path: str
    request_hash: str

    def lookup(self, session: Session) -> JSONResponse | None:
        row = session.get(IdempotencyKey, (self.principal, self.key))
        if row is None:
            return None
        if row.created_at < utcnow() - TTL:
            session.delete(row)
            session.flush()
            return None
        if row.request_hash != self.request_hash or row.path != self.path or row.method != self.method:
            raise ProblemError(422, "idempotency-key-reused", "Idempotency key reused with a different request",
                               f"Key '{self.key}' was already used for {row.method} {row.path} with another body")
        return JSONResponse(row.response, status_code=row.status_code, headers={"Idempotent-Replayed": "true"})

    def save(self, session: Session, status_code: int, body: Any) -> None:
        session.add(IdempotencyKey(principal=self.principal, key=self.key, method=self.method, path=self.path,
                                   request_hash=self.request_hash, status_code=status_code, response=body))

    def execute(self, db, status_code: int, action: Action) -> JSONResponse:
        after = None
        with db.session() as s:
            replay = self.lookup(s)
            if replay is not None:
                return replay
            body, after = action(s)
            self.save(s, status_code, body)
        if after is not None:
            after()
        return JSONResponse(body, status_code=status_code)


async def require_idempotency(request: Request,
                              idempotency_key: str | None = Header(None, alias="Idempotency-Key")) -> Idempotency:
    if not idempotency_key or len(idempotency_key) > 128:
        raise ProblemError(400, "idempotency-key-required", "Idempotency-Key header required",
                           "Action endpoints require an Idempotency-Key header (max 128 chars)")
    body = await request.body()
    principal = getattr(request.state, "principal", "anonymous")
    return Idempotency(idempotency_key, principal, request.method, request.url.path, sha256_hex(body))
