from __future__ import annotations

import re
from contextvars import ContextVar

from app.core.ids import new_id

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
_VALID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def get_correlation_id() -> str:
    cid = correlation_id_var.get()
    if cid is None:
        cid = new_id()
        correlation_id_var.set(cid)
    return cid


class CorrelationMiddleware:
    """Pure ASGI (safe for SSE streaming). Accepts or generates X-Correlation-ID, echoes it, and stamps
    every response with X-OTProbe-Environment: LIVE or SIMULATED."""

    def __init__(self, app, environment: str = "SIMULATED") -> None:
        self.app, self.environment = app, environment.encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-correlation-id", b"").decode("latin-1")
        cid = incoming if _VALID.match(incoming or "") else new_id()
        token = correlation_id_var.set(cid)

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-correlation-id", cid.encode()))
                headers.append((b"x-otprobe-environment", self.environment))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            correlation_id_var.reset(token)
