"""RFC 7807 problem responses."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.correlation import correlation_id_var

PROBLEM_BASE = "https://otprobe.local/problems/"
log = logging.getLogger("otprobe.errors")


class ProblemError(Exception):
    def __init__(self, status: int, slug: str, title: str, detail: str | None = None,
                 errors: list[dict[str, Any]] | None = None) -> None:
        super().__init__(detail or title)
        self.status, self.slug, self.title, self.detail, self.errors = status, slug, title, detail, errors


def not_found(kind: str, ident: str) -> ProblemError:
    return ProblemError(404, "not-found", f"{kind} not found", f"{kind} {ident} does not exist")


def problem_response(status: int, slug: str, title: str, detail: str | None = None,
                     errors: list[dict[str, Any]] | None = None, instance: str | None = None) -> JSONResponse:
    body: dict[str, Any] = {"type": PROBLEM_BASE + slug, "title": title, "status": status}
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    if errors:
        body["errors"] = errors
    cid = correlation_id_var.get()
    if cid:
        body["correlationId"] = cid
    return JSONResponse(body, status_code=status, media_type="application/problem+json")


def install_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem(request: Request, exc: ProblemError):
        return problem_response(exc.status, exc.slug, exc.title, exc.detail, exc.errors, request.url.path)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return problem_response(422, "validation-error", "Request validation failed", None, errors, request.url.path)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException):
        slug = "not-found" if exc.status_code == 404 else "http-error"
        return problem_response(exc.status_code, slug, str(exc.detail), None, None, request.url.path)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.exception("unhandled error")
        return problem_response(500, "internal-error", "Internal server error", None, None, request.url.path)
