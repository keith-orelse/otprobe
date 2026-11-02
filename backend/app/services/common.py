from __future__ import annotations

import base64
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.errors import ProblemError


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"o:{offset}".encode()).decode()


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        assert raw.startswith("o:")
        return max(0, int(raw[2:]))
    except Exception:  # noqa: BLE001
        raise ProblemError(400, "invalid-cursor", "Invalid pagination cursor") from None


def paginate(session: Session, stmt: Select, limit: int, cursor: str | None) -> tuple[list[Any], str | None, int]:
    """Opaque cursor (offset-encoded in the POC; can become keyset without an API change)."""
    offset = decode_cursor(cursor)
    total = session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = list(session.scalars(stmt.limit(limit).offset(offset)))
    nxt = encode_cursor(offset + limit) if offset + limit < total else None
    return rows, nxt, total
