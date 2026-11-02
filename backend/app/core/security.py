"""Passwords (bcrypt), user JWTs, and opaque random tokens stored as SHA-256 hashes."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from datetime import timedelta

import bcrypt
import jwt

from app.core.clock import utcnow
from app.core.crypto import sha256_hex

JWT_TTL = timedelta(hours=8)
STREAM_TICKET_TTL_SEC = 30


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def issue_jwt(secret: str, user_id: str, username: str, role: str) -> tuple[str, int]:
    now = utcnow()
    claims = {"sub": user_id, "usr": username, "role": role, "iat": int(now.timestamp()),
              "exp": int((now + JWT_TTL).timestamp()), "iss": "otprobe"}
    return jwt.encode(claims, secret, algorithm="HS256"), int(JWT_TTL.total_seconds())


def decode_jwt(secret: str, token: str) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], issuer="otprobe")


def opaque_token(prefix: str) -> tuple[str, str]:
    """Returns (plaintext, sha256 hash). Only the hash is ever persisted."""
    token = f"{prefix}_{secrets.token_urlsafe(32)}"
    return token, sha256_hex(token)


@dataclass
class _Ticket:
    user_id: str
    expires: float


class StreamTickets:
    """Single-use, 30 s tickets for EventSource (which cannot send Authorization headers)."""

    def __init__(self) -> None:
        self._tickets: dict[str, _Ticket] = {}

    def issue(self, user_id: str) -> str:
        now = time.monotonic()
        self._tickets = {k: v for k, v in self._tickets.items() if v.expires > now}
        ticket = f"stk_{secrets.token_urlsafe(24)}"
        self._tickets[ticket] = _Ticket(user_id, now + STREAM_TICKET_TTL_SEC)
        return ticket

    def redeem(self, ticket: str) -> str | None:
        t = self._tickets.pop(ticket, None)
        return t.user_id if t and t.expires > time.monotonic() else None
