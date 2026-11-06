"""Account bootstrap for the live server: the three role accounts, without demo passwords. Idempotent."""

from __future__ import annotations

import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models import User

LIVE_USERS = [
    ("admin", "Administrator", "ADMIN", "admin_password"),
    ("operator", "Operator", "OPERATOR", "operator_password"),
    ("approver", "Approver", "APPROVER", "approver_password"),
]


def seed_live_users(session: Session, settings) -> list[tuple[str, str]]:
    """Live mode: no demo passwords. Each account takes OTPROBE_<ROLE>_PASSWORD or a generated password, which is
    returned once (the caller logs it) and never stored in clear. Existing accounts are left alone."""
    generated = []
    for username, display, role, setting in LIVE_USERS:
        if session.scalar(select(User).where(User.username == username)) is not None:
            continue
        password = getattr(settings, setting)
        if not password:
            password = secrets.token_urlsafe(12)
            generated.append((username, password))
        elif len(password) < 12:
            raise ValueError(f"OTPROBE_{username.upper()}_PASSWORD must be at least 12 characters")
        session.add(User(username=username, display_name=display, role=role, password_hash=hash_password(password)))
    session.flush()
    return generated
