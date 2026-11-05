"""Live-network safety: scan scope and the kill switch / safe mode state (docs/SAFETY_AND_SCOPE.md)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.clock import utcnow
from app.core.ids import new_id
from app.models.base import Base, UtcDateTime


class ScanScope(Base):
    __tablename__ = "scan_scopes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(8))                  # INCLUDE | EXCLUDE
    profile: Mapped[str] = mapped_column(String(16), default="OT_SENSITIVE")   # IT | OT_SENSITIVE
    level: Mapped[str] = mapped_column(String(8), default="?")    # default Purdue level for assets found here
    label: Mapped[str] = mapped_column(String(128), default="")
    authorization: Mapped[str] = mapped_column(Text, default="")  # who approved scanning this range
    plugins: Mapped[list[str]] = mapped_column(JSON, default=list)
    zone_id: Mapped[str | None] = mapped_column(String(64))       # INCLUDE entries own a zone row
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    disabled_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class SafetyState(Base):
    """Single row (id='global'). Survives restarts, so a stopped system stays stopped."""

    __tablename__ = "safety_state"
    id: Mapped[str] = mapped_column(String(16), primary_key=True, default="global")
    armed: Mapped[bool] = mapped_column(Boolean, default=True)
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    changed_by: Mapped[str | None] = mapped_column(String(64))
    changed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    reason: Mapped[str] = mapped_column(Text, default="")


class AgentBuild(Base):
    """A verified agent binary from a signed release (docs/GO_AGENT.md §1). Only builds whose release signature and
    file hash both verified are ever stored."""

    __tablename__ = "agent_builds"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)          # "<version>/<build id>"
    version: Mapped[str] = mapped_column(String(32), index=True)
    build_id: Mapped[str] = mapped_column(String(48))                      # windows-amd64, linux-legacy-386, ...
    os: Mapped[str] = mapped_column(String(16))
    arch: Mapped[str] = mapped_column(String(16))
    variant: Mapped[str] = mapped_column(String(16))                       # modern | legacy
    file: Mapped[str] = mapped_column(String(128))
    path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    min_os: Mapped[str] = mapped_column(String(64), default="")
    registered_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
