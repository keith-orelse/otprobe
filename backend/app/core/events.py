"""SSE hub. Services stage events on the DB session; they are published only after commit."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass
from typing import Any, AsyncIterator

from sqlalchemy import event as sa_event
from sqlalchemy.orm import Session, sessionmaker

from app.core.clock import utcnow
from app.core.correlation import get_correlation_id

_PENDING = "otprobe_pending_events"


@dataclass(frozen=True)
class Event:
    id: int
    type: str
    ts: str
    correlation_id: str | None
    entity: dict[str, str | None]
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type, "ts": self.ts, "correlationId": self.correlation_id,
                "entity": self.entity, "data": self.data}

    @property
    def topic(self) -> str:
        return self.type.split(".", 1)[0]


class EventHub:
    def __init__(self, buffer_size: int = 1000, queue_size: int = 1000) -> None:
        self._seq = 0
        self._buffer: deque[Event] = deque(maxlen=buffer_size)
        self._subscribers: set[asyncio.Queue[Event]] = set()
        self._queue_size = queue_size

    def publish(self, type_: str, entity_kind: str, entity_id: str | None, data: dict[str, Any] | None = None,
                correlation_id: str | None = None) -> Event:
        self._seq += 1
        evt = Event(self._seq, type_, utcnow().isoformat(), correlation_id,
                    {"kind": entity_kind, "id": entity_id}, data or {})
        self._buffer.append(evt)
        for q in list(self._subscribers):
            try:
                q.put_nowait(evt)
            except asyncio.QueueFull:
                pass  # slow consumer: it can resync via Last-Event-ID / REST
        return evt

    def subscribe(self, last_event_id: int | None = None) -> tuple[asyncio.Queue[Event], list[Event]]:
        q: asyncio.Queue[Event] = asyncio.Queue(self._queue_size)
        self._subscribers.add(q)
        backlog = [e for e in self._buffer if last_event_id is not None and e.id > last_event_id]
        return q, backlog

    def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        self._subscribers.discard(q)

    async def stream(self, topics: set[str] | None, last_event_id: int | None = None) -> AsyncIterator[Event]:
        q, backlog = self.subscribe(last_event_id)
        try:
            for e in backlog:
                if _matches(e, topics):
                    yield e
            while True:
                e = await q.get()
                if _matches(e, topics):
                    yield e
        finally:
            self.unsubscribe(q)


def _matches(e: Event, topics: set[str] | None) -> bool:
    return not topics or e.topic in topics


def normalize_topics(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    return {t.strip().rstrip("s") if t.strip() != "discovery" else "discovery" for t in raw.split(",") if t.strip()}


def stage(session: Session, type_: str, entity_kind: str, entity_id: str | None,
          data: dict[str, Any] | None = None) -> None:
    session.info.setdefault(_PENDING, []).append((type_, entity_kind, entity_id, data or {}, get_correlation_id()))


def install(factory: sessionmaker, hub: EventHub) -> None:
    @sa_event.listens_for(factory, "after_commit")
    def _flush(session: Session) -> None:
        for type_, kind, ident, data, cid in session.info.pop(_PENDING, []):
            hub.publish(type_, kind, ident, data, cid)

    @sa_event.listens_for(factory, "after_rollback")
    def _discard(session: Session) -> None:
        session.info.pop(_PENDING, None)


def sse_payload(e: Event) -> dict[str, str]:
    return {"id": str(e.id), "event": e.type, "data": json.dumps(e.to_dict(), default=str)}
