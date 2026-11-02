"""In-process MQTT broker simulation (no Mosquitto). Topic filters support + and #."""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable

from app.core.clock import utcnow


@dataclass(frozen=True)
class BrokerMessage:
    topic: str
    payload: Any
    client_id: str
    received_at: datetime


def topic_matches(topic_filter: str, topic: str) -> bool:
    f_parts, t_parts = topic_filter.split("/"), topic.split("/")
    for i, f in enumerate(f_parts):
        if f == "#":
            return True
        if i >= len(t_parts) or (f != "+" and f != t_parts[i]):
            return False
    return len(f_parts) == len(t_parts)


Handler = Callable[[BrokerMessage], Awaitable[None]]


class Broker:
    host_ip = "192.168.20.149"   # logically hosted on historian-01:8883
    port = 8883

    def __init__(self) -> None:
        self._subs: dict[str, tuple[str, Handler]] = {}
        self._retained: dict[str, BrokerMessage] = {}
        self._ids = itertools.count(1)

    def subscribe(self, topic_filter: str, handler: Handler) -> str:
        sid = f"sub-{next(self._ids)}"
        self._subs[sid] = (topic_filter, handler)
        return sid

    def unsubscribe(self, sid: str) -> None:
        self._subs.pop(sid, None)

    async def publish(self, topic: str, payload: Any, client_id: str, retain: bool = True) -> BrokerMessage:
        msg = BrokerMessage(topic, payload, client_id, utcnow())
        if retain:
            self._retained[topic] = msg
        for topic_filter, handler in list(self._subs.values()):
            if topic_matches(topic_filter, topic):
                await handler(msg)
        return msg

    def retained(self, topic_filter: str = "#") -> list[BrokerMessage]:
        return [m for t, m in sorted(self._retained.items()) if topic_matches(topic_filter, t)]

    def clear(self) -> None:
        self._retained.clear()
