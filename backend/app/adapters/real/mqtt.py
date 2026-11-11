"""The MQTT adapter for the bundled broker (Mode A, docs/MQTT_BROKER.md). The broker process itself is
``app.adapters.real.net.broker.BundledBroker``; this adapter turns what it receives into ``MqttMessage``s and answers
the probe's "which MQTT device connected from this address"."""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import secrets
from typing import Any, AsyncIterator, Awaitable, Callable

from app.adapters.base import (
    AdapterDescriptor,
    AdapterResult,
    DiscoveredHost,
    MqttAdapter,
    MqttMessage,
    Query,
    ResultStatus,
    StageCallback,
    Target,
)
from app.adapters.real.net import mosquitto as mq
from app.adapters.real.net.broker import BundledBroker
from app.core.clock import utcnow
from app.core.mqtt_topics import topic_matches

log = logging.getLogger("otprobe.mqtt")
MAX_PAYLOAD = 16 * 1024                 # larger messages are counted, not stored
QUEUE_SIZE = 10_000
KINDS = {"temperature": "temperature", "pressure": "pressure", "status": "plc_status"}


def decode(payload: bytes) -> tuple[bool, Any]:
    """(stored, value): JSON when it parses (numbers, objects), else the text. Binary or oversized payloads (for
    example Sparkplug B protobuf) are not stored."""
    if len(payload) > MAX_PAYLOAD:
        return False, "oversize"
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return False, "binary"
    try:
        return True, json.loads(text)
    except ValueError:
        return True, text.strip()


class RealMqttAdapter(MqttAdapter):
    """Reads the bundled broker. A message's ``client_id`` is the device account allowed to publish its topic."""

    implementation = "mosquitto"
    label = "MQTT (bundled broker)"

    def __init__(self, broker: BundledBroker | None) -> None:
        self.broker = broker
        self._subs: dict[str, tuple[str, Callable[[MqttMessage], Awaitable[None]]]] = {}
        self._topics: dict[str, collections.OrderedDict[str, None]] = {}
        self._queue: asyncio.Queue | None = None
        self._worker: asyncio.Task | None = None
        self.dropped = collections.Counter()
        if broker is not None:
            broker.on_message = self._on_message

    def descriptor(self) -> AdapterDescriptor:
        return AdapterDescriptor(self.protocol, self.implementation, False, self.label)

    def _result(self, target: str, status: ResultStatus, data=None, raw=None, code=None, detail=None):
        return AdapterResult(self.protocol, target, status, data or {}, raw or {}, latency_ms=0.0,
                             collected_at=utcnow(), error_code=code, error_detail=detail)

    # ---- messages ----------------------------------------------------------------------------------------------

    def _on_message(self, topic: str, payload: bytes, retained: bool) -> None:
        stored, value = decode(payload)
        if not stored:
            self.dropped[value] += 1
            return
        username = mq.owner(topic, self.broker.accounts) if self.broker else None
        if username:
            seen = self._topics.setdefault(username, collections.OrderedDict())
            seen[topic] = None
            seen.move_to_end(topic)
            while len(seen) > 20:
                seen.popitem(last=False)
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(MqttMessage(topic, value, username or "", utcnow()))
        except asyncio.QueueFull:
            self.dropped["queue-full"] += 1

    async def _deliver(self) -> None:
        while True:
            msg = await self._queue.get()
            for topic_filter, handler in list(self._subs.values()):
                if topic_matches(topic_filter, msg.topic):
                    try:
                        await handler(msg)
                    except Exception:  # noqa: BLE001 - one bad handler never stops delivery
                        log.exception("MQTT handler failed for %s", msg.topic)

    async def subscribe(self, topic_filter: str, handler: Callable[[MqttMessage], Awaitable[None]]) -> str:
        if self._queue is None:
            self._queue = asyncio.Queue(QUEUE_SIZE)
            self._worker = asyncio.create_task(self._deliver(), name="mqtt-deliver")
        sub_id = secrets.token_hex(8)
        self._subs[sub_id] = (topic_filter, handler)
        return sub_id

    async def unsubscribe(self, subscription_id: str) -> None:
        self._subs.pop(subscription_id, None)
        if not self._subs and self._worker is not None:
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
            self._worker = self._queue = None

    async def clients(self) -> list[dict[str, Any]]:
        if self.broker is None:
            return []
        return [{"client_id": c["username"], "source_ip": c["ip"], "mqtt_client_id": c["client_id"],
                 "topics": list(self._topics.get(c["username"], {}))} for c in self.broker.connections()]

    # ---- probe -------------------------------------------------------------------------------------------------

    def _off(self, target: str) -> AdapterResult:
        return self._result(target, ResultStatus.NOT_SUPPORTED, code="BROKER_OFF",
                            detail="The bundled MQTT broker is off (set MQTT_BROKER=bundled)")

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        return
        yield  # pragma: no cover - devices connect to the broker; there is nothing to sweep

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        if self.broker is None:
            return self._off(target.address)
        mine = [c for c in await self.clients() if c["source_ip"] == target.address]
        if not mine:
            return self._result(target.address, ResultStatus.NOT_SUPPORTED, code="NO_CLIENT",
                                detail="No MQTT device connected from this address")
        c = mine[0]
        kind = next((KINDS[t.rsplit("/", 1)[-1]] for t in c["topics"] if t.rsplit("/", 1)[-1] in KINDS), None)
        host = self.broker.public_host or "otprobe"
        data = {"mqtt.client_id": c["mqtt_client_id"], "mqtt.account": c["client_id"], "mqtt.topics": c["topics"],
                "mqtt.broker": f"{host}:{self.broker.tls_port}"}
        if kind:
            data["telemetry.kind"] = kind
        return self._result(target.address, ResultStatus.OK, data, raw={"clients": mine})

    async def health_check(self, target: Target) -> AdapterResult:
        if self.broker is None:
            return self._off(target.address)
        status = ResultStatus.OK if self.broker.running else ResultStatus.UNREACHABLE
        return self._result(target.address, status, raw={"version": self.broker.version},
                            detail=self.broker.error or None)

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["clients"]))
