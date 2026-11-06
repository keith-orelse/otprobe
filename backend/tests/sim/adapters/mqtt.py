from __future__ import annotations

import ipaddress
from typing import AsyncIterator, Awaitable, Callable

from app.adapters.base import (
    AdapterResult,
    DiscoveredHost,
    MqttAdapter,
    MqttMessage,
    Protocol,
    Query,
    ResultStatus,
    StageCallback,
    Target,
)
from tests.sim.adapters.common import SimAdapterMixin
from tests.sim.broker import Broker, BrokerMessage

KINDS = {"temperature": "temperature", "pressure": "pressure", "status": "plc_status"}


class SimulatedMqttAdapter(SimAdapterMixin, MqttAdapter):
    label = "MQTT (Demo broker)"

    def __init__(self, world, latency, broker: Broker) -> None:
        super().__init__(world, latency)
        self.broker = broker

    def _clients_from(self, ip: str) -> list[dict]:
        out = []
        for c in self.world.mqtt_clients():
            d = self.world.device(c["device_id"])
            if c["source_ip"] == ip and c["connected"] and d is not None and d.online:
                out.append(c)
        return out

    async def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        net = ipaddress.ip_network(target.address, strict=False)
        for c in self.world.mqtt_clients():
            if ipaddress.ip_address(c["source_ip"]) in net and self._clients_from(c["source_ip"]):
                await self.latency.wait(f"mqtt-clients:{c['client_id']}", 0.1)
                yield DiscoveredHost(c["source_ip"], None, Protocol.MQTT,
                                     {"mqtt.client_id": c["client_id"], "mqtt.topics": c["topics"]})

    async def probe(self, target: Target, query: Query, on_stage: StageCallback | None = None) -> AdapterResult:
        await self.latency.wait(f"mqtt:{target.address}", 0.2)
        clients = self._clients_from(target.address)
        if not clients:
            return self.result(target.address, ResultStatus.NOT_SUPPORTED, error_code="NO_CLIENT",
                               error_detail="No MQTT client connected from this address")
        c = clients[0]
        kind = next((KINDS[t.rsplit("/", 1)[-1]] for t in c["topics"] if t.rsplit("/", 1)[-1] in KINDS), None)
        data = {"mqtt.client_id": c["client_id"], "mqtt.topics": c["topics"],
                "mqtt.broker": f"{self.broker.host_ip}:{self.broker.port}", "telemetry.kind": kind}
        return self.result(target.address, ResultStatus.OK, data, raw={"clients": clients})

    async def health_check(self, target: Target) -> AdapterResult:
        return self.result(target.address, ResultStatus.OK, raw={"broker": f"{self.broker.host_ip}:{self.broker.port}"})

    async def get_device_info(self, target: Target) -> AdapterResult:
        return await self.probe(target, Query(["clients"]))

    async def subscribe(self, topic_filter: str, handler: Callable[[MqttMessage], Awaitable[None]]) -> str:
        async def bridge(m: BrokerMessage) -> None:
            await handler(MqttMessage(m.topic, m.payload, m.client_id, m.received_at))

        return self.broker.subscribe(topic_filter, bridge)

    async def unsubscribe(self, subscription_id: str) -> None:
        self.broker.unsubscribe(subscription_id)

    async def clients(self) -> list[dict]:
        return [{"client_id": c["client_id"], "source_ip": c["source_ip"], "topics": c["topics"]}
                for c in self.world.mqtt_clients() if c["connected"]]
