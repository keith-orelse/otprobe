"""API schemas (camelCase on the wire). OpenAPI is generated from these."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

T = TypeVar("T")


class Camel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, from_attributes=True)

    def dump(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class Page(Camel, Generic[T]):
    items: list[T]
    next_cursor: str | None = None
    total: int


class Zone(Camel):
    id: str
    name: str
    cidr: str
    default_level: str
    safe_mode: bool
    scannable: bool
    description: str


class WorkflowStep(Camel):
    seq: int
    name: str
    status: str
    detail: str
    progress: float | None = None
    data: dict[str, Any] = {}
    started_at: datetime | None = None
    finished_at: datetime | None = None


Method = Literal["ARP", "ICMP", "SNMP"]


class DiscoveryMethod(Camel):
    method: str
    label: str
    implementation: str
    simulated: bool
    description: str


class DiscoveryJobCreate(Camel):
    targets: list[str] = Field(min_length=1, max_length=8, examples=[["192.168.20.0/24", "192.168.10.0/24"]])
    methods: list[Method] = Field(default_factory=lambda: ["ARP", "ICMP", "SNMP"], min_length=1)


class DiscoveryJob(Camel):
    id: str
    targets: list[str]
    methods: list[str]
    safe_mode: bool
    status: str
    progress: int
    phase: str | None
    devices_found: int
    new_assets: int
    rogue_count: int
    requested_by: str
    error: str | None
    correlation_id: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    steps: list[WorkflowStep] = []
    actions: dict[str, "ActionState"] = {}


class Observation(Camel):
    id: str
    asset_id: str | None
    ip: str
    mac: str | None
    method: str
    responded: bool
    result: dict[str, Any]
    observed_at: datetime


class FieldValue(Camel):
    path: str
    value: Any
    source: str
    source_label: str
    stage: str
    collected_at: datetime


class Classification(Camel):
    type: str
    confidence: int
    evidence: list[dict[str, Any]]


class ActionState(Camel):
    enabled: bool
    reason: str


DiscoveryJob.model_rebuild()


class AssetSummary(Camel):
    id: str
    ip: str
    mac: str | None
    hostname: str | None
    sys_name: str | None
    display_name: str
    type: str | None = Field(validation_alias="device_type")
    os: str | None = Field(validation_alias="os_name")
    level: str
    criticality: str | None
    status: str
    is_rogue: bool
    agent_state: str
    eligibility: str
    eligibility_reason: str
    discovered_by: list[str]
    first_seen: datetime
    last_seen: datetime
    last_probe_at: datetime | None


class Relationship(Camel):
    kind: str
    direction: str
    peer_asset_id: str
    peer_name: str
    protocol: str
    port: int | None
    source: str


class AssetDetail(AssetSummary):
    zone: Zone | None = None
    classification: Classification | None = None
    groups: dict[str, list[FieldValue]] = {}
    relationships: list[Relationship] = []
    deploy_agent: ActionState
    agentless: ActionState
    last_probe_id: str | None = None
    notes: list[str] = []


class ProbeCreate(Camel):
    note: str | None = None


class ProbeResult(Camel):
    protocol: str
    status: str
    data: dict[str, Any]
    stages: list[dict[str, Any]]
    latency_ms: float | None
    error_code: str | None
    error_detail: str | None
    collected_at: datetime


class ProbeRun(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    status: str
    requested_by: str
    classification: Classification | None
    eligibility: str | None
    eligibility_reason: str | None
    error: str | None
    correlation_id: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    steps: list[WorkflowStep] = []
    results: list[ProbeResult] = []


class AuditEvent(Camel):
    seq: int
    at: datetime
    actor_type: str
    actor_id: str | None
    actor_name: str
    action: str
    entity_kind: str
    entity_id: str | None
    correlation_id: str | None
    details: dict[str, Any]
    hash: str


class VaultProfile(Camel):
    name: str
    protocol: str
    username: str
    secret: str
    secret_set: bool


class TopologyNode(Camel):
    id: str
    kind: str
    parent: str | None
    label: str
    state: str | None = None
    asset_id: str | None = None
    ip: str | None = None
    type: str | None = None
    order: int | None = None   # zones: top-to-bottom display order
    tier: str | None = None    # assets: "infrastructure" (observed to link other assets) or "host"


class TopologyEdge(Camel):
    id: str
    source: str
    target: str
    kind: str
    protocol: str | None = None
    port: int | None = None


class Topology(Camel):
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


class DashboardSummary(Camel):
    assets: dict[str, int]
    assets_by_level: dict[str, int]
    eligibility: dict[str, int]
    rogue: int
    last_discovery: DiscoveryJob | None
    recent_events: list[AuditEvent]
    adapters: list[dict[str, Any]]
