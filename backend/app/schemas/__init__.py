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
    maintenance_window_required: bool = False
    current_agent_id: str | None = None
    compliance: "Compliance | None" = None
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
    open_findings: dict[str, int] = {}
    compliance_avg: float | None = None
    unknown_total: int = 0
    monitoring: list["MonitoringRow"] = []
    recent_drift: list["DriftEvent"] = []
    recent_changes: list[dict[str, Any]] = []
    assets_by_level_type: dict[str, dict[str, int]] = {}
    pending_approvals: int = 0
    agents: dict[str, int] = {}


class NavCounts(Camel):
    pending_approvals: int
    open_findings: int
    critical_findings: int
    agents_attention: int
    rogue_assets: int
    running_workflows: int


# ---------------------------------------------------------------- Phase 3: auth, approvals, deployment, agents
class LoginRequest(Camel):
    username: str = Field(examples=["operator"])
    password: str = Field(examples=["operator-demo"])


class User(Camel):
    id: str
    username: str
    display_name: str
    role: str
    permissions: list[str] = []


class LoginResponse(Camel):
    access_token: str
    token_type: str = "bearer"
    expires_in_sec: int
    user: User


class StreamTicket(Camel):
    ticket: str
    expires_in_sec: int


class Package(Camel):
    id: str
    name: str
    version: str
    architecture: str
    sha256: str
    size_bytes: int
    supported_os: list[str]
    status: str
    release_notes: str
    created_at: datetime


class MaintenanceWindow(Camel):
    start: datetime
    end: datetime


class DeploymentCreate(Camel):
    asset_id: str
    package_id: str = Field(examples=["pkg-probe-agent-1.1.0"])
    credential_profile: str = "OT-WINDOWS-INSTALLER"
    purpose: str = Field(min_length=3, max_length=500, examples=["Deep compliance monitoring"])
    maintenance_window: MaintenanceWindow | None = None


class Decision(Camel):
    reason: str | None = Field(None, max_length=500)


class Approval(Camel):
    id: str
    subject_kind: str
    subject_id: str
    target_asset_id: str
    target_name: str | None = None
    requested_by: str
    purpose: str
    criticality: str | None
    maintenance_window: MaintenanceWindow | None = None
    status: str
    decided_by: str | None
    decided_at: datetime | None
    reason: str | None
    created_at: datetime
    actions: dict[str, ActionState] = {}


class PrecheckResult(Camel):
    run_no: int
    seq: int
    check: str
    status: str
    detail: str
    checked_at: datetime


class Deployment(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    package: Package | None = None
    credential_profile: str
    status: str
    purpose: str
    requested_by: str
    approval: Approval | None = None
    precheck_run_no: int
    precheck_passed_at: datetime | None
    precheck: list[PrecheckResult] = []
    steps: list[WorkflowStep] = []
    agent_id: str | None
    failure_code: str | None
    failure_detail: str | None
    retry_of_id: str | None
    correlation_id: str
    created_at: datetime
    deploy_started_at: datetime | None
    enrolling_since: datetime | None
    finished_at: datetime | None
    actions: dict[str, ActionState] = {}


class Agent(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    deployment_id: str
    status: str
    version: str
    credential_prefix: str | None
    installed_at: datetime
    enrolled_at: datetime | None
    last_heartbeat_at: datetime | None
    seconds_since_heartbeat: int | None = None
    missed_heartbeats: int
    heartbeat_interval_sec: float = 0
    revoked_at: datetime | None
    removed_at: datetime | None
    actions: dict[str, "ActionState"] = {}
    removal_id: str | None = None


class HeartbeatRecord(Camel):
    seq: int
    received_at: datetime
    agent_time: datetime | None
    payload: dict[str, Any]


class EnrollRequest(Camel):
    enrollment_token: str
    hostname: str
    host_fingerprint: str
    agent_version: str


class EnrollResponse(Camel):
    agent_id: str
    agent_credential: str
    heartbeat_interval_sec: float
    task_poll_wait_sec: int


class HeartbeatIn(Camel):
    seq: int = Field(ge=0)
    agent_time: datetime
    agent_version: str | None = None
    cpu_pct: float | None = None
    mem_mb: float | None = None
    queue_depth: int | None = None


class DemoFault(Camel):
    fault: str = Field(examples=["heartbeat_blocked"])
    enabled: bool = True
    params: dict[str, Any] = {}


class DemoDevice(Camel):
    device_id: str
    ip: str
    hostname: str
    type: str
    level: str
    powered: bool
    online: bool
    agent_installed: bool
    faults: list[str]
    config: dict[str, str] = {}


class DemoState(Camel):
    devices: list[DemoDevice]
    available_faults: dict[str, str]
    config_controls: dict[str, list[str]] = {}


# ---------------------------------------------------------------- Phase 4: assessments, findings, drift, comparison
class RuleInfo(Camel):
    id: str
    title: str
    severity: str
    sources: list[str]
    evidence: str
    condition: str
    on_fail: str
    references: list[str]


class PolicyInfo(Camel):
    key: str
    version: str
    name: str
    kind: str
    digest: str
    loaded_at: datetime
    rules: list[RuleInfo]


class AssessmentCreate(Camel):
    policy_id: str | None = Field(None, examples=["windows-engineering-baseline"])


class RuleResult(Camel):
    seq: int
    rule_id: str
    rule_version: str
    title: str
    status: str
    severity: str
    evidence_path: str
    observed: Any = None
    expected: str
    message: str | None
    previous_status: str | None
    references: list[str] = []


class DriftEvent(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    run_id: str
    previous_run_id: str
    rule_id: str
    from_status: str
    to_status: str
    evidence_path: str
    before: Any = None
    after: Any = None
    finding_id: str | None
    detected_at: datetime


class EvidenceChange(Camel):
    path: str
    before: Any = None
    after: Any = None
    detected_at: datetime


class AssessmentRun(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    agent_id: str | None
    policy_key: str
    policy_version: str
    source: str
    trigger: str
    status: str
    requested_by: str
    score: float | None
    counts: dict[str, int]
    previous_run_id: str | None
    error: str | None
    correlation_id: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    evidence: dict[str, Any] | None = None
    results: list[RuleResult] = []
    drift_events: list[DriftEvent] = []
    evidence_changes: list[EvidenceChange] = []


class Compliance(Camel):
    score: float | None
    counts: dict[str, int]
    source: str | None
    last_run_id: str | None
    last_assessment_at: datetime | None
    last_deep_status: str | None
    next_assessment_at: datetime | None
    open_findings: int
    run_action: ActionState


class FindingEventOut(Camel):
    from_status: str | None
    to_status: str
    run_id: str | None
    actor: str
    reason: str | None
    at: datetime


class Finding(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    asset_ip: str | None = None
    rule_id: str
    title: str
    severity: str
    status: str
    result_status: str
    source: str
    observed: Any = None
    expected: str
    references: list[str]
    remediation: str | None
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None
    reopen_count: int
    accepted_by: str | None
    accepted_reason: str | None
    accepted_at: datetime | None
    accepted_until: datetime | None
    last_run_id: str | None
    actions: dict[str, ActionState] = {}
    events: list[FindingEventOut] = []
    drift_events: list[DriftEvent] = []


class AcceptRisk(Camel):
    reason: str = Field(min_length=5, max_length=500)
    expires_at: datetime | None = None


class RevokeAcceptance(Camel):
    reason: str | None = None


class AuthorizeAsset(Camel):
    reason: str = Field(min_length=3, max_length=300)


class CompareCell(Camel):
    level: str
    value: Any = None
    source: str | None = None
    detail: str | None = None


class CompareRow(Camel):
    capability: str
    agentless: CompareCell
    deep: CompareCell


class Comparison(Camel):
    asset_id: str
    asset_name: str
    has_deep_evidence: bool
    rows: list[CompareRow]


class DemoConfig(Camel):
    control: Literal["firewall", "antivirus", "unauthorized_software", "remove_patch"]
    value: str = Field(examples=["disabled"])


class MonitoringRow(Camel):
    asset_id: str
    asset_name: str
    agent_id: str
    agent_status: str
    seconds_since_heartbeat: int | None
    last_assessment_at: datetime | None
    next_assessment_at: datetime | None
    score: float | None
    unknown: int
    open_findings: int


AssetDetail.model_rebuild()
DashboardSummary.model_rebuild()


# ---------------------------------------------------------------- Phase 5: removal, telemetry, demo, reset
class RemovalCreate(Camel):
    purpose: str = Field("Decommission POC agent", min_length=3, max_length=500)


class Removal(Camel):
    id: str
    asset_id: str
    asset_name: str | None = None
    agent_id: str
    status: str
    purpose: str
    requested_by: str
    approval: Approval | None = None
    failure_code: str | None
    failure_detail: str | None
    correlation_id: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    steps: list[WorkflowStep] = []
    actions: dict[str, ActionState] = {}


class TelemetryTopic(Camel):
    topic: str
    client_id: str
    asset_id: str | None
    asset_name: str | None
    last_payload: Any = None
    last_at: datetime
    messages: int
    open_findings: list[str] = []
    recent: list[dict[str, Any]] = []


class TelemetryRecord(Camel):
    topic: str
    client_id: str
    asset_id: str | None
    payload: Any = None
    received_at: datetime


class DemoReset(Camel):
    confirm: str = Field(description='Type "RESET" to confirm', examples=["RESET"])
    clear_discovery_history: bool = False
    force: bool = False


class DemoResetResult(Camel):
    status: str
    cleared: dict[str, int]
    discovery_history: str
    agents_revoked: int

Agent.model_rebuild()
