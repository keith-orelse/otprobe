"""Protocol abstraction layer.

Engines depend ONLY on the interfaces in this module. Simulated implementations live in
``app.adapters.simulated``; real implementations (not part of the POC) would live in
``app.adapters.real``. Both must pass ``tests/contract``.

Every adapter returns normalised data keyed by provenance field paths (see docs/PROVENANCE.md),
so business code never sees protocol-specific shapes.
"""

from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Awaitable, Callable, Mapping, Optional, Sequence


class Protocol(str, enum.Enum):
    ICMP = "ICMP"
    ARP = "ARP"
    SNMP = "SNMP"
    WINRM = "WinRM"
    WMI = "WMI"
    MQTT = "MQTT"
    SSH = "SSH"


class ResultStatus(str, enum.Enum):
    """Outcome of a single adapter call. Adapters never raise for expected network outcomes."""

    OK = "OK"
    PARTIAL = "PARTIAL"              # some data collected, some queries failed
    TIMEOUT = "TIMEOUT"
    UNREACHABLE = "UNREACHABLE"      # no route / host down
    REFUSED = "REFUSED"              # TCP RST / port closed
    BLOCKED = "BLOCKED"              # filtered (e.g. ICMP disabled, conduit drop)
    AUTH_FAILED = "AUTH_FAILED"
    TLS_INVALID = "TLS_INVALID"
    DISABLED = "DISABLED"            # service present but disabled (e.g. WinRM)
    NOT_SUPPORTED = "NOT_SUPPORTED"  # protocol not applicable to this target
    ERROR = "ERROR"                  # unexpected adapter error


class Reachability(str, enum.Enum):
    """ICMP-specific health states. NOTE: no reply does NOT imply OFFLINE."""

    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    HIGH_LATENCY = "HIGH_LATENCY"
    TIMEOUT = "TIMEOUT"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Credential:
    """Resolved credential handed to an adapter. ``secret`` must never be logged or serialised."""

    profile: str
    username: str
    secret: str = field(repr=False)
    params: Mapping[str, Any] = field(default_factory=dict)  # e.g. SNMPv3 auth/priv protocols


@dataclass(frozen=True)
class Target:
    """A single host (``address``) or a subnet in CIDR form for ``discover``."""

    address: str
    port: Optional[int] = None
    credential: Optional[Credential] = None
    safe_mode: bool = False                  # Level 0/1: passive/read-only, rate-limited
    timeout_sec: float = 5.0
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Query:
    """Protocol-specific query. ``items`` are logical groups, e.g. SNMP ``["system", "interfaces"]``
    or WMI ``["os", "hardware", "firewall", "antivirus", "software", "services", "hotfixes"]``."""

    items: Sequence[str]
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class Stage:
    """A visible sub-step of an adapter call (e.g. WinRM CONNECTING -> TCP_OK -> ...)."""

    name: str
    status: ResultStatus
    detail: str = ""
    at: Optional[datetime] = None


@dataclass
class AdapterResult:
    protocol: Protocol
    target: str
    status: ResultStatus
    # Normalised data keyed by provenance field path, e.g. {"os.build": "26100.2314"}.
    data: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    stages: list[Stage] = field(default_factory=list)
    latency_ms: Optional[float] = None
    collected_at: Optional[datetime] = None
    error_code: Optional[str] = None
    error_detail: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status in (ResultStatus.OK, ResultStatus.PARTIAL)


@dataclass(frozen=True)
class DiscoveredHost:
    ip: str
    mac: Optional[str]
    method: Protocol
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdapterDescriptor:
    protocol: Protocol
    implementation: str          # e.g. "simulated", "pysnmp"
    simulated: bool              # drives UI labels like "SNMP (Demo)"; never used by business logic
    display_label: str           # e.g. "SNMP (Demo)", "ARP (via switch span, Demo)"


StageCallback = Callable[[Stage], Awaitable[None]]
ProgressCallback = Callable[[float], Awaitable[None]]  # 0.0 .. 1.0


class ProtocolAdapter(abc.ABC):
    """Common contract for every protocol adapter."""

    protocol: Protocol

    @abc.abstractmethod
    def descriptor(self) -> AdapterDescriptor: ...

    @abc.abstractmethod
    def discover(self, target: Target) -> AsyncIterator[DiscoveredHost]:
        """Yield hosts found in ``target`` (CIDR) one by one, so discovery can stream progress.
        Adapters that cannot discover (WinRM, WMI, SSH) yield nothing."""

    @abc.abstractmethod
    async def probe(self, target: Target, query: Query, on_stage: Optional[StageCallback] = None) -> AdapterResult:
        """Collect the queried groups from a single host."""

    @abc.abstractmethod
    async def health_check(self, target: Target) -> AdapterResult:
        """Cheap reachability check for this protocol (no credentials required unless needed)."""

    @abc.abstractmethod
    async def get_device_info(self, target: Target) -> AdapterResult:
        """Identity summary: whatever this protocol can tell about vendor/model/os/hostname."""


class IcmpAdapter(ProtocolAdapter):
    protocol = Protocol.ICMP
    # health_check().data contains {"reachability.icmp": Reachability, "reachability.rtt_ms": float}


class ArpAdapter(ProtocolAdapter):
    protocol = Protocol.ARP


class SnmpAdapter(ProtocolAdapter):
    protocol = Protocol.SNMP


class WmiAdapter(ProtocolAdapter):
    protocol = Protocol.WMI


class SshAdapter(ProtocolAdapter):
    """Stub in the POC: identity-only (hostname, os-release, kernel, uptime)."""

    protocol = Protocol.SSH


class RemoteOperation(str, enum.Enum):
    """Closed set of remote operations the deployment/removal engines may request.
    A real WinRM adapter maps each to a vetted PowerShell script; no free-form commands."""

    QUERY_DISK_FREE = "QUERY_DISK_FREE"
    QUERY_HOSTNAME = "QUERY_HOSTNAME"
    QUERY_SERVICE = "QUERY_SERVICE"
    QUERY_REBOOT_PENDING = "QUERY_REBOOT_PENDING"
    QUERY_AGENT_INSTALLED = "QUERY_AGENT_INSTALLED"
    QUERY_SERVER_CONNECTIVITY = "QUERY_SERVER_CONNECTIVITY"  # Test-NetConnection <server> -Port 443
    VERIFY_FILE_HASH = "VERIFY_FILE_HASH"
    INSTALL_AGENT = "INSTALL_AGENT"
    WRITE_ENROLLMENT_BUNDLE = "WRITE_ENROLLMENT_BUNDLE"
    START_SERVICE = "START_SERVICE"
    STOP_SERVICE = "STOP_SERVICE"
    UNINSTALL_AGENT = "UNINSTALL_AGENT"
    REMOVE_FILES = "REMOVE_FILES"


@dataclass
class RemoteSession:
    session_id: str
    target: str
    stages: list[Stage]


class WinRmAdapter(ProtocolAdapter):
    protocol = Protocol.WINRM

    @abc.abstractmethod
    async def open_session(self, target: Target, on_stage: Optional[StageCallback] = None
                           ) -> tuple[AdapterResult, Optional[RemoteSession]]:
        """Stages: CONNECTING -> TCP_OK -> TLS_VALIDATED -> AUTH_OK -> SESSION_CREATED."""

    @abc.abstractmethod
    async def execute(self, session: RemoteSession, op: RemoteOperation,
                      params: Mapping[str, Any]) -> AdapterResult: ...

    @abc.abstractmethod
    async def close_session(self, session: RemoteSession) -> None: ...


@dataclass(frozen=True)
class MqttMessage:
    topic: str
    payload: Any
    client_id: str
    received_at: datetime


class MqttAdapter(ProtocolAdapter):
    protocol = Protocol.MQTT

    @abc.abstractmethod
    async def subscribe(self, topic_filter: str, handler: Callable[[MqttMessage], Awaitable[None]]) -> str:
        """Returns a subscription id."""

    @abc.abstractmethod
    async def unsubscribe(self, subscription_id: str) -> None: ...


# ---- Non-protocol infrastructure interfaces (same swap rules apply) ----------------------------


@dataclass(frozen=True)
class PackageRef:
    package_id: str
    name: str
    version: str
    sha256: str
    size_bytes: int


@dataclass
class TransferResult:
    status: ResultStatus
    remote_path: Optional[str] = None
    bytes_transferred: int = 0
    error_code: Optional[str] = None
    error_detail: Optional[str] = None


class PackageTransfer(abc.ABC):
    @abc.abstractmethod
    async def transfer(self, session: RemoteSession, package: PackageRef,
                       on_progress: Optional[ProgressCallback] = None) -> TransferResult: ...


@dataclass(frozen=True)
class MaskedCredential:
    profile: str
    protocol: str
    username: str
    secret: str = "••••••••"
    secret_set: bool = True


class CredentialVault(abc.ABC):
    @abc.abstractmethod
    async def resolve(self, profile: str, *, purpose: str, correlation_id: str) -> Credential:
        """Return the secret for immediate use. Every call is audited (CREDENTIAL_RETRIEVED)."""

    @abc.abstractmethod
    async def describe(self, profile: str) -> MaskedCredential: ...

    @abc.abstractmethod
    async def list_profiles(self) -> list[MaskedCredential]: ...


class SimulationControl(abc.ABC):
    """Port for admin Demo Controls. Only a simulated implementation exists; a real deployment would not register
    one, and the demo endpoints would return 404."""

    @abc.abstractmethod
    def devices(self) -> list[dict[str, Any]]: ...

    @abc.abstractmethod
    def set_fault(self, device_id: str, fault: str, params: Mapping[str, Any], set_by: str) -> None: ...

    @abc.abstractmethod
    def clear_fault(self, device_id: str, fault: str) -> None: ...
