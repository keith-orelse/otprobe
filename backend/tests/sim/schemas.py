"""Demo Controls and Reset POC request/response bodies (test simulator only)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.schemas import Camel


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


class DemoConfig(Camel):
    control: Literal["firewall", "antivirus", "unauthorized_software", "remove_patch"]
    value: str = Field(examples=["disabled"])


class DemoReset(Camel):
    confirm: str = Field(description='Type "RESET" to confirm', examples=["RESET"])
    clear_discovery_history: bool = False
    force: bool = False


class DemoResetResult(Camel):
    status: str
    cleared: dict[str, int]
    discovery_history: str
    agents_revoked: int
