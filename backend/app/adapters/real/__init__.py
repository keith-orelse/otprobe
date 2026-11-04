"""Real (live network) adapters. Registered by the composition root (app.main) when ADAPTER_MODE=real."""

from __future__ import annotations

from app.adapters.base import Protocol
from app.adapters.real.arp import RealArpAdapter
from app.adapters.real.icmp import RealIcmpAdapter
from app.adapters.real.net.gate import NetworkGate, ScopeEntry
from app.adapters.real.snmp import RealSnmpAdapter
from app.adapters.real.tcp import RealTcpAdapter
from app.adapters.real.unavailable import (
    UnavailableMqtt,
    UnavailableSsh,
    UnavailableTransfer,
    UnavailableWinRm,
    UnavailableWmi,
)
from app.adapters.registry import AdapterRegistry


def register_real(registry: AdapterRegistry, gate: NetworkGate) -> None:
    registry.register(Protocol.ICMP, "real", RealIcmpAdapter(gate))
    registry.register(Protocol.ARP, "real", RealArpAdapter(gate))
    registry.register(Protocol.TCP, "real", RealTcpAdapter(gate))
    registry.register(Protocol.SNMP, "real", RealSnmpAdapter(gate))
    registry.register(Protocol.WINRM, "real", UnavailableWinRm())
    registry.register(Protocol.WMI, "real", UnavailableWmi())
    registry.register(Protocol.SSH, "real", UnavailableSsh())
    registry.register(Protocol.MQTT, "real", UnavailableMqtt())


__all__ = ["register_real", "NetworkGate", "ScopeEntry", "UnavailableTransfer"]
