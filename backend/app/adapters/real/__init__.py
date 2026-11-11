"""Real (live network) adapters. Registered by the composition root (app.main) when ADAPTER_MODE=real."""

from __future__ import annotations

from app.adapters.base import Protocol
from app.adapters.real.arp import RealArpAdapter
from app.adapters.real.icmp import RealIcmpAdapter
from app.adapters.real.mqtt import RealMqttAdapter
from app.adapters.real.net.broker import BundledBroker
from app.adapters.real.net.gate import NetworkGate, ScopeEntry
from app.adapters.real.plugins import ALL_PLUGINS
from app.adapters.real.snmp import RealSnmpAdapter
from app.adapters.real.ssh import RealSshAdapter
from app.adapters.real.tcp import RealTcpAdapter
from app.adapters.real.unavailable import UnavailableTransfer
from app.adapters.real.winrm import RealWinRmAdapter, RealWmiAdapter
from app.adapters.registry import AdapterRegistry


def register_real(registry: AdapterRegistry, gate: NetworkGate, broker: BundledBroker | None = None) -> None:
    registry.register(Protocol.ICMP, "real", RealIcmpAdapter(gate))
    registry.register(Protocol.ARP, "real", RealArpAdapter(gate))
    registry.register(Protocol.TCP, "real", RealTcpAdapter(gate))
    registry.register(Protocol.SNMP, "real", RealSnmpAdapter(gate))
    registry.register(Protocol.WINRM, "real", RealWinRmAdapter(gate))
    registry.register(Protocol.WMI, "real", RealWmiAdapter(gate))
    registry.register(Protocol.SSH, "real", RealSshAdapter(gate))
    registry.register(Protocol.MQTT, "real", RealMqttAdapter(broker))
    for plugin in ALL_PLUGINS:
        registry.register_plugin(plugin(gate))


__all__ = ["register_real", "BundledBroker", "NetworkGate", "ScopeEntry", "UnavailableTransfer"]
