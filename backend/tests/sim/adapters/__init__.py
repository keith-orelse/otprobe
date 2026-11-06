"""Simulated adapter implementations. Registered by the composition root (app.main)."""

from __future__ import annotations

from app.adapters.base import Protocol
from app.adapters.registry import AdapterRegistry
from tests.sim.adapters.arp import SimulatedArpAdapter
from tests.sim.adapters.control import SimulatedControl
from tests.sim.adapters.icmp import SimulatedIcmpAdapter
from tests.sim.adapters.mqtt import SimulatedMqttAdapter
from tests.sim.adapters.snmp import SimulatedSnmpAdapter
from tests.sim.adapters.ssh import SimulatedSshAdapter
from tests.sim.adapters.transfer import SimulatedPackageTransfer
from tests.sim.adapters.winrm import SimulatedWinRmAdapter
from tests.sim.adapters.wmi import SimulatedWmiAdapter
from tests.sim.broker import Broker
from tests.sim.latency import SimLatency
from tests.sim.world import SimWorld


def register_simulated(registry: AdapterRegistry, world: SimWorld, latency: SimLatency, broker: Broker) -> None:
    """Registers protocol adapters. Package transfer is built separately because it shares WinRM sessions."""
    registry.register(Protocol.ICMP, "simulated", SimulatedIcmpAdapter(world, latency))
    registry.register(Protocol.ARP, "simulated", SimulatedArpAdapter(world, latency))
    registry.register(Protocol.SNMP, "simulated", SimulatedSnmpAdapter(world, latency))
    registry.register(Protocol.WINRM, "simulated", SimulatedWinRmAdapter(world, latency))
    registry.register(Protocol.WMI, "simulated", SimulatedWmiAdapter(world, latency))
    registry.register(Protocol.SSH, "simulated", SimulatedSshAdapter(world, latency))
    registry.register(Protocol.MQTT, "simulated", SimulatedMqttAdapter(world, latency, broker))


def build_transfer(registry: AdapterRegistry, world: SimWorld, latency: SimLatency) -> SimulatedPackageTransfer:
    winrm = registry.implementations(Protocol.WINRM)["simulated"]
    return SimulatedPackageTransfer(world, latency, winrm.session_device)


__all__ = ["register_simulated", "build_transfer", "SimulatedControl"]
