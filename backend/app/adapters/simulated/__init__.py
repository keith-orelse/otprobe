"""Simulated adapter implementations. Registered by the composition root (app.main)."""

from __future__ import annotations

from app.adapters.base import Protocol
from app.adapters.registry import AdapterRegistry
from app.adapters.simulated.arp import SimulatedArpAdapter
from app.adapters.simulated.control import SimulatedControl
from app.adapters.simulated.icmp import SimulatedIcmpAdapter
from app.adapters.simulated.mqtt import SimulatedMqttAdapter
from app.adapters.simulated.snmp import SimulatedSnmpAdapter
from app.adapters.simulated.ssh import SimulatedSshAdapter
from app.adapters.simulated.transfer import SimulatedPackageTransfer
from app.adapters.simulated.winrm import SimulatedWinRmAdapter
from app.adapters.simulated.wmi import SimulatedWmiAdapter
from app.sim.broker import Broker
from app.sim.latency import SimLatency
from app.sim.world import SimWorld


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
