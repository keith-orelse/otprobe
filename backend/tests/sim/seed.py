"""Idempotent seeding of the simulated world and of the OTProbe-side demo configuration (zones, vault, demo users,
packages). Existing rows are never overwritten (state survives restarts); only Reset POC rebuilds the world."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models import CredentialProfile, Package, User, Zone
from tests.sim import demo_credentials, seed_data
from tests.sim.models import SimDevice, SimFault, SimMeta, SimMqttClient

SEED_VERSION = 1


def seed_world(session: Session) -> int:
    created = 0
    for d in seed_data.DEVICES:
        if session.get(SimDevice, d["device_id"]) is None:
            session.add(SimDevice(**{**d, "state": deepcopy(d["state"])}, powered=True))
            created += 1
    for c in seed_data.MQTT_CLIENTS:
        if session.get(SimMqttClient, c["client_id"]) is None:
            session.add(SimMqttClient(**deepcopy(c), connected=True))
    if session.get(SimMeta, "seed_version") is None:
        session.add(SimMeta(key="seed_version", value=SEED_VERSION))
    session.flush()
    return created


def reset_world(session: Session) -> None:
    for model in (SimFault, SimMqttClient, SimDevice, SimMeta):
        session.execute(delete(model))
    session.flush()
    seed_world(session)


ZONES = [
    Zone(id="zone-dmz", name="DMZ (OTProbe server)", cidr="192.168.35.0/24", default_level="DMZ", safe_mode=False,
         scannable=False, description="Probe server zone. Never scanned."),
    Zone(id="zone-l2", name="Supervisory (Level 2)", cidr="192.168.20.0/24", default_level="2", safe_mode=False,
         scannable=True, description="Engineering workstations, SCADA, historian. Reached via fw-conduit-01."),
    Zone(id="zone-l1", name="Control / Process (Level 1/0)", cidr="192.168.10.0/24", default_level="1",
         safe_mode=True, scannable=True,
         description="PLCs and field devices. SAFE MODE: passive/read-only, rate-limited."),
]

DESCRIPTIONS = {
    "OT-WINDOWS-READONLY": "Read-only WinRM/CIM account for agentless probing",
    "OT-WINDOWS-INSTALLER": "Installer account for agent deployment (approval required)",
    "OT-SNMPV3-RO": "SNMPv3 authPriv read-only user (SHA-256/AES-128)",
    "OT-LINUX-SSH-RO": "Read-only SSH account for Linux identity collection",
}


def seed_config(session: Session, fernet) -> None:
    for z in ZONES:
        if session.get(Zone, z.id) is None:
            session.add(Zone(**{c.key: getattr(z, c.key) for c in Zone.__table__.columns}))
    for name, protocol, username, secret in demo_credentials.ALL:
        if session.scalar(select(CredentialProfile).where(CredentialProfile.name == name)) is None:
            params = {"auth": "SHA-256", "priv": "AES-128"} if protocol == "SNMP" else {}
            session.add(CredentialProfile(name=name, protocol=protocol, username=username, params=params,
                                          secret_ciphertext=fernet.encrypt(secret.encode()).decode(),
                                          description=DESCRIPTIONS[name]))
    session.flush()


DEMO_USERS = [
    ("operator", "Olivia Operator (demo)", "OPERATOR", "operator-demo"),
    ("approver", "Arjun Approver (demo)", "APPROVER", "approver-demo"),
    ("admin", "Ada Admin (demo)", "ADMIN", "admin-demo"),
]

PACKAGE_SUPPORTED_OS = ["Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022"]


def package_blob_sha256(version: str, size: int) -> str:
    """SHA-256 of a deterministic generated blob standing in for the MSI (real hash, no real binary)."""
    h = hashlib.sha256()
    chunk = hashlib.sha512(f"OTProbe Probe Agent {version} x64".encode()).digest() * 1024
    remaining = size
    while remaining > 0:
        part = chunk[:remaining]
        h.update(part)
        remaining -= len(part)
    return h.hexdigest()


def seed_trust(session: Session) -> None:
    for username, display, role, password in DEMO_USERS:
        if session.scalar(select(User).where(User.username == username)) is None:
            session.add(User(username=username, display_name=display, role=role,
                             password_hash=hash_password(password)))
    for version, status, size, notes, created in (
        ("1.0.0", "DEPRECATED", 18_874_368, "Initial POC agent. Superseded by 1.1.0.",
         datetime(2026, 6, 2, tzinfo=timezone.utc)),
        ("1.1.0", "ACTIVE", 24_117_248, "Adds long-poll tasking and USB policy collector.",
         datetime(2026, 9, 15, tzinfo=timezone.utc)),
    ):
        pid = f"pkg-probe-agent-{version}"
        if session.get(Package, pid) is None:
            session.add(Package(id=pid, name="Probe Agent", version=version, architecture="x64",
                                sha256=package_blob_sha256(version, size), size_bytes=size,
                                supported_os=PACKAGE_SUPPORTED_OS, status=status, release_notes=notes,
                                created_at=created))
    session.flush()
