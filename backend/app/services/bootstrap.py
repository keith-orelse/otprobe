"""OTProbe-side configuration seed (zones, credential vault). Idempotent."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import demo_credentials
from app.models import CredentialProfile, Zone

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
