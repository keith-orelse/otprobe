"""Idempotent seeding of the simulated world. Existing devices are never overwritten (state survives
restarts); only Reset POC rebuilds the world."""

from __future__ import annotations

from copy import deepcopy

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models import SimDevice, SimFault, SimMeta, SimMqttClient
from app.sim import seed_data

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
