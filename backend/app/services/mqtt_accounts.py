"""Device accounts on the bundled MQTT broker (Mode A, docs/MQTT_BROKER.md §2).

OTProbe's database is the source of truth: the broker's password and ACL files are rebuilt from it at start-up and on
every change. Passwords are shown once and only Mosquitto's hash is kept. Each account may publish under its own
topic prefix only, and prefixes never overlap, so every message has exactly one possible publisher."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.base import BrokerAccount, Protocol
from app.context import AppContext
from app.core import audit, events
from app.core.audit import Actor
from app.core.clock import utcnow
from app.core.errors import ProblemError, not_found
from app.core.mqtt_topics import overlaps, password_hash, valid_prefix, valid_username
from app.models import Asset, MqttAccount, TelemetryMessage


def broker_accounts(session: Session) -> list[BrokerAccount]:
    return [BrokerAccount(a.username, a.password_hash, a.topic_prefix, a.enabled)
            for a in session.scalars(select(MqttAccount).order_by(MqttAccount.username))]


async def start_broker(ctx: AppContext) -> None:
    if ctx.broker is None:
        return
    with ctx.db.session() as s:
        accounts = broker_accounts(s)
    await ctx.broker.start(accounts)


async def _apply(ctx: AppContext, kick: tuple[str, ...] = ()) -> None:
    if ctx.broker is None:
        return
    with ctx.db.session() as s:
        accounts = broker_accounts(s)
    await ctx.broker.apply(accounts, kick=kick)


def _require_broker(ctx: AppContext) -> None:
    if ctx.broker is None:
        raise ProblemError(409, "mqtt-broker-off", "MQTT broker is off",
                           "Set MQTT_BROKER=bundled and restart OTProbe to manage device accounts")


def _get(session: Session, username: str) -> MqttAccount:
    acc = session.scalar(select(MqttAccount).where(MqttAccount.username == username))
    if acc is None:
        raise not_found("MQTT account", username)
    return acc


def _asset(session: Session, asset_id: str | None) -> Asset | None:
    if asset_id is None:
        return None
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise ProblemError(422, "unknown-asset", "Unknown asset", f"Asset {asset_id} does not exist")
    return asset


def _view(ctx: AppContext, session: Session, a: MqttAccount) -> schemas.MqttAccount:
    conns = [c for c in (ctx.broker.connections() if ctx.broker else []) if c["username"] == a.username]
    seen = ctx.broker.last_seen.get(a.username) if ctx.broker else None    # kept after a disconnect
    asset = session.get(Asset, a.asset_id) if a.asset_id else None
    mine = TelemetryMessage.client_id == a.username
    last = session.scalar(select(func.max(TelemetryMessage.received_at)).where(mine))
    topics = list(session.scalars(select(TelemetryMessage.topic).where(mine)
                                  .group_by(TelemetryMessage.topic).order_by(TelemetryMessage.topic).limit(50)))
    return schemas.MqttAccount(username=a.username, topic_prefix=a.topic_prefix, asset_id=a.asset_id,
                               asset_name=asset.display_name if asset else None, description=a.description,
                               enabled=a.enabled, created_by=a.created_by, created_at=a.created_at,
                               password_changed_at=a.password_changed_at, connected=bool(conns),
                               connections=[{"clientId": c["client_id"], "ip": c["ip"],
                                             "connectedAt": c["connected_at"]} for c in conns],
                               last_seen=seen, last_message_at=last, topics=topics)


def _connection(ctx: AppContext, a: MqttAccount) -> dict[str, Any]:
    """What to type into the device."""
    status = ctx.broker.status() if ctx.broker else {}
    tls = next((x for x in status.get("listeners", []) if x["tls"]), None)
    plain = next((x for x in status.get("listeners", []) if not x["tls"]), None)
    return {"host": status.get("host") or "<OTProbe IP>", "port": (tls or plain or {}).get("port"),
            "tls": tls is not None, "username": a.username, "topic": f"{a.topic_prefix}/<metric>",
            "caCertificate": "/api/v1/mqtt/ca.pem" if tls else None}


def list_accounts(ctx: AppContext) -> list[schemas.MqttAccount]:
    with ctx.db.session() as s:
        return [_view(ctx, s, a) for a in s.scalars(select(MqttAccount).order_by(MqttAccount.username))]


async def create_account(ctx: AppContext, req: schemas.MqttAccountCreate, actor: Actor) -> schemas.MqttAccountSecret:
    _require_broker(ctx)
    prefix = req.topic_prefix.strip()
    if not valid_username(req.username):
        raise ProblemError(422, "mqtt-username-invalid", "Invalid username",
                           "Lowercase letters, digits, '.', '_' or '-', 3-64 characters, not starting with 'otprobe'")
    if not valid_prefix(prefix):
        raise ProblemError(422, "mqtt-acl-too-broad", "Invalid topic prefix",
                           "Use plain topic levels such as plant/line1/sensor01: no wildcards (+ #), no $, no "
                           "leading or trailing '/', at most 10 levels")
    password = secrets.token_urlsafe(18)
    with ctx.db.session() as s:
        if s.scalar(select(MqttAccount).where(MqttAccount.username == req.username)) is not None:
            raise ProblemError(409, "mqtt-account-exists", "Account exists", f"{req.username} already exists")
        for other in s.scalars(select(MqttAccount)):
            if overlaps(prefix, other.topic_prefix):
                raise ProblemError(409, "mqtt-prefix-overlap", "Topic prefix overlaps",
                                   f"{prefix} overlaps {other.topic_prefix} ({other.username}). Each device needs "
                                   "its own topics, so every message has one sender")
        _asset(s, req.asset_id)
        acc = MqttAccount(username=req.username, topic_prefix=prefix, asset_id=req.asset_id,
                          description=req.description, password_hash=password_hash(password), enabled=True,
                          created_by=actor.name)
        s.add(acc)
        s.flush()
        audit.record(s, actor, "MQTT_ACCOUNT_CREATED", "mqtt_account", acc.username,
                     {"topicPrefix": prefix, "assetId": req.asset_id})
        events.stage(s, "mqtt.account", "mqtt_account", acc.username, {})
    await _apply(ctx)
    with ctx.db.session() as s:
        acc = _get(s, req.username)
        return schemas.MqttAccountSecret(account=_view(ctx, s, acc), password=password,
                                         connection=_connection(ctx, acc))


async def update_account(ctx: AppContext, username: str, req: schemas.MqttAccountUpdate,
                         actor: Actor) -> schemas.MqttAccount:
    _require_broker(ctx)
    fields = req.model_fields_set
    with ctx.db.session() as s:
        acc = _get(s, username)
        changes: dict[str, Any] = {}
        if "asset_id" in fields and req.asset_id != acc.asset_id:
            _asset(s, req.asset_id)
            changes["assetId"] = {"from": acc.asset_id, "to": req.asset_id}
            acc.asset_id = req.asset_id
            # Messages already received move with the account.
            for m in s.scalars(select(TelemetryMessage).where(TelemetryMessage.client_id == username)):
                m.asset_id = req.asset_id
        if "description" in fields and req.description is not None and req.description != acc.description:
            changes["description"] = req.description
            acc.description = req.description
        toggled = "enabled" in fields and req.enabled is not None and req.enabled != acc.enabled
        if toggled:
            acc.enabled = bool(req.enabled)
            audit.record(s, actor, "MQTT_ACCOUNT_ENABLED" if acc.enabled else "MQTT_ACCOUNT_DISABLED",
                         "mqtt_account", username, {})
        if changes:
            audit.record(s, actor, "MQTT_ACCOUNT_UPDATED", "mqtt_account", username, changes)
        events.stage(s, "mqtt.account", "mqtt_account", username, {})
    if toggled:
        await _apply(ctx)
    with ctx.db.session() as s:
        return _view(ctx, s, _get(s, username))


async def new_password(ctx: AppContext, username: str, actor: Actor) -> schemas.MqttAccountSecret:
    """A new password; the device is disconnected and must log in with it."""
    _require_broker(ctx)
    password = secrets.token_urlsafe(18)
    with ctx.db.session() as s:
        acc = _get(s, username)
        acc.password_hash, acc.password_changed_at = password_hash(password), utcnow()
        audit.record(s, actor, "MQTT_ACCOUNT_PASSWORD_ROTATED", "mqtt_account", username, {})
    await _apply(ctx, kick=(username,))
    with ctx.db.session() as s:
        acc = _get(s, username)
        return schemas.MqttAccountSecret(account=_view(ctx, s, acc), password=password,
                                         connection=_connection(ctx, acc))


async def delete_account(ctx: AppContext, username: str, actor: Actor) -> None:
    _require_broker(ctx)
    with ctx.db.session() as s:
        acc = _get(s, username)
        audit.record(s, actor, "MQTT_ACCOUNT_DELETED", "mqtt_account", username,
                     {"topicPrefix": acc.topic_prefix, "assetId": acc.asset_id})
        s.delete(acc)
        events.stage(s, "mqtt.account", "mqtt_account", username, {})
    await _apply(ctx)


def broker_status(ctx: AppContext, admin: bool) -> schemas.MqttBrokerStatus:
    if ctx.broker is None:
        return schemas.MqttBrokerStatus(mode="off")
    st = dict(ctx.broker.status())
    if not admin:
        st["log"], st["refused"] = [], []
    with ctx.db.session() as s:
        st["accounts"] = s.scalar(select(func.count()).select_from(MqttAccount)) or 0
    st["dropped"] = dict(getattr(ctx.registry.get(Protocol.MQTT), "dropped", {}) or {})
    st["ca_available"] = bool(ca_pem(ctx))
    return schemas.MqttBrokerStatus(**st)


def ca_pem(ctx: AppContext) -> str:
    """The CA certificate devices install to trust the broker (public; it is the same CA the agents pin)."""
    path = ctx.settings.tls_ca_file
    return Path(path).read_text() if path and Path(path).is_file() else ""
