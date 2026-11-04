"""MQTT telemetry ingest: subscribe, store (bounded), attribute to assets, evaluate telemetry rules -> findings."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app import schemas
from app.adapters.base import MqttMessage, Protocol
from app.context import AppContext
from app.core import audit, events
from app.core.audit import system
from app.core.clock import utcnow
from app.core.mqtt_topics import topic_matches
from app.engines.assessment.engine import RuleOutcome, evaluate_policy
from app.engines.assessment.findings import apply_outcome
from app.models import Asset, Finding, TelemetryMessage

log = logging.getLogger("otprobe.telemetry")
ACTOR = system("telemetry-engine")
SUBSCRIPTION = "factory/#"


class TelemetryService:
    def __init__(self, ctx: AppContext) -> None:
        self.ctx = ctx
        self.sub_id: str | None = None
        self._ip_by_client: dict[str, str] = {}

    @property
    def mqtt(self):
        return self.ctx.registry.get(Protocol.MQTT)

    def policies(self) -> list[dict[str, Any]]:
        return [p for p in self.ctx.rules.policies.values() if p["policy"]["kind"] == "telemetry"]

    async def start(self) -> None:
        self.sub_id = await self.mqtt.subscribe(SUBSCRIPTION, self.on_message)

    async def stop(self) -> None:
        if self.sub_id:
            await self.mqtt.unsubscribe(self.sub_id)

    async def _asset_for(self, session: Session, client_id: str) -> Asset | None:
        if client_id not in self._ip_by_client:
            self._ip_by_client = {c["client_id"]: c["source_ip"] for c in await self.mqtt.clients()}
        ip = self._ip_by_client.get(client_id)
        return session.scalar(select(Asset).where(Asset.ip == ip)) if ip else None

    async def on_message(self, msg: MqttMessage) -> None:
        try:
            with self.ctx.db.session() as s:
                asset = await self._asset_for(s, msg.client_id)
                s.add(TelemetryMessage(topic=msg.topic, client_id=msg.client_id, asset_id=asset.id if asset else None,
                                       payload=msg.payload, received_at=msg.received_at))
                s.flush()
                self._prune(s)
                if asset is not None:
                    self._evaluate(s, asset, msg.topic, msg.payload, msg.client_id)
                events.stage(s, "telemetry.message", "telemetry", msg.topic,
                             {"clientId": msg.client_id, "assetId": asset.id if asset else None,
                              "payload": msg.payload})
        except Exception:  # noqa: BLE001 - never break the broker loop
            log.exception("telemetry message failed: %s", msg.topic)

    def _prune(self, s: Session) -> None:
        keep = self.ctx.settings.telemetry_retention
        count = s.scalar(select(func.count()).select_from(TelemetryMessage)) or 0
        if count > keep * 1.1:
            cutoff = s.scalar(select(TelemetryMessage.received_at).order_by(TelemetryMessage.received_at.desc())
                              .offset(keep).limit(1))
            if cutoff is not None:
                s.execute(delete(TelemetryMessage).where(TelemetryMessage.received_at <= cutoff))

    def _apply(self, s: Session, asset: Asset, outcome: RuleOutcome, topic: str, client_id: str = "",
               unit: str = "") -> None:
        before = s.scalar(select(Finding.status).where(Finding.asset_id == asset.id,
                                                       Finding.rule_id == outcome.rule_id))
        f = apply_outcome(s, asset.id, outcome, "TELEMETRY", ACTOR, None)
        if f is not None and f.status in ("OPEN", "REOPENED") and before in (None, "RESOLVED"):
            audit.record(s, ACTOR, "TELEMETRY_THRESHOLD_EXCEEDED", "finding", f.id, {
                "assetId": asset.id, "ruleId": outcome.rule_id, "topic": topic, "observed": outcome.observed,
                "expected": outcome.expected,
                "message": f"{asset.display_name} ({client_id or 'publisher'}) reported {outcome.observed}"
                           f"{(' ' + unit) if unit else ''} on {topic}; expected {outcome.expected}"})

    def _evaluate(self, s: Session, asset: Asset, topic: str, payload: Any, client_id: str = "") -> None:
        if not isinstance(payload, dict):
            return
        for policy in self.policies():
            rules = [r for r in policy["rules"] if topic_matches(r["topic"], topic)]
            if not rules:
                continue
            for outcome in evaluate_policy({**policy, "rules": rules}, payload, "TELEMETRY"):
                if outcome.status != "UNKNOWN":
                    self._apply(s, asset, outcome, topic, client_id, str(payload.get("unit", "")))

    def staleness_tick(self) -> None:
        scale = self.ctx.settings.telemetry_time_scale
        now = utcnow()
        with self.ctx.db.session() as s:
            for policy in self.policies():
                for rule in policy["rules"]:
                    window = rule.get("stale_after_sec")
                    if not window:
                        continue
                    last = s.scalar(select(TelemetryMessage).where(TelemetryMessage.topic == rule["topic"],
                                                                   TelemetryMessage.asset_id.is_not(None))
                                    .order_by(TelemetryMessage.received_at.desc()).limit(1))
                    if last is None or now - last.received_at < timedelta(seconds=window * scale):
                        continue
                    asset = s.get(Asset, last.asset_id)
                    age = int((now - last.received_at).total_seconds())
                    outcome = RuleOutcome(rule["id"], rule["title"], rule["on_fail"]["status"],
                                          rule["on_fail"].get("severity", rule["severity"]), rule["severity"],
                                          rule["evidence"], f"no message for {age} s", rule.get("expected", ""),
                                          f"telemetry stale on {rule['topic']}", list(rule.get("references", [])),
                                          rule.get("remediation"))
                    self._apply(s, asset, outcome, rule["topic"])


def topics(session: Session) -> list[schemas.TelemetryTopic]:
    latest = (select(TelemetryMessage.topic, func.max(TelemetryMessage.received_at).label("at"),
                     func.count().label("n")).group_by(TelemetryMessage.topic).subquery())
    out = []
    for topic, at, n in session.execute(select(latest.c.topic, latest.c.at, latest.c.n).order_by(latest.c.topic)):
        msg = session.scalar(select(TelemetryMessage).where(TelemetryMessage.topic == topic,
                                                            TelemetryMessage.received_at == at).limit(1))
        asset = session.get(Asset, msg.asset_id) if msg.asset_id else None
        recent = list(session.scalars(select(TelemetryMessage).where(TelemetryMessage.topic == topic)
                                      .order_by(TelemetryMessage.received_at.desc()).limit(30)))
        open_f = []
        if asset is not None:
            open_f = [f.rule_id for f in session.scalars(select(Finding).where(
                Finding.asset_id == asset.id, Finding.source == "TELEMETRY",
                Finding.status.in_(["OPEN", "REOPENED"])))]
        out.append(schemas.TelemetryTopic(topic=topic, client_id=msg.client_id, asset_id=msg.asset_id,
                                          asset_name=asset.display_name if asset else None, last_payload=msg.payload,
                                          last_at=at, messages=n, open_findings=open_f,
                                          recent=[{"at": m.received_at.isoformat(), "payload": m.payload}
                                                  for m in reversed(recent)]))
    return out


def messages(session: Session, topic: str | None, limit: int) -> list[schemas.TelemetryRecord]:
    stmt = select(TelemetryMessage).order_by(TelemetryMessage.received_at.desc()).limit(limit)
    if topic:
        stmt = stmt.where(TelemetryMessage.topic == topic)
    return [schemas.TelemetryRecord.model_validate(m) for m in session.scalars(stmt)]
