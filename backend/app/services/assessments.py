"""Deep assessments: request -> task (long-poll dispatch) -> agent evidence -> server-side evaluation.
Also the assessment scheduler, task timeouts and read models."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import schemas
from app.context import AppContext
from app.core import audit
from app.core.audit import system
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.core.errors import ProblemError, not_found
from app.core.principal import CurrentAgent, CurrentUser
from app.engines.assessment.runner import current_policy, evaluate_run
from app.models import (
    Agent,
    AgentTask,
    AssessmentRun,
    Asset,
    AssetField,
    DriftEvent,
    EvidenceChange,
    Finding,
    Policy,
    RuleResult,
)
from app.rules.book import RuleBook
from app.services.common import paginate
from app.workflow.machine import ASSESSMENT, TASK

SCHEDULER = system("assessment-scheduler")
EVALUATOR = system("assessment-engine")
DEFAULT_POLICY = "windows-engineering-baseline"
POLICY_BY_OS = {"windows": "windows-engineering-baseline", "linux": "linux-host-baseline"}
COLLECTORS = ["os", "hardware", "firewall", "antivirus", "patches", "software", "services", "local_admins",
              "password_policy", "audit", "usb", "network", "agent"]
# The Go agent (it reports a platform at enrollment) gets the collector set of its policy, which includes
# collectors the simulated agent does not have.
GO_AGENT_COLLECTORS = {
    "windows-engineering-baseline": [*COLLECTORS, "rdp", "smb"],
    "linux-host-baseline": ["os", "firewall", "packages", "patches", "services", "admins", "password_policy", "ssh",
                            "audit", "usb", "network", "agent"],
}


def policy_for(session: Session, asset: Asset) -> str:
    """The compliance policy for an asset's operating system (Windows baseline when unknown)."""
    family = session.scalar(select(AssetField.value).where(AssetField.asset_id == asset.id,
                                                           AssetField.field_path == "os.family"))
    return POLICY_BY_OS.get(family, DEFAULT_POLICY)


def collectors_for(agent: Agent, policy_key: str) -> list[str]:
    if agent.platform and policy_key in GO_AGENT_COLLECTORS:
        return GO_AGENT_COLLECTORS[policy_key]
    return COLLECTORS
ASSESSABLE = ("ONLINE", "STALE", "OFFLINE")
ACTIVE_RUN = ("QUEUED", "RUNNING")


# ---------------------------------------------------------------- policies
def sync_policies(session: Session, book: RuleBook) -> None:
    """Rules are data: each (policy, version) is stored as loaded; a changed file under the same version is updated
    and audited."""
    for key, doc in book.policies.items():
        digest = hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()
        version = doc["policy"]["version"]
        row = session.scalar(select(Policy).where(Policy.key == key, Policy.version == version))
        if row is None:
            session.add(Policy(key=key, version=version, name=doc["policy"]["name"], kind=doc["policy"]["kind"],
                               digest=digest, document=doc, source_file=f"rules/{key}"))
            audit.record(session, system("rule-loader"), "POLICY_LOADED", "policy", key,
                         {"version": version, "rules": len(doc["rules"]), "digest": digest[:12]})
        elif row.digest != digest:
            row.document, row.digest, row.loaded_at = doc, digest, utcnow()
            audit.record(session, system("rule-loader"), "POLICY_UPDATED", "policy", key,
                         {"version": version, "digest": digest[:12]})
    session.flush()


def list_policies(session: Session) -> list[schemas.PolicyInfo]:
    out = []
    for p in session.scalars(select(Policy).order_by(Policy.key, Policy.loaded_at)):
        out.append(schemas.PolicyInfo(key=p.key, version=p.version, name=p.name, kind=p.kind, digest=p.digest,
                                      loaded_at=p.loaded_at, rules=[
                                          schemas.RuleInfo(id=r["id"], title=r["title"], severity=r["severity"],
                                                           sources=r.get("sources", ["DEEP_AGENT"]),
                                                           evidence=r["evidence"], condition=r["condition"],
                                                           on_fail=r["on_fail"]["status"],
                                                           references=r.get("references", []))
                                          for r in p.document["rules"]]))
    return out


# ---------------------------------------------------------------- request & dispatch
def run_action(session: Session, asset: Asset) -> schemas.ActionState:
    agent = session.get(Agent, asset.current_agent_id) if asset.current_agent_id else None
    if agent is None or agent.status not in ASSESSABLE:
        return schemas.ActionState(enabled=False, reason="Deep assessment needs an enrolled agent")
    active = session.scalar(select(AssessmentRun).where(AssessmentRun.asset_id == asset.id,
                                                        AssessmentRun.source == "DEEP_AGENT",
                                                        AssessmentRun.status.in_(ACTIVE_RUN)))
    if active is not None:
        return schemas.ActionState(enabled=False, reason=f"Assessment {active.id[:8]} is {active.status}")
    if agent.status != "ONLINE":
        return schemas.ActionState(enabled=True, reason=f"Agent is {agent.status}: the task will wait in the queue")
    return schemas.ActionState(enabled=True, reason="Run the compliance baseline for this OS on the agent")


def _create_run(ctx: AppContext, session: Session, asset: Asset, agent: Agent, trigger: str, actor, policy_key: str
                ) -> AssessmentRun:
    policy = current_policy(session, policy_key)
    if policy is None:
        raise ProblemError(422, "unknown-policy", "Unknown policy", policy_key)
    run = AssessmentRun(asset_id=asset.id, agent_id=agent.id, policy_key=policy.key, policy_version=policy.version,
                        source="DEEP_AGENT", trigger=trigger, requested_by=actor.name,
                        correlation_id=get_correlation_id())
    ASSESSMENT.create(session, run, actor, {"assetId": asset.id, "agentId": agent.id, "policy": policy.key,
                                            "trigger": trigger})
    task = AgentTask(agent_id=agent.id, kind="RUN_ASSESSMENT", assessment_run_id=run.id,
                     correlation_id=run.correlation_id,
                     payload={"policyId": policy.key, "policyVersion": policy.version,
                              "collectors": collectors_for(agent, policy.key),
                              "assessmentRunId": run.id})
    TASK.create(session, task, actor, {"agentId": agent.id, "kind": task.kind, "runId": run.id})
    return run


def request(ctx: AppContext, session: Session, asset_id: str, user: CurrentUser, policy_key: str | None
            ) -> tuple[dict[str, Any], Any]:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise not_found("Asset", asset_id)
    action = run_action(session, asset)
    if not action.enabled:
        raise ProblemError(409, "assessment-not-possible", "Assessment not possible", action.reason)
    agent = session.get(Agent, asset.current_agent_id)
    run = _create_run(ctx, session, asset, agent, "MANUAL", user.actor, policy_key or policy_for(session, asset))
    agent_id = agent.id
    return run_schema(session, run).dump(), lambda: ctx.signal(agent_id).set()


def _dispatch(ctx: AppContext, agent_id: str) -> list[dict[str, Any]]:
    with ctx.db.session() as s:
        agent = s.get(Agent, agent_id)
        task = s.scalar(select(AgentTask).where(AgentTask.agent_id == agent_id, AgentTask.status == "QUEUED")
                        .order_by(AgentTask.created_at).limit(1))
        if task is None:
            return []
        now = utcnow()
        actor = audit.Actor("AGENT", f"agent:{agent_id[:8]}", agent_id)
        task.dispatched_at, task.deadline_at = now, now + timedelta(seconds=ctx.settings.assessment_timeout_sec)
        TASK.transition(s, task, "DISPATCHED", actor)
        run = s.get(AssessmentRun, task.assessment_run_id)
        run.started_at = now
        ASSESSMENT.transition(s, run, "RUNNING", actor, details={"taskId": task.id, "agentVersion": agent.version})
        return [{"taskId": task.id, "kind": task.kind, "correlationId": task.correlation_id,
                 "deadline": task.deadline_at.isoformat(), "payload": task.payload}]


async def poll_tasks(ctx: AppContext, agent: CurrentAgent, wait_sec: int) -> list[dict[str, Any]]:
    """Long-poll: return as soon as a task is queued for this agent, or empty after wait_sec."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + wait_sec
    signal = ctx.signal(agent.id)
    while True:
        signal.clear()
        tasks = _dispatch(ctx, agent.id)
        remaining = deadline - loop.time()
        if tasks or remaining <= 0:
            return tasks
        try:
            await asyncio.wait_for(signal.wait(), remaining)
        except asyncio.TimeoutError:
            return []


def submit_evidence(ctx: AppContext, agent: CurrentAgent, task_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    with ctx.db.session() as s:
        task = s.get(AgentTask, task_id)
        if task is None or task.agent_id != agent.id:
            raise not_found("Task", task_id)
        if task.status != "DISPATCHED":
            raise ProblemError(409, "invalid-state-transition", "Task is not awaiting evidence",
                               f"Task {task_id} is {task.status}")
        task.completed_at = utcnow()
        TASK.transition(s, task, "COMPLETED", agent.actor, details={"evidenceKeys": sorted(evidence)})
        run = s.get(AssessmentRun, task.assessment_run_id)
        audit.record(s, agent.actor, "ASSESSMENT_EVIDENCE_UPLOADED", "assessment", run.id,
                     {"collectors": evidence.get("collectors", {}), "taskId": task_id})
        result = evaluate_run(s, run, evidence, EVALUATOR)
        return {"runId": run.id, **result}


# ---------------------------------------------------------------- scheduler & timeouts (called by the watchdog)
def scheduler_tick(ctx: AppContext) -> None:
    interval = ctx.settings.assessment_interval_sec
    now = utcnow()
    with ctx.db.session() as s:
        for agent in s.scalars(select(Agent).where(Agent.status == "ONLINE")):
            asset = s.get(Asset, agent.asset_id)
            last = s.scalar(select(func.max(AssessmentRun.created_at)).where(
                AssessmentRun.asset_id == asset.id, AssessmentRun.source == "DEEP_AGENT"))
            reference = last or agent.enrolled_at
            if reference is None or (now - reference).total_seconds() < interval:
                continue
            if not run_action(s, asset).enabled:
                continue
            _create_run(ctx, s, asset, agent, "SCHEDULED", SCHEDULER, policy_for(s, asset))
            s.flush()
            ctx.signal(agent.id).set()


def timeout_tick(ctx: AppContext) -> None:
    now = utcnow()
    with ctx.db.session() as s:
        for task in s.scalars(select(AgentTask).where(AgentTask.status == "DISPATCHED", AgentTask.deadline_at < now)):
            detail = (f"Assessment timed out: no evidence received from agent within "
                      f"{int(ctx.settings.assessment_timeout_sec)} s")
            task.completed_at = now
            TASK.transition(s, task, "TIMED_OUT", SCHEDULER, detail)
            run = s.get(AssessmentRun, task.assessment_run_id)
            run.error, run.finished_at = detail, now
            ASSESSMENT.transition(s, run, "TIMED_OUT", SCHEDULER, detail)


# ---------------------------------------------------------------- read models
def run_schema(session: Session, run: AssessmentRun, detail: bool = False) -> schemas.AssessmentRun:
    out = schemas.AssessmentRun.model_validate(run)
    asset = session.get(Asset, run.asset_id)
    out.asset_name = asset.display_name if asset else None
    if detail:
        out.results = [schemas.RuleResult.model_validate(r) for r in session.scalars(
            select(RuleResult).where(RuleResult.run_id == run.id).order_by(RuleResult.seq))]
        out.drift_events = [drift_schema(session, d) for d in session.scalars(
            select(DriftEvent).where(DriftEvent.run_id == run.id))]
        out.evidence_changes = [schemas.EvidenceChange.model_validate(c) for c in session.scalars(
            select(EvidenceChange).where(EvidenceChange.run_id == run.id).order_by(EvidenceChange.path))]
    else:
        out.evidence = None
    return out


def drift_schema(session: Session, d: DriftEvent) -> schemas.DriftEvent:
    out = schemas.DriftEvent.model_validate(d)
    asset = session.get(Asset, d.asset_id)
    out.asset_name = asset.display_name if asset else None
    return out


def list_runs(session: Session, limit: int, cursor: str | None, asset_id: str | None, source: str | None
              ) -> schemas.Page:
    stmt = select(AssessmentRun).order_by(AssessmentRun.created_at.desc())
    if asset_id:
        stmt = stmt.where(AssessmentRun.asset_id == asset_id)
    if source:
        stmt = stmt.where(AssessmentRun.source == source)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.AssessmentRun](items=[run_schema(session, r) for r in rows], next_cursor=nxt,
                                               total=total)


def get_run(session: Session, run_id: str) -> schemas.AssessmentRun:
    run = session.get(AssessmentRun, run_id)
    if run is None:
        raise not_found("Assessment run", run_id)
    return run_schema(session, run, detail=True)


def list_drift(session: Session, limit: int, cursor: str | None, asset_id: str | None) -> schemas.Page:
    stmt = select(DriftEvent).order_by(DriftEvent.detected_at.desc())
    if asset_id:
        stmt = stmt.where(DriftEvent.asset_id == asset_id)
    rows, nxt, total = paginate(session, stmt, limit, cursor)
    return schemas.Page[schemas.DriftEvent](items=[drift_schema(session, d) for d in rows], next_cursor=nxt,
                                            total=total)


def compliance(ctx: AppContext, session: Session, asset: Asset) -> schemas.Compliance:
    latest = session.scalar(select(AssessmentRun).where(AssessmentRun.asset_id == asset.id,
                                                        AssessmentRun.status == "EVALUATED")
                            .order_by(AssessmentRun.finished_at.desc()).limit(1))
    last_deep = session.scalar(select(AssessmentRun).where(AssessmentRun.asset_id == asset.id,
                                                           AssessmentRun.source == "DEEP_AGENT")
                               .order_by(AssessmentRun.created_at.desc()).limit(1))
    open_findings = session.scalar(select(func.count()).select_from(Finding).where(
        Finding.asset_id == asset.id, Finding.status.in_(["OPEN", "REOPENED"]))) or 0
    agent = session.get(Agent, asset.current_agent_id) if asset.current_agent_id else None
    nxt = None
    if agent is not None and agent.status == "ONLINE":
        ref = last_deep.created_at if last_deep else agent.enrolled_at
        if ref is not None:
            nxt = ref + timedelta(seconds=ctx.settings.assessment_interval_sec)
    return schemas.Compliance(
        score=latest.score if latest else None, counts=latest.counts if latest else {},
        source=latest.source if latest else None, last_run_id=latest.id if latest else None,
        last_assessment_at=latest.finished_at if latest else None,
        last_deep_status=last_deep.status if last_deep else None, next_assessment_at=nxt,
        open_findings=open_findings, run_action=run_action(session, asset))
