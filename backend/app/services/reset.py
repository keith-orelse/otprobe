"""Reset POC: restore seed state. The audit log is append-only and survives (a POC_RESET event is added);
discovery history is kept as archived (never a rogue baseline) unless clear_discovery_history is set."""

from __future__ import annotations

from sqlalchemy import delete, func, select, update

from app import schemas
from app.context import AppContext
from app.core import audit, events
from app.core.clock import utcnow
from app.core.errors import ProblemError
from app.core.principal import CurrentUser
from app.models import (
    Agent,
    AgentTask,
    Approval,
    AssessmentRun,
    Asset,
    AssetField,
    AssetRelationship,
    Deployment,
    DiscoveryJob,
    DiscoveryObservation,
    DriftEvent,
    EnrollmentToken,
    EvidenceChange,
    Finding,
    FindingEvent,
    Heartbeat,
    IdempotencyKey,
    PrecheckResult,
    ProbeResult,
    ProbeRun,
    Removal,
    RuleResult,
    TelemetryMessage,
    WorkflowStep,
)

# children before parents (foreign keys)
KNOWLEDGE_TABLES = [Heartbeat, AgentTask, RuleResult, DriftEvent, EvidenceChange, FindingEvent, Finding,
                    AssessmentRun, EnrollmentToken, PrecheckResult, Removal, Agent, Approval, Deployment,
                    ProbeResult, ProbeRun, AssetRelationship, AssetField, TelemetryMessage, IdempotencyKey]


async def reset(ctx: AppContext, req: schemas.DemoReset, user: CurrentUser) -> schemas.DemoResetResult:
    if req.confirm != "RESET":
        raise ProblemError(422, "confirmation-required", 'Type "RESET" to confirm the reset')
    if ctx.sim_control is None:
        raise ProblemError(404, "not-found", "Simulation controls are not available")
    busy = ctx.runner.active()
    if busy and not req.force:
        raise ProblemError(409, "workflows-running", "Workflows are still running",
                           f"{len(busy)} running ({', '.join(busy[:3])}). Wait, or reset with force=true.")
    await ctx.runner.shutdown()
    cleared: dict[str, int] = {}
    with ctx.db.session() as s:
        revoked = s.execute(update(Agent).where(Agent.revoked_at.is_(None)).values(revoked_at=utcnow())).rowcount
        for model in KNOWLEDGE_TABLES:
            cleared[model.__tablename__] = s.scalar(select(func.count()).select_from(model)) or 0
            s.execute(delete(model))
        s.execute(delete(WorkflowStep).where(WorkflowStep.workflow_kind != "DISCOVERY"))
        if req.clear_discovery_history:
            for model in (DiscoveryObservation, DiscoveryJob):
                cleared[model.__tablename__] = s.scalar(select(func.count()).select_from(model)) or 0
                s.execute(delete(model))
            s.execute(delete(WorkflowStep))
            history = "cleared"
        else:
            s.execute(update(DiscoveryObservation).values(asset_id=None))
            s.execute(update(DiscoveryJob).values(archived=True))
            history = "kept (archived: not used as a rogue baseline)"
        cleared["assets"] = s.scalar(select(func.count()).select_from(Asset)) or 0
        s.execute(delete(Asset))
    ctx.sim_control.reset()
    ctx.task_signals.clear()
    with ctx.db.session() as s:
        audit.record(s, user.actor, "POC_RESET", "poc", None, {
            "cleared": cleared, "discoveryHistory": history, "agentsRevoked": revoked, "force": req.force})
        events.stage(s, "demo.reset", "poc", None, {})
    return schemas.DemoResetResult(status="POC reset to seed state", cleared=cleared, discovery_history=history,
                                   agents_revoked=revoked)
