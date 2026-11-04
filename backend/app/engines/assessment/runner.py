"""Evaluates an assessment run end to end: rules -> score -> findings -> drift -> configuration changes, and writes
deep evidence into the provenance store (stage DEEP)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit, events
from app.core.audit import Actor
from app.core.clock import utcnow
from app.core.correlation import get_correlation_id
from app.core.fields import PROVENANCE_FIELDS
from app.engines.assessment.engine import evaluate_policy, evidence_diff, is_drift, policy_applies, score
from app.engines.assessment.findings import apply_outcome
from app.engines.inventory import upsert_fields
from app.models import AssessmentRun, Asset, AssetField, DriftEvent, EvidenceChange, Policy, RuleResult
from app.rules.conditions import MISSING, nest, resolve_path
from app.workflow.machine import ASSESSMENT


def current_policy(session: Session, key: str) -> Policy | None:
    return session.scalar(select(Policy).where(Policy.key == key).order_by(Policy.loaded_at.desc()).limit(1))


def previous_run(session: Session, run: AssessmentRun) -> AssessmentRun | None:
    """Drift compares like with like: the asset's last evaluated run of the same policy AND source."""
    return session.scalar(select(AssessmentRun).where(
        AssessmentRun.asset_id == run.asset_id, AssessmentRun.policy_key == run.policy_key,
        AssessmentRun.source == run.source, AssessmentRun.status == "EVALUATED", AssessmentRun.id != run.id,
    ).order_by(AssessmentRun.finished_at.desc()).limit(1))


def evaluate_run(session: Session, run: AssessmentRun, evidence: dict[str, Any], actor: Actor) -> dict[str, Any]:
    policy = session.scalar(select(Policy).where(Policy.key == run.policy_key, Policy.version == run.policy_version))
    outcomes = evaluate_policy(policy.document, evidence, run.source)
    run_score, counts = score(outcomes)
    prev = previous_run(session, run)
    prev_status: dict[str, str] = {}
    if prev is not None:
        prev_results = session.scalars(select(RuleResult).where(RuleResult.run_id == prev.id))
        prev_status = {r.rule_id: r.status for r in prev_results}
    now = utcnow()
    drift = []
    for seq, o in enumerate(outcomes, start=1):
        if o.rule_error:
            audit.record(session, actor, "RULE_EVALUATION_ERROR", "assessment", run.id,
                         {"ruleId": o.rule_id, "message": o.message})
        session.add(RuleResult(run_id=run.id, seq=seq, rule_id=o.rule_id, rule_version=run.policy_version,
                               title=o.title, status=o.status, severity=o.severity, evidence_path=o.evidence_path,
                               observed=o.observed, expected=o.expected, message=o.message,
                               previous_status=prev_status.get(o.rule_id), references=o.references))
        finding = apply_outcome(session, run.asset_id, o, run.source, actor, run.id)
        if prev is not None and is_drift(prev_status.get(o.rule_id), o.status):
            before = resolve_path(prev.evidence or {}, o.evidence_path)
            d = DriftEvent(asset_id=run.asset_id, run_id=run.id, previous_run_id=prev.id, rule_id=o.rule_id,
                           from_status=prev_status[o.rule_id], to_status=o.status, evidence_path=o.evidence_path,
                           before=None if before is MISSING else before, after=o.observed,
                           finding_id=finding.id if finding else None, detected_at=now)
            session.add(d)
            session.flush()
            drift.append(d)
            audit.record(session, actor, "CONFIGURATION_DRIFT_DETECTED", "finding", d.finding_id, {
                "assetId": run.asset_id, "ruleId": o.rule_id, "from": d.from_status, "to": d.to_status,
                "evidencePath": o.evidence_path, "before": d.before, "after": d.after, "runId": run.id,
                "driftEventId": d.id})
            events.stage(session, "drift.detected", "asset", run.asset_id, {"ruleId": o.rule_id, "runId": run.id})
    changes = []
    if prev is not None:
        for path, before, after in evidence_diff(prev.evidence, evidence):
            changes.append(EvidenceChange(asset_id=run.asset_id, run_id=run.id, previous_run_id=prev.id, path=path,
                                          before=before, after=after, detected_at=now))
        session.add_all(changes)
    if run.source == "DEEP_AGENT":
        flat = {p: v for p in PROVENANCE_FIELDS if (v := resolve_path(evidence, p)) is not MISSING}
        upsert_fields(session, run.asset_id, flat, "DEEP_AGENT", "DEEP", "ASSESSMENT", run.id, now)
    run.evidence, run.score, run.counts, run.finished_at = evidence, run_score, counts, now
    run.previous_run_id = prev.id if prev else None
    ASSESSMENT.transition(session, run, "EVALUATED", actor, details={
        "score": run_score, "counts": counts, "drift": len(drift), "configurationChanges": len(changes)})
    events.stage(session, "asset.updated", "asset", run.asset_id, {})
    return {"score": run_score, "counts": counts, "drift": len(drift), "changes": len(changes)}


def evaluate_agentless(session: Session, asset: Asset, probe_id: str, actor: Actor) -> list[AssessmentRun]:
    """After an agentless probe, evaluate every compliance policy whose rules accept AGENTLESS evidence."""
    latest: dict[str, AssetField] = {}
    stmt = select(AssetField).where(AssetField.asset_id == asset.id, AssetField.stage == "AGENTLESS")
    for f in session.scalars(stmt):
        if f.field_path not in latest or f.collected_at > latest[f.field_path].collected_at:
            latest[f.field_path] = f
    evidence = nest({p: f.value for p, f in latest.items()})
    runs = []
    for policy in session.scalars(select(Policy).where(Policy.kind == "compliance")):
        if policy.id != current_policy(session, policy.key).id or not policy_applies(policy.document, evidence):
            continue
        if not any("AGENTLESS" in r.get("sources", ["DEEP_AGENT"]) for r in policy.document["rules"]):
            continue
        run = AssessmentRun(asset_id=asset.id, policy_key=policy.key, policy_version=policy.version,
                            source="AGENTLESS", trigger="PROBE", requested_by=actor.name,
                            correlation_id=get_correlation_id(), started_at=utcnow())
        ASSESSMENT.create(session, run, actor, {"assetId": asset.id, "policy": policy.key, "source": "AGENTLESS",
                                                "probeId": probe_id})
        evaluate_run(session, run, evidence, actor)
        runs.append(run)
    return runs
