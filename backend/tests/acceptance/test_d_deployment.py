"""D: requester cannot approve own request; approval -> precheck -> deploy -> enroll -> heartbeat works end to end
through real API calls; the agent runtime is a separate process."""

from __future__ import annotations

import asyncio
import json
import os

import pytest
from sqlalchemy import select

from app.core.crypto import sha256_hex
from app.models import Agent, AuditEvent, EnrollmentToken
from tests.flows import approve, deploy, precheck, prepared, request_deployment

pytestmark = pytest.mark.acceptance
EWS = "192.168.20.13"


def body(asset: dict) -> dict:
    return {"assetId": asset["id"], "packageId": "pkg-probe-agent-1.1.0", "purpose": "Monitoring"}


async def test_end_to_end_with_separate_agent_process(live, db_path):
    h, proc = live
    await prepared(h)
    asset = await h.asset_by_ip(EWS)
    assert asset["deployAgent"]["enabled"] is True

    dep = await request_deployment(h, EWS)
    assert dep["status"] == "PENDING_APPROVAL" and dep["approval"]["status"] == "PENDING"
    assert dep["actions"]["deploy"] == {"enabled": False, "reason": "Awaiting approval"}

    # requester cannot approve own request (operator lacks the role; checked separately for admins below)
    r = await h.post(f"/approvals/{dep['approval']['id']}/approve")
    assert r.status_code == 403

    await approve(h, dep)
    pre = await precheck(h, dep["id"])
    assert pre["status"] == "PRECHECK_PASSED", pre["precheck"]
    assert [c["check"] for c in pre["precheck"]] == [
        "REACHABLE", "HOSTNAME_VERIFIED", "WINRM_AVAILABLE", "AUTHENTICATION", "PACKAGE_COMPATIBLE", "DISK_SPACE",
        "EXISTING_AGENT", "SERVER_CONNECTIVITY", "REBOOT_REQUIRED"]
    assert all(c["status"] == "PASS" for c in pre["precheck"])
    assert pre["actions"]["deploy"]["enabled"] is True

    done = await deploy(h, dep["id"])
    assert done["status"] == "COMPLETED", (done["failureCode"], done["failureDetail"])
    steps = [(s["name"], s["status"]) for s in done["steps"]]
    assert steps == [(n, "OK") for n in ("CONNECT", "WINRM_SESSION", "RETRIEVE_CREDENTIAL", "TRANSFER_PACKAGE",
                                         "VERIFY_HASH", "INSTALL", "SERVICE_CREATED", "START_SERVICE",
                                         "AWAIT_ENROLLMENT")]

    agent = await h.wait_for(f"/agents/{done['agentId']}", lambda a: a["status"] == "ONLINE")
    seq0 = (await h.get(f"/agents/{agent['id']}/heartbeats"))["total"]
    await asyncio.sleep(1.6)   # heartbeat interval is 0.5 s in this test
    assert (await h.get(f"/agents/{agent['id']}/heartbeats"))["total"] >= seq0 + 2
    assert (await h.asset_by_ip(EWS))["agentState"] == "ONLINE"

    # the agent is a separate OS process talking over HTTP
    assert proc.poll() is None and proc.pid != os.getpid()

    with h.ctx.db.session() as s:
        row = s.get(Agent, agent["id"])
        assert row.credential_hash and len(row.credential_hash) == 64 and row.credential_prefix.startswith("agt_")
        tok = s.scalar(select(EnrollmentToken).where(EnrollmentToken.deployment_id == dep["id"]))
        assert tok.used_at is not None
        actions = [(e.action, e.actor_name) for e in s.scalars(
            select(AuditEvent).where(AuditEvent.entity_id.in_([dep["id"], dep["approval"]["id"], agent["id"]]))
            .order_by(AuditEvent.seq))]
    names = [a for a, _ in actions]
    for expected in ("DEPLOYMENT_REQUESTED", "APPROVAL_GRANTED", "DEPLOYMENT_APPROVED", "PRECHECK_STARTED",
                     "PRECHECK_PASSED", "DEPLOYMENT_STARTED", "ENROLLMENT_TOKEN_ISSUED", "PACKAGE_TRANSFERRED",
                     "AGENT_REGISTERED", "AGENT_INSTALLED", "AGENT_CREDENTIAL_ISSUED", "AGENT_ENROLLED",
                     "DEPLOYMENT_COMPLETED"):
        assert expected in names, expected
    assert ("DEPLOYMENT_REQUESTED", "operator") in actions and ("APPROVAL_GRANTED", "approver") in actions
    assert (await h.get("/audit-events/verify"))["valid"] is True


async def test_self_approval_forbidden_even_for_admin(discovered):
    h = discovered
    await h.probe(EWS)
    dep = await request_deployment(h, EWS, requester="admin")
    r = await h.post(f"/approvals/{dep['approval']['id']}/approve")
    assert r.status_code == 403 and r.json()["type"].endswith("self-approval-forbidden")
    appr = await h.get(f"/approvals/{dep['approval']['id']}")
    assert appr["status"] == "PENDING"
    assert appr["actions"]["approve"] == {"enabled": False,
                                          "reason": "You requested this; another approver must decide"}
    denied = (await h.get("/audit-events", params={"action": "APPROVAL_SELF_DENIED"}))["items"]
    assert denied and denied[0]["actorName"] == "admin" and denied[0]["entityId"] == dep["approval"]["id"]
    await approve(h, dep, "approver")   # a different approver can


async def test_rbac(discovered):
    h = discovered
    await h.probe(EWS)
    asset = await h.asset_by_ip(EWS)
    await h.login("approver")
    r = await h.post("/deployments", body(asset))
    assert r.status_code == 403   # approvers decide, they do not request
    r = await h.post("/discovery/jobs", {"targets": ["192.168.20.0/24"]})
    assert r.status_code == 403
    dep = await request_deployment(h, EWS)
    await approve(h, dep)
    await h.login("approver")
    r = await h.post(f"/deployments/{dep['id']}/precheck")
    assert r.status_code == 403 and "you are APPROVER" in r.json()["detail"]
    await h.login("operator")
    r = await h.post(f"/deployments/{dep['id']}/deploy")
    assert r.status_code == 409 and r.json()["detail"] == "Precheck must pass first"
    h.client.headers.pop("Authorization")
    r = await h.client.get("/api/v1/assets")
    assert r.status_code == 401 and r.headers["content-type"] == "application/problem+json"


async def test_plc_and_critical_assets(discovered):
    h = discovered
    await h.probe("192.168.10.10")
    await h.probe("192.168.20.139")
    plc = await h.asset_by_ip("192.168.10.10")
    r = await h.post("/deployments", body(plc))
    assert r.status_code == 422
    assert r.json()["detail"] == "Traditional PLCs are handled agentless/read-only in this POC."
    scada = await h.asset_by_ip("192.168.20.139")
    r = await h.post("/deployments", body(scada))
    assert r.status_code == 422 and r.json()["type"].endswith("maintenance-window-required")
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    dep = await request_deployment(h, "192.168.20.139", maintenanceWindow={
        "start": now.isoformat(), "end": (now + timedelta(hours=2)).isoformat()})
    await h.login("approver")
    r = await h.post(f"/approvals/{dep['approval']['id']}/approve")
    assert r.status_code == 422   # critical asset: approver must give a reason
    await approve(h, dep, reason="Window agreed with line 1 supervisor")


async def test_checksum_failure_installs_nothing(discovered):
    h = discovered
    await h.probe(EWS)
    dep = await request_deployment(h, EWS)
    await approve(h, dep)
    await precheck(h, dep["id"])
    h.ctx.sim_control.set_fault("dev-ews01", "package_checksum_mismatch", {}, "test")
    failed = await deploy(h, dep["id"])
    assert failed["status"] == "FAILED" and failed["failureCode"] == "HASH_MISMATCH"
    assert failed["failureDetail"].startswith("Package hash mismatch")
    assert failed["agentId"] is None and (await h.asset_by_ip(EWS))["agentState"] == "NOT_INSTALLED"
    dev = h.ctx.extras["world"].device("dev-ews01")
    assert "agent" not in dev.state.get("files", {}) and not dev.state["files"].get("staged")
    assert (await h.get("/audit-events", params={"action": "DEPLOY_HASH_FAIL"}))["total"] == 1
    assert failed["actions"]["retry"]["enabled"] is True
    retry = (await h.post(f"/deployments/{dep['id']}/retry", expect=201)).json()
    assert retry["retryOfId"] == dep["id"] and retry["status"] == "PENDING_APPROVAL"


async def test_enrollment_token_is_single_use(discovered):
    h = discovered
    await h.probe(EWS)
    dep = await request_deployment(h, EWS)
    await approve(h, dep)
    await precheck(h, dep["id"])
    done = await deploy(h, dep["id"], until=("ENROLLING", "FAILED"))   # no agent runtime in this test
    assert done["status"] == "ENROLLING"
    bundle = h.ctx.extras["world"].device("dev-ews01").state["files"]["enroll_bundle"]
    body = {"enrollmentToken": bundle["enrollmentToken"], "hostname": "eng-ws-01", "hostFingerprint": "x",
            "agentVersion": "1.1.0"}
    with h.ctx.db.session() as s:   # only the hash is stored
        assert s.scalar(select(EnrollmentToken.token_hash)) == sha256_hex(bundle["enrollmentToken"])
    first = await h.client.post("/api/v1/agents/enroll", json=body)
    assert first.status_code == 201
    replay = await h.client.post("/api/v1/agents/enroll", json=body)
    assert replay.status_code == 401 and replay.json()["detail"] == "Enrollment token already used"
    cred = first.json()["agentCredential"]
    with h.ctx.db.session() as s:   # credential never stored in plaintext anywhere
        assert all(cred not in json.dumps(e.details) for e in s.scalars(select(AuditEvent)))
    r = await h.client.post(f"/api/v1/agents/{first.json()['agentId']}/heartbeat",
                            json={"seq": 1, "agentTime": "2026-11-02T10:00:00Z"},
                            headers={"Authorization": "Bearer agt_wrong"})
    assert r.status_code == 401


async def test_agent_heartbeat_before_enrolling_still_completes(discovered):
    """Regression: the agent can enroll and heartbeat while the engine is still finishing its last deploy step
    (deployment DEPLOYING). The deployment must still complete instead of timing out as ENROLLMENT_FAILED."""
    from app.engines.deployment import engine as deploy_engine

    h = discovered
    await h.probe(EWS)
    dep = await request_deployment(h, EWS)
    await approve(h, dep)
    await precheck(h, dep["id"])
    original = deploy_engine.DeploymentEngine._install

    async def install_then_agent_races(self, dep_id, tracker, winrm, session, ref, asset_id):
        real_execute = winrm.execute

        async def execute(sess, op, params):
            res = await real_execute(sess, op, params)
            if op.value == "START_SERVICE":   # the agent wakes up right here, before the engine moves to ENROLLING
                bundle = h.ctx.extras["world"].device("dev-ews01").state["files"]["enroll_bundle"]
                body = {"enrollmentToken": bundle["enrollmentToken"], "hostname": "eng-ws-01", "hostFingerprint": "x",
                        "agentVersion": "1.1.0"}
                enrolled = (await h.client.post("/api/v1/agents/enroll", json=body)).json()
                r = await h.client.post(f"/api/v1/agents/{enrolled['agentId']}/heartbeat",
                                        json={"seq": 1, "agentTime": "2026-11-04T10:00:00Z"},
                                        headers={"Authorization": f"Bearer {enrolled['agentCredential']}"})
                assert r.status_code == 204
            return res

        winrm.execute = execute
        try:
            return await original(self, dep_id, tracker, winrm, session, ref, asset_id)
        finally:
            winrm.execute = real_execute

    deploy_engine.DeploymentEngine._install = install_then_agent_races
    try:
        done = await deploy(h, dep["id"])
    finally:
        deploy_engine.DeploymentEngine._install = original
    assert done["status"] == "COMPLETED", (done["failureCode"], done["failureDetail"])
    assert next(s for s in done["steps"] if s["name"] == "AWAIT_ENROLLMENT")["status"] == "OK"
