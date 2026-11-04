import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ErrorBox, Panel, Pill, Progress, StepList, time } from "../components/ui";
import { Lifecycle } from "../components/visual";
import type { ActionState, Deployment, Page } from "../types";

export function Deployments() {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["deployments", "list"], queryFn: () => apiGet<Page<Deployment>>("/deployments", { limit: 50 }) });
  return (
    <div className="page">
      <p className="hint">Request a deployment from an eligible asset's page. Flow: request → approval (by someone else) →
        precheck → deploy → the agent enrolls itself (outbound) → first heartbeat.</p>
      <ErrorBox error={q.error} />
      <table className="dense clickable">
        <thead><tr><th>Requested</th><th>Asset</th><th>Package</th><th>Status</th><th>Requested by</th><th>Approval</th><th>Failure</th></tr></thead>
        <tbody>{q.data?.items.map((d) => (
          <tr key={d.id} onClick={() => nav(`/deployments/${d.id}`)}>
            <td className="mono">{time(d.createdAt)}</td><td>{d.assetName}</td>
            <td>{d.package?.name} {d.package?.version}</td><td><Pill value={d.status} /></td><td>{d.requestedBy}</td>
            <td><Pill value={d.approval?.status} /> {d.approval?.decidedBy && <span className="muted">{d.approval.decidedBy}</span>}</td>
            <td className="mono small">{d.failureCode ?? ""}</td>
          </tr>))}
          {q.data?.items.length === 0 && <tr><td colSpan={7} className="muted">No deployments yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function ActionButton({ label, state, onClick, primary }: { label: string; state?: ActionState; onClick: () => void;
  primary?: boolean }) {
  if (!state) return null;
  return (
    <div className="action-with-reason">
      <button className={`btn ${primary ? "btn-primary" : ""}`} disabled={!state.enabled} title={state.reason}
        onClick={onClick}>{label}</button>
      <div className={state.enabled ? "reason reason-ok" : "reason"}>{state.reason}</div>
    </div>
  );
}

const DEPLOY_STAGES = [
  { key: "requested", label: "Requested" }, { key: "approval", label: "Approval" }, { key: "precheck", label: "Precheck" },
  { key: "deploy", label: "Deploy" }, { key: "enroll", label: "Enrollment" }, { key: "done", label: "Completed" },
];

/** Maps the deployment state machine onto lifecycle stages (current stage, and where it stopped if it failed). */
function deployStage(d: Deployment): { current: number; failedAt?: number; failedLabel?: string } {
  switch (d.status) {
    case "REQUESTED": case "PENDING_APPROVAL": return { current: 1 };
    case "REJECTED": return { current: 1, failedAt: 1, failedLabel: "Rejected" };
    case "APPROVED": case "PRECHECK_RUNNING": return { current: 2 };
    case "PRECHECK_FAILED": return { current: 2, failedAt: 2, failedLabel: "Precheck failed" };
    case "PRECHECK_PASSED": case "DEPLOYING": return { current: 3 };
    case "ENROLLING": return { current: 4 };
    case "COMPLETED": return { current: 5 };
    default: return d.enrollingSince ? { current: 4, failedAt: 4, failedLabel: "Enrollment failed" }
      : { current: 3, failedAt: 3, failedLabel: "Deploy failed" };
  }
}

export function DeploymentDetail() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["deployments", id], queryFn: () => apiGet<Deployment>(`/deployments/${id}`) });
  const act = useMutation({
    mutationFn: (action: string) => apiAction<Deployment>(`/deployments/${id}/${action}`),
    onSuccess: (d, action) => {
      qc.invalidateQueries({ queryKey: ["deployments"] });
      if (action === "retry") nav(`/deployments/${d.id}`);
    },
  });
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d) return <div className="muted">Loading…</div>;
  const transfer = d.steps.find((s) => s.name === "TRANSFER_PACKAGE" && s.status === "RUNNING");
  return (
    <div className="page">
      <div className="crumbs"><Link to="/deployments">Deployments</Link> / {d.id.slice(0, 8)}</div>
      <div className="asset-head">
        <div>
          <h1>Deploy {d.package?.name} {d.package?.version} → <Link to={`/assets/${d.assetId}`}>{d.assetName}</Link> <Pill value={d.status} /></h1>
          <div className="meta"><span>requested by {d.requestedBy}</span><span>{time(d.createdAt)}</span>
            <span className="mono">correlation {d.correlationId}</span>
            {d.retryOfId && <Link to={`/deployments/${d.retryOfId}`}>retry of {d.retryOfId.slice(0, 8)}</Link>}</div>
        </div>
        <div className="actions">
          <ActionButton label="RUN PRECHECK" state={d.actions.precheck} onClick={() => act.mutate("precheck")} />
          <ActionButton label="DEPLOY AGENT" primary state={d.actions.deploy} onClick={() => act.mutate("deploy")} />
          {d.status === "FAILED" && <ActionButton label="RETRY" state={d.actions.retry} onClick={() => act.mutate("retry")} />}
        </div>
      </div>
      <Lifecycle stages={DEPLOY_STAGES} {...deployStage(d)} />
      <ErrorBox error={act.error} />
      {d.failureCode && <div className="error-box"><b>{d.failureCode}</b>: {d.failureDetail}</div>}
      <div className="grid-2">
        <Panel title="Approval">
          {d.approval && (
            <table className="kv"><tbody>
              <tr><th>Status</th><td><Pill value={d.approval.status} /></td></tr>
              <tr><th>Requester</th><td>{d.approval.requestedBy}</td></tr>
              <tr><th>Purpose</th><td>{d.approval.purpose}</td></tr>
              <tr><th>Criticality</th><td><Pill value={d.approval.criticality} /></td></tr>
              <tr><th>Maintenance window</th><td>{d.approval.maintenanceWindow
                ? `${time(d.approval.maintenanceWindow.start)} – ${time(d.approval.maintenanceWindow.end)}` : "not required"}</td></tr>
              <tr><th>Decision</th><td>{d.approval.decidedBy ? `${d.approval.status.toLowerCase()} by ${d.approval.decidedBy}` : "—"}</td></tr>
              <tr><th>Decided</th><td>{time(d.approval.decidedAt)}</td></tr>
              <tr><th>Reason</th><td>{d.approval.reason ?? "—"}</td></tr>
              {d.approval.status === "PENDING" && <tr><td colSpan={2}><Link to="/approvals">Go to approvals →</Link></td></tr>}
            </tbody></table>)}
        </Panel>
        <Panel title={<>Precheck {d.precheckRunNo > 0 && <span className="muted">run #{d.precheckRunNo}</span>}</>}>
          {d.precheck.length ? (
            <table className="dense"><tbody>{d.precheck.map((c) => (
              <tr key={c.check}><td className="mono small">{c.check}</td><td><Pill value={c.status === "WARN" ? "WARNING" : c.status === "PASS" ? "OK" : "FAILED"} title={c.status} /></td>
                <td>{c.detail}</td></tr>))}
            </tbody></table>) : <p className="muted">{d.status === "PRECHECK_RUNNING" ? "Running…" : "Not run yet."}</p>}
        </Panel>
        <Panel title="Deployment steps">
          {transfer?.progress != null && <Progress value={Math.round(transfer.progress * 100)} />}
          {d.steps.length ? <StepList steps={d.steps} /> : <p className="muted">Starts when DEPLOY AGENT is pressed after a passed precheck.</p>}
          {d.agentId && <Link to={`/agents/${d.agentId}`}>Agent {d.agentId.slice(0, 8)} →</Link>}
        </Panel>
      </div>
    </div>
  );
}
