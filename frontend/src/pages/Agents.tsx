import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ErrorBox, Panel, Pill, StepList, time } from "../components/ui";
import { Lifecycle } from "../components/visual";
import type { Agent, HeartbeatRecord, Page, Removal } from "../types";

/** Seconds since the last heartbeat, ticking locally between server refreshes (display only). */
function useSince(ts: string | null): number | null {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(t); }, []);
  return ts ? Math.max(0, Math.round((now - Date.parse(ts)) / 1000)) : null;
}

function LastHeartbeat({ ts }: { ts: string | null }) {
  const s = useSince(ts);
  return <span className="mono">{s == null ? "—" : `${s} seconds ago`}</span>;
}

export function Agents() {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["agents", "list"], queryFn: () => apiGet<Page<Agent>>("/agents", { limit: 100 }),
    refetchInterval: 3000 });
  return (
    <div className="page">
      <p className="hint">Agents are outbound-only: they enroll, heartbeat and poll for tasks over HTTPS. The server
        never connects to them. STALE after 3 missed heartbeats, OFFLINE after 6.</p>
      <ErrorBox error={q.error} />
      <table className="dense clickable">
        <thead><tr><th>Agent</th><th>Asset</th><th>Status</th><th>Last heartbeat</th><th className="num">Missed</th>
          <th>Version</th><th>Credential</th><th>Enrolled</th></tr></thead>
        <tbody>{q.data?.items.map((a) => (
          <tr key={a.id} onClick={() => nav(`/agents/${a.id}`)}>
            <td className="mono">{a.id.slice(0, 8)}</td><td>{a.assetName}</td><td><Pill value={a.status} /></td>
            <td><LastHeartbeat ts={a.lastHeartbeatAt} /></td><td className="num">{a.missedHeartbeats}</td>
            <td>{a.version}</td><td className="mono">{a.credentialPrefix ? `${a.credentialPrefix}…` : "—"}</td>
            <td>{time(a.enrolledAt)}</td>
          </tr>))}
          {q.data?.items.length === 0 && <tr><td colSpan={8} className="muted">No agents. Deploy one from an eligible asset.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

export function AgentDetail() {
  const { id = "" } = useParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const remove = useMutation({
    mutationFn: () => apiAction<Removal>(`/agents/${id}/removals`, { purpose: "Decommission POC agent" }),
    onSuccess: (r) => nav(`/removals/${r.id}`),
  });
  const restart = useMutation({
    mutationFn: () => apiAction<{ message: string }>(`/agents/${id}/restart`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["agents"] }),
  });
  const a = useQuery({ queryKey: ["agents", id], queryFn: () => apiGet<Agent>(`/agents/${id}`), refetchInterval: 2000 });
  const hb = useQuery({ queryKey: ["agents", id, "hb"], queryFn: () => apiGet<Page<HeartbeatRecord>>(`/agents/${id}/heartbeats`, { limit: 20 }),
    refetchInterval: 2000 });
  if (a.error) return <ErrorBox error={a.error} />;
  const ag = a.data;
  if (!ag) return <div className="muted">Loading…</div>;
  return (
    <div className="page">
      <div className="crumbs"><Link to="/agents">Agents</Link> / {ag.id.slice(0, 8)}</div>
      <div className="asset-head">
        <h1>Probe Agent {ag.id.slice(0, 8)} on <Link to={`/assets/${ag.assetId}`}>{ag.assetName}</Link> <Pill value={ag.status} /></h1>
        <div className="actions">
          <div className="action-with-reason">
            <button className="btn" disabled={!ag.actions.restart?.enabled || restart.isPending} title={ag.actions.restart?.reason}
              onClick={() => restart.mutate()}>RESTART AGENT SERVICE</button>
            <div className="reason reason-ok">{ag.actions.restart?.reason}</div>
          </div>
          <div className="action-with-reason">
            <button className="btn" disabled={!ag.actions.remove?.enabled || remove.isPending} title={ag.actions.remove?.reason}
              onClick={() => remove.mutate()}>REMOVE AGENT</button>
            <div className={ag.actions.remove?.enabled ? "reason reason-ok" : "reason"}>{ag.actions.remove?.reason}</div>
            {ag.removalId && <Link to={`/removals/${ag.removalId}`} className="small">removal →</Link>}
          </div>
        </div>
      </div>
      <ErrorBox error={remove.error ?? restart.error} />
      {restart.data && <div className="note">{restart.data.message}</div>}
      <div className="grid-2">
        <Panel title="Agent">
          <table className="kv"><tbody>
            <tr><th>Last heartbeat</th><td><LastHeartbeat ts={ag.lastHeartbeatAt} /></td></tr>
            <tr><th>Missed heartbeats</th><td>{ag.missedHeartbeats} (interval {ag.heartbeatIntervalSec} s)</td></tr>
            <tr><th>Version</th><td>{ag.version}</td></tr>
            <tr><th>Credential</th><td className="mono">{ag.credentialPrefix ? `${ag.credentialPrefix}… (stored hashed)` : "—"}</td></tr>
            {ag.platform && <tr><th>Platform</th><td className="mono">{ag.platform}</td></tr>}
            {ag.profile && <tr><th>Profile</th><td className="mono">{ag.profile}</td></tr>}
            <tr><th>Installed</th><td>{time(ag.installedAt)}</td></tr>
            <tr><th>Enrolled</th><td>{time(ag.enrolledAt)}</td></tr>
            <tr><th>Revoked</th><td>{time(ag.revokedAt)}</td></tr>
            <tr><th>Deployment</th><td><Link to={`/deployments/${ag.deploymentId}`}>{ag.deploymentId.slice(0, 8)}</Link></td></tr>
          </tbody></table>
        </Panel>
        <Panel title={`Heartbeats (${hb.data?.total ?? 0})`}>
          <table className="dense"><thead><tr><th className="num">Seq</th><th>Received</th><th>Agent time</th><th>Payload</th></tr></thead>
            <tbody>{hb.data?.items.map((h) => (
              <tr key={h.seq + h.receivedAt}><td className="num">{h.seq}</td><td className="mono">{time(h.receivedAt)}</td>
                <td className="mono">{time(h.agentTime)}</td>
                <td className="mono small">{Object.entries(h.payload).filter(([, v]) => v != null).map(([k, v]) => `${k}=${v}`).join("  ")}</td></tr>))}
            </tbody></table>
        </Panel>
      </div>
    </div>
  );
}

const REMOVAL_STAGES = [
  { key: "requested", label: "Requested" }, { key: "approved", label: "Approval" },
  { key: "rollback", label: "Rollback" }, { key: "done", label: "Agent removed" },
];

function removalStage(r: Removal): { current: number; failedAt?: number; failedLabel?: string } {
  switch (r.status) {
    case "REQUESTED": return { current: 1 };
    case "REJECTED": return { current: 1, failedAt: 1, failedLabel: "Rejected" };
    case "APPROVED": case "RUNNING": return { current: 2 };
    case "FAILED": return { current: 2, failedAt: 2, failedLabel: "Rollback failed" };
    default: return { current: 3 };
  }
}

export function RemovalDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["removals", id], queryFn: () => apiGet<Removal>(`/removals/${id}`) });
  const act = useMutation({
    mutationFn: (verb: "start" | "retry") => apiAction<Removal>(`/removals/${id}/${verb}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["removals"] }),
  });
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data;
  if (!r) return <div className="muted">Loading…</div>;
  return (
    <div className="page">
      <div className="crumbs"><Link to="/agents">Agents</Link> / <Link to={`/agents/${r.agentId}`}>{r.agentId.slice(0, 8)}</Link> / removal</div>
      <div className="asset-head">
        <div>
          <h1>Remove agent from <Link to={`/assets/${r.assetId}`}>{r.assetName}</Link> <Pill value={r.status} /></h1>
          <div className="meta"><span>requested by {r.requestedBy}</span><span>{time(r.createdAt)}</span>
            <span className="mono">correlation {r.correlationId}</span></div>
        </div>
        <div className="actions">
          <div className="action-with-reason">
            <button className="btn btn-primary" disabled={!r.actions.start?.enabled || act.isPending}
              onClick={() => act.mutate("start")}>START ROLLBACK</button>
            <div className={r.actions.start?.enabled ? "reason reason-ok" : "reason"}>{r.actions.start?.reason}</div>
          </div>
          {r.status === "FAILED" && <div className="action-with-reason">
            <button className="btn" disabled={!r.actions.retry?.enabled || act.isPending} onClick={() => act.mutate("retry")}>RETRY</button>
            <div className="reason">{r.actions.retry?.reason}</div>
          </div>}
        </div>
      </div>
      <Lifecycle stages={REMOVAL_STAGES} {...removalStage(r)} />
      <ErrorBox error={act.error} />
      {r.failureCode && <div className="error-box"><b>{r.failureCode}</b>: {r.failureDetail}</div>}
      <div className="grid-2">
        <Panel title="Approval">
          {r.approval && <table className="kv"><tbody>
            <tr><th>Status</th><td><Pill value={r.approval.status} /></td></tr>
            <tr><th>Purpose</th><td>{r.purpose}</td></tr>
            <tr><th>Decision</th><td>{r.approval.decidedBy ? `${r.approval.status.toLowerCase()} by ${r.approval.decidedBy}` : "—"}</td></tr>
            {r.approval.status === "PENDING" && <tr><td colSpan={2}><Link to="/approvals">Go to approvals →</Link></td></tr>}
          </tbody></table>}
          <p className="hint">Rollback never deletes assessment history, findings, deployments or audit logs. If a step fails,
            the agent identity is revoked anyway.</p>
        </Panel>
        <Panel title="Rollback steps">
          {r.steps.length ? <StepList steps={r.steps} /> : <p className="muted">Starts after approval.</p>}
        </Panel>
      </div>
    </div>
  );
}
