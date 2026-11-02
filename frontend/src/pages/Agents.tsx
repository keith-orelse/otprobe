import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiGet } from "../api";
import { ErrorBox, Panel, Pill, time } from "../components/ui";
import type { Agent, HeartbeatRecord, Page } from "../types";

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
      <h1>Agents</h1>
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
  const a = useQuery({ queryKey: ["agents", id], queryFn: () => apiGet<Agent>(`/agents/${id}`), refetchInterval: 2000 });
  const hb = useQuery({ queryKey: ["agents", id, "hb"], queryFn: () => apiGet<Page<HeartbeatRecord>>(`/agents/${id}/heartbeats`, { limit: 20 }),
    refetchInterval: 2000 });
  if (a.error) return <ErrorBox error={a.error} />;
  const ag = a.data;
  if (!ag) return <div className="muted">Loading…</div>;
  return (
    <div className="page">
      <div className="crumbs"><Link to="/agents">Agents</Link> / {ag.id.slice(0, 8)}</div>
      <h1>Probe Agent {ag.id.slice(0, 8)} on <Link to={`/assets/${ag.assetId}`}>{ag.assetName}</Link> <Pill value={ag.status} /></h1>
      <div className="grid-2">
        <Panel title="Agent">
          <table className="kv"><tbody>
            <tr><th>Last heartbeat</th><td><LastHeartbeat ts={ag.lastHeartbeatAt} /></td></tr>
            <tr><th>Missed heartbeats</th><td>{ag.missedHeartbeats} (interval {ag.heartbeatIntervalSec} s)</td></tr>
            <tr><th>Version</th><td>{ag.version}</td></tr>
            <tr><th>Credential</th><td className="mono">{ag.credentialPrefix ? `${ag.credentialPrefix}… (stored hashed)` : "—"}</td></tr>
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
