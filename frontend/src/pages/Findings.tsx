import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ErrorBox, Pager, Panel, Pill, time, Value } from "../components/ui";
import type { Finding, Page } from "../types";

export function Findings() {
  const nav = useNavigate();
  const [status, setStatus] = useState("OPEN,REOPENED");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["findings", status, severity, source, cursor],
    queryFn: () => apiGet<Page<Finding>>("/findings", { status, severity, source, cursor, limit: 100 }) });
  return (
    <div className="page">
      <h1>Findings</h1>
      <div className="toolbar">
        <select value={status} onChange={(e) => { setStatus(e.target.value); setCursor(null); }}>
          <option value="OPEN,REOPENED">Open + reopened</option><option value="">All statuses</option>
          <option>OPEN</option><option>REOPENED</option><option>RESOLVED</option><option>ACCEPTED_RISK</option>
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setCursor(null); }}>
          <option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
        </select>
        <select value={source} onChange={(e) => { setSource(e.target.value); setCursor(null); }}>
          <option value="">All sources</option><option>DEEP_AGENT</option><option>AGENTLESS</option><option>DISCOVERY</option>
        </select>
        <span className="hint">One finding per asset + rule. Resolves when the check passes; reopens on regression.</span>
      </div>
      <ErrorBox error={q.error} />
      <table className="dense clickable">
        <thead><tr><th>Severity</th><th>Status</th><th>Asset</th><th>Rule</th><th>Title</th><th>Observed</th><th>Expected</th>
          <th>Source</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>{q.data?.items.map((f) => (
          <tr key={f.id} onClick={() => nav(`/findings/${f.id}`)}>
            <td><Pill value={f.severity} /></td><td><Pill value={f.status} />{f.reopenCount > 0 && <span className="muted small"> ×{f.reopenCount}</span>}</td>
            <td>{f.assetName}</td><td className="mono">{f.ruleId}</td><td>{f.title}</td>
            <td><Value value={f.observed} /></td><td className="small">{f.expected}</td><td><Pill value={f.source} /></td>
            <td className="mono small">{time(f.firstSeen)}</td><td className="mono small">{time(f.lastSeen)}</td>
          </tr>))}
          {q.data?.items.length === 0 && <tr><td colSpan={10} className="muted">No findings match.</td></tr>}
        </tbody>
      </table>
      {q.data && <Pager total={q.data.total} next={q.data.nextCursor} hasPrev={!!cursor}
        onNext={() => setCursor(q.data!.nextCursor)} onFirst={() => setCursor(null)} />}
    </div>
  );
}

export function FindingDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const q = useQuery({ queryKey: ["findings", id], queryFn: () => apiGet<Finding>(`/findings/${id}`) });
  const act = useMutation({
    mutationFn: (verb: "accept-risk" | "revoke-acceptance") => apiAction<Finding>(`/findings/${id}/${verb}`, { reason }),
    onSuccess: () => { setReason(""); qc.invalidateQueries({ queryKey: ["findings"] }); },
  });
  if (q.error) return <ErrorBox error={q.error} />;
  const f = q.data;
  if (!f) return <div className="muted">Loading…</div>;
  const canAccept = f.actions.acceptRisk, canRevoke = f.actions.revokeAcceptance;
  return (
    <div className="page">
      <div className="crumbs"><Link to="/findings">Findings</Link> / {f.ruleId}</div>
      <h1><Pill value={f.severity} /> {f.title} <Pill value={f.status} /></h1>
      <div className="meta"><Link to={`/assets/${f.assetId}`}>{f.assetName}</Link><span className="mono">{f.assetIp}</span>
        <span className="mono">{f.ruleId}</span><Pill value={f.source} />
        {f.lastRunId && <Link to={`/assessments/${f.lastRunId}`}>last assessment →</Link>}</div>
      <div className="grid-2">
        <Panel title="Details">
          <table className="kv"><tbody>
            <tr><th>Observed</th><td><Value value={f.observed} /></td></tr>
            <tr><th>Expected</th><td>{f.expected}</td></tr>
            <tr><th>Result</th><td><Pill value={f.resultStatus} /></td></tr>
            <tr><th>Remediation</th><td>{f.remediation ?? "—"}</td></tr>
            <tr><th>References</th><td>{f.references.join(" · ") || "—"}</td></tr>
            <tr><th>First seen</th><td>{time(f.firstSeen)}</td></tr>
            <tr><th>Last seen</th><td>{time(f.lastSeen)}</td></tr>
            <tr><th>Resolved</th><td>{time(f.resolvedAt)}</td></tr>
            <tr><th>Reopened</th><td>{f.reopenCount} time(s)</td></tr>
            {f.acceptedBy && <tr><th>Risk accepted</th><td>by {f.acceptedBy}: {f.acceptedReason}
              {f.acceptedUntil && <> (until {time(f.acceptedUntil)})</>}</td></tr>}
          </tbody></table>
          <div className="decide">
            <input placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)}
              disabled={!canAccept.enabled && !canRevoke.enabled} />
            <button className="btn btn-sm" disabled={!canAccept.enabled || act.isPending} title={canAccept.reason}
              onClick={() => act.mutate("accept-risk")}>Accept risk</button>
            <button className="btn btn-sm" disabled={!canRevoke.enabled || act.isPending} title={canRevoke.reason}
              onClick={() => act.mutate("revoke-acceptance")}>Revoke acceptance</button>
            <div className="reason">{canAccept.enabled ? canAccept.reason : canRevoke.enabled ? canRevoke.reason : canAccept.reason}</div>
          </div>
          <ErrorBox error={act.error} />
        </Panel>
        <Panel title="Lifecycle">
          <table className="dense"><thead><tr><th>When</th><th>Transition</th><th>By</th><th>Reason</th><th /></tr></thead>
            <tbody>{f.events.map((e, i) => (
              <tr key={i}><td className="mono small">{time(e.at)}</td>
                <td>{e.fromStatus ? <><Pill value={e.fromStatus} />→ </> : null}<Pill value={e.toStatus} /></td>
                <td>{e.actor}</td><td className="small">{e.reason ?? ""}</td>
                <td>{e.runId && <Link to={`/assessments/${e.runId}`}>run</Link>}</td></tr>))}
            </tbody></table>
          {f.driftEvents.length > 0 && <>
            <h3 className="sub">Configuration drift</h3>
            <table className="dense"><tbody>{f.driftEvents.map((d) => (
              <tr key={d.id}><td className="mono small">{time(d.detectedAt)}</td><td><Pill value={d.fromStatus} />→ <Pill value={d.toStatus} /></td>
                <td className="mono small">{d.evidencePath}: <Value value={d.before} /> → <Value value={d.after} /></td></tr>))}
            </tbody></table></>}
        </Panel>
      </div>
    </div>
  );
}
