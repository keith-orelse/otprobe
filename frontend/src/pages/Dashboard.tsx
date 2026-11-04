import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "../api";
import { ErrorBox, Panel, Pill, Progress, time } from "../components/ui";
import type { DashboardSummary } from "../types";
import { Score } from "./Assessments";

export function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => apiGet<DashboardSummary>("/dashboard/summary") });
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d) return <div className="muted">Loading…</div>;
  const kpis: [string, number, string?][] = [
    ["Assets", d.assets.total ?? 0], ["Online", d.assets.ONLINE ?? 0, "ok"], ["Offline", d.assets.OFFLINE ?? 0, "fail"],
    ["Rogue", d.rogue, d.rogue ? "fail" : undefined], ["Agent eligible", d.eligibility.ELIGIBLE ?? 0, "ok"],
    ["Review required", d.eligibility.REVIEW_REQUIRED ?? 0, "warn"],
    ["Open critical/high", (d.openFindings.CRITICAL ?? 0) + (d.openFindings.HIGH ?? 0), "fail"],
    ["Open medium/low", (d.openFindings.MEDIUM ?? 0) + (d.openFindings.LOW ?? 0), "warn"],
  ];
  return (
    <div className="page">
      <h1>Dashboard</h1>
      <div className="kpis">
        {kpis.map(([label, v, tone]) => (
          <div key={label} className={`kpi ${tone ? `kpi-${tone}` : ""}`}><span>{label}</span><b>{v}</b></div>
        ))}
      </div>
      <div className="grid-2">
        <Panel title={<>Continuous monitoring · average compliance <Score score={d.complianceAvg} unknown={d.unknownTotal} /></>}>
          {d.monitoring.length ? (
            <table className="dense"><thead><tr><th>Asset</th><th>Agent</th><th>Last heartbeat</th><th>Last assessment</th>
              <th>Next assessment</th><th>Compliance</th><th className="num">Open findings</th></tr></thead>
              <tbody>{d.monitoring.map((m) => (
                <tr key={m.agentId}><td><Link to={`/assets/${m.assetId}`}>{m.assetName}</Link></td><td><Pill value={m.agentStatus} /></td>
                  <td className="mono">{m.secondsSinceHeartbeat == null ? "—" : `${m.secondsSinceHeartbeat} s ago`}</td>
                  <td className="mono small">{time(m.lastAssessmentAt)}</td><td className="mono small">{time(m.nextAssessmentAt)}</td>
                  <td><Score score={m.score} unknown={m.unknown} /></td><td className="num">{m.openFindings}</td></tr>))}
              </tbody></table>) : <p className="muted">No agents deployed yet.</p>}
        </Panel>
        <Panel title="Configuration drift & changes" actions={<Link to="/findings">Findings →</Link>}>
          {d.recentDrift.length === 0 && d.recentChanges.length === 0 && <p className="muted">No drift or configuration changes yet.</p>}
          <table className="dense"><tbody>
            {d.recentDrift.map((x) => (
              <tr key={x.id} className="drift-row"><td className="mono small">{time(x.detectedAt)}</td><td>{x.assetName}</td>
                <td className="mono">{x.ruleId}</td><td><Pill value={x.fromStatus} />→ <Pill value={x.toStatus} /></td>
                <td>{x.findingId && <Link to={`/findings/${x.findingId}`}>finding</Link>}</td></tr>))}
            {d.recentChanges.map((x, i) => (
              <tr key={i}><td className="mono small">{time(x.detectedAt)}</td><td>{x.assetName}</td>
                <td className="mono small" colSpan={2}>{x.path}: {JSON.stringify(x.before)} → {JSON.stringify(x.after)}</td>
                <td><Link to={`/assessments/${x.runId}`}>run</Link></td></tr>))}
          </tbody></table>
        </Panel>
      </div>
      <div className="grid-2">
        <Panel title="Last discovery">
          {d.lastDiscovery ? (
            <table className="kv"><tbody>
              <tr><th>Status</th><td><Pill value={d.lastDiscovery.status} /></td></tr>
              <tr><th>Progress</th><td><Progress value={d.lastDiscovery.progress} /></td></tr>
              <tr><th>Targets</th><td className="mono">{d.lastDiscovery.targets.join(", ")}</td></tr>
              <tr><th>Devices found</th><td>{d.lastDiscovery.devicesFound} ({d.lastDiscovery.newAssets} new,
                {" "}{d.lastDiscovery.rogueCount} rogue)</td></tr>
              <tr><th>Finished</th><td>{time(d.lastDiscovery.finishedAt)}</td></tr>
            </tbody></table>
          ) : <p className="muted">No discovery yet. <Link to="/discovery">Start one</Link>.</p>}
        </Panel>
        <Panel title="Inventory by Purdue level / eligibility">
          <table className="dense"><thead><tr><th>Level</th><th className="num">Assets</th></tr></thead><tbody>
            {Object.entries(d.assetsByLevel).sort().map(([l, n]) => <tr key={l}><td>L{l}</td><td className="num">{n}</td></tr>)}
          </tbody></table>
          <table className="dense"><thead><tr><th>Agent eligibility</th><th className="num">Assets</th></tr></thead><tbody>
            {Object.entries(d.eligibility).map(([e, n]) => <tr key={e}><td><Pill value={e} /></td><td className="num">{n}</td></tr>)}
          </tbody></table>
        </Panel>
      </div>
      <div className="grid-2">
        <Panel title="Protocol adapters">
          <table className="dense"><thead><tr><th>Protocol</th><th>Implementation</th><th>Label</th></tr></thead><tbody>
            {d.adapters.map((a) => (
              <tr key={a.protocol}><td>{a.protocol}</td>
                <td>{a.implementation} {a.simulated && <span className="pill pill-warn">SIMULATED</span>}</td>
                <td>{a.label}</td></tr>
            ))}
          </tbody></table>
        </Panel>
        <Panel title="Recent audit events" actions={<Link to="/audit">All →</Link>}>
          <table className="dense"><tbody>
            {d.recentEvents.map((e) => (
              <tr key={e.seq}><td className="mono muted">{time(e.at)}</td><td className="mono">{e.action}</td>
                <td>{e.actorName}</td></tr>
            ))}
          </tbody></table>
        </Panel>
      </div>
    </div>
  );
}
