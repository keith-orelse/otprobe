import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "../api";
import { ErrorBox, Panel, Pill, Progress, time } from "../components/ui";
import type { DashboardSummary } from "../types";

export function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => apiGet<DashboardSummary>("/dashboard/summary") });
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d) return <div className="muted">Loading…</div>;
  const kpis: [string, number, string?][] = [
    ["Assets", d.assets.total ?? 0], ["Online", d.assets.ONLINE ?? 0, "ok"], ["Offline", d.assets.OFFLINE ?? 0, "fail"],
    ["Rogue", d.rogue, d.rogue ? "fail" : undefined], ["Agent eligible", d.eligibility.ELIGIBLE ?? 0, "ok"],
    ["Review required", d.eligibility.REVIEW_REQUIRED ?? 0, "warn"],
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
