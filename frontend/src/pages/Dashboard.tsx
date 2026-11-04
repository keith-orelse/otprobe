import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, BadgeCheck, Cpu, Radar, Server, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { apiGet } from "../api";
import { ago, ErrorBox, Panel, Pill, Progress, time } from "../components/ui";
import { DeviceIcon, LevelBadge } from "../components/visual";
import type { DashboardSummary } from "../types";
import { Score } from "./Assessments";

const LEVELS: { key: string; name: string; hint: string }[] = [
  { key: "2", name: "Supervisory", hint: "Engineering workstations, SCADA, historian" },
  { key: "1", name: "Control", hint: "PLCs: agentless, read-only" },
  { key: "0", name: "Process", hint: "Sensors and field devices: ARP + MQTT only" },
];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

function SummaryCard({ icon: Icon, label, value, sub, tone, to }:
  { icon: typeof Server; label: string; value: React.ReactNode; sub: React.ReactNode; tone?: string; to: string }) {
  return (
    <Link to={to} className={`summary-card ${tone ? `summary-${tone}` : ""}`}>
      <div className="summary-card-header"><span>{label}</span><span className="summary-card-icon"><Icon size={20} /></span></div>
      <div className="summary-card-value">{value}</div>
      <div className="summary-card-subtext">{sub}</div>
    </Link>
  );
}

function Ring({ score }: { score: number | null }) {
  const pct = score ?? 0;
  const c = 2 * Math.PI * 42;
  const tone = score == null ? "#cbd5e1" : pct >= 90 ? "#1e8e3e" : pct >= 70 ? "#e9a100" : "#d93025";
  return (
    <svg viewBox="0 0 100 100" className="ring" role="img" aria-label={`compliance ${score ?? "unknown"}`}>
      <circle cx="50" cy="50" r="42" className="ring-track" />
      <circle cx="50" cy="50" r="42" className="ring-value" style={{ stroke: tone }}
        strokeDasharray={`${(pct / 100) * c} ${c}`} transform="rotate(-90 50 50)" />
      <text x="50" y="49" textAnchor="middle" className="ring-text">{score == null ? "—" : `${Math.round(pct)}%`}</text>
      <text x="50" y="63" textAnchor="middle" className="ring-sub">compliance</text>
    </svg>
  );
}

export function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => apiGet<DashboardSummary>("/dashboard/summary"),
    refetchInterval: 10000 });
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data;
  if (!d) return <div className="muted">Loading…</div>;
  // Tolerate an older API that lacks newer summary fields.
  const agents = d.agents ?? {};
  const byLevelType = d.assetsByLevelType ?? {};
  const pendingApprovals = d.pendingApprovals ?? 0;
  const total = d.assets.total ?? 0;
  const openTotal = SEVERITIES.reduce((n, s) => n + (d.openFindings[s] ?? 0), 0);
  const maxSev = Math.max(1, ...SEVERITIES.map((s) => d.openFindings[s] ?? 0));
  const agentsOnline = agents.ONLINE ?? 0;
  const agentsAttention = (agents.STALE ?? 0) + (agents.OFFLINE ?? 0) + (agents.ERROR ?? 0);

  if (total === 0) {
    return (
      <div className="empty-hero">
        <div className="header-icon-bg"><Radar size={28} /></div>
        <h2>No assets discovered yet</h2>
        <p>Start with a discovery of the simulated OT subnets. Devices appear one by one; nothing real is scanned.</p>
        <Link to="/discovery" className="btn btn-primary">Start discovery</Link>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="summary-grid">
        <SummaryCard icon={Server} label="Assets" value={total} to="/assets"
          sub={<>{d.assets.ONLINE ?? 0} online · {d.assets.OFFLINE ?? 0} offline</>} />
        <SummaryCard icon={Cpu} label="Deep agents" value={agentsOnline} to="/agents" tone={agentsAttention ? "warn" : undefined}
          sub={agentsAttention ? <>{agentsAttention} need attention</> : <>{d.eligibility.ELIGIBLE ?? 0} more eligible</>} />
        <SummaryCard icon={AlertTriangle} label="Open findings" value={openTotal} to="/findings"
          tone={(d.openFindings.CRITICAL ?? 0) + (d.openFindings.HIGH ?? 0) ? "fail" : undefined}
          sub={<>{(d.openFindings.CRITICAL ?? 0) + (d.openFindings.HIGH ?? 0)} critical / high</>} />
        <SummaryCard icon={BadgeCheck} label="Pending approvals" value={pendingApprovals} to="/approvals"
          tone={pendingApprovals ? "info" : undefined} sub="deployments and removals" />
        <SummaryCard icon={ShieldAlert} label="Rogue devices" value={d.rogue} to="/assets" tone={d.rogue ? "fail" : undefined}
          sub={d.rogue ? "unknown MACs on the OT network" : "no unknown devices"} />
      </div>

      <div className="grid-2 grid-wide-left">
        <Panel title="Plant overview · Purdue model" actions={<Link to="/network-map">Network map →</Link>}>
          <div className="purdue">
            <div className="purdue-row purdue-dmz">
              <LevelBadge level="DMZ" /><div><b>OTProbe server</b><span>reaches Level 2 and below through fw-conduit-01</span></div>
            </div>
            {LEVELS.map((lvl) => {
              const types = byLevelType[lvl.key] ?? {};
              const count = Object.values(types).reduce((a, b) => a + b, 0);
              return (
                <div key={lvl.key} className="purdue-row">
                  <LevelBadge level={lvl.key} />
                  <div className="purdue-main">
                    <div className="purdue-head"><b>Level {lvl.key} · {lvl.name}</b><span className="muted">{count} device{count === 1 ? "" : "s"}</span></div>
                    <div className="purdue-chips">
                      {Object.entries(types).sort((a, b) => b[1] - a[1]).map(([type, n]) => (
                        <Link key={type} to={`/assets?level=${lvl.key}`} className="type-chip"><DeviceIcon type={type} size={14} />{type}<b>{n}</b></Link>))}
                      {count === 0 && <span className="muted small">{lvl.hint}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
        <Panel title="Security posture" actions={<Link to="/findings">Findings →</Link>}>
          <div className="posture">
            <Ring score={d.complianceAvg} />
            <div className="sev-bars">
              {SEVERITIES.map((s) => (
                <Link key={s} to={`/findings?severity=${s}`} className="sev-row">
                  <Pill value={s} />
                  <span className="sev-track"><span className={`sev-fill sev-${s.toLowerCase()}`}
                    style={{ width: `${((d.openFindings[s] ?? 0) / maxSev) * 100}%` }} /></span>
                  <b>{d.openFindings[s] ?? 0}</b>
                </Link>))}
              <p className="hint">Average of each asset's latest assessment. {d.unknownTotal} UNKNOWN result{d.unknownTotal === 1 ? "" : "s"} excluded from scores.</p>
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="Continuous monitoring" actions={<Link to="/agents">Agents →</Link>}>
        {d.monitoring.length ? (
          <table className="dense"><thead><tr><th>Asset</th><th>Agent</th><th>Last heartbeat</th><th>Last assessment</th>
            <th>Next assessment</th><th>Compliance</th><th className="num">Open findings</th></tr></thead>
            <tbody>{d.monitoring.map((m) => (
              <tr key={m.agentId}><td><Link to={`/assets/${m.assetId}`}>{m.assetName}</Link></td><td><Pill value={m.agentStatus} /></td>
                <td className="mono">{m.secondsSinceHeartbeat == null ? "—" : `${m.secondsSinceHeartbeat} s ago`}</td>
                <td className="mono small">{time(m.lastAssessmentAt)}</td><td className="mono small">{time(m.nextAssessmentAt)}</td>
                <td><Score score={m.score} unknown={m.unknown} /></td><td className="num">{m.openFindings}</td></tr>))}
            </tbody></table>
        ) : <div className="empty-inline">No deep agents yet. Probe an eligible workstation, then <b>Deploy agent</b> from its asset page.</div>}
      </Panel>

      <div className="grid-2">
        <Panel title="Drift & configuration changes">
          {d.recentDrift.length === 0 && d.recentChanges.length === 0
            ? <div className="empty-inline">No drift yet. Deep assessments compare each run with the previous one.</div> : (
            <ul className="timeline">
              {d.recentDrift.map((x) => (
                <li key={x.id} className="tl-fail"><span className="tl-time">{ago(x.detectedAt)}</span>
                  <div><b>{x.assetName}</b> · <span className="mono">{x.ruleId}</span> <Pill value={x.fromStatus} />→ <Pill value={x.toStatus} />
                    {x.findingId && <Link to={`/findings/${x.findingId}`}> finding →</Link>}</div></li>))}
              {d.recentChanges.slice(0, 6).map((x, i) => (
                <li key={i}><span className="tl-time">{ago(x.detectedAt)}</span>
                  <div><b>{x.assetName}</b> · <span className="mono small">{x.path}</span> {JSON.stringify(x.before)} → {JSON.stringify(x.after)}</div></li>))}
            </ul>)}
        </Panel>
        <Panel title="Recent activity" actions={<Link to="/audit">Audit log →</Link>}>
          <ul className="timeline">
            {d.recentEvents.slice(0, 9).map((e) => (
              <li key={e.seq}><span className="tl-time">{ago(e.at)}</span>
                <div><span className="mono small">{e.action}</span> <span className="muted">by {e.actorName}</span></div></li>))}
          </ul>
        </Panel>
      </div>

      <div className="grid-2">
        <Panel title="Last discovery" actions={<Link to="/discovery">Discovery →</Link>}>
          {d.lastDiscovery && (
            <table className="kv"><tbody>
              <tr><th>Status</th><td><Pill value={d.lastDiscovery.status} /></td></tr>
              <tr><th>Progress</th><td><Progress value={d.lastDiscovery.progress} /></td></tr>
              <tr><th>Targets</th><td className="mono">{d.lastDiscovery.targets.join(", ")}</td></tr>
              <tr><th>Devices found</th><td>{d.lastDiscovery.devicesFound} ({d.lastDiscovery.newAssets} new, {d.lastDiscovery.rogueCount} rogue)</td></tr>
              <tr><th>Finished</th><td>{time(d.lastDiscovery.finishedAt)}</td></tr>
            </tbody></table>)}
        </Panel>
        <Panel title="Protocol adapters" actions={<Link to="/settings">Settings →</Link>}>
          <div className="adapter-grid">
            {d.adapters.map((a) => (
              <div key={a.protocol} className="adapter"><b>{a.protocol}</b><span>{a.label}</span>
                {a.simulated && <span className="pill pill-warn">simulated</span>}</div>))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
