import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radar, Search } from "lucide-react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { apiGet } from "../api";
import { ago, ErrorBox, Pager, Pill } from "../components/ui";
import { DeviceIcon, LevelBadge } from "../components/visual";
import type { AssetSummary, Page } from "../types";

const LEVEL_FILTERS = [["", "All levels"], ["2", "L2 · Supervisory"], ["1", "L1 · Control"], ["0", "L0 · Process"]];

export function Assets() {
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const level = params.get("level") ?? "";
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const assets = useQuery({ queryKey: ["assets", q, status, level, cursor],
    queryFn: () => apiGet<Page<AssetSummary>>("/assets", { q, status, level, cursor, limit: 50 }) });
  const setLevel = (v: string) => { setCursor(null); setParams(v ? { level: v } : {}); };
  const empty = assets.data && assets.data.total === 0 && !q && !status && !level;
  return (
    <div className="page">
      {empty ? (
        <div className="empty-hero">
          <div className="header-icon-bg"><Radar size={28} /></div>
          <h2>No assets yet</h2>
          <p>Assets are created by discovery and merged by MAC address. Each field records which protocol reported it.</p>
          <Link to="/discovery" className="btn btn-primary">Start discovery</Link>
        </div>
      ) : (<>
        <div className="toolbar">
          <div className="chip-group" role="tablist" aria-label="Purdue level">
            {LEVEL_FILTERS.map(([v, label]) => (
              <button key={v} role="tab" aria-selected={level === v} className={`chip${level === v ? " chip-active" : ""}`}
                onClick={() => setLevel(v)}>{label}</button>))}
          </div>
          <div className="search-input"><Search size={16} />
            <input placeholder="Filter IP / hostname / MAC / type" value={q} onChange={(e) => { setQ(e.target.value); setCursor(null); }} /></div>
          <select value={status} onChange={(e) => { setStatus(e.target.value); setCursor(null); }}>
            <option value="">All statuses</option><option>ONLINE</option><option>OFFLINE</option><option>UNKNOWN</option>
          </select>
        </div>
        <ErrorBox error={assets.error} />
        <table className="dense clickable">
          <thead><tr><th>Device</th><th>IP</th><th>Type</th><th>OS / firmware</th><th>Level</th><th>Criticality</th><th>Status</th>
            <th>Agent state</th><th>Eligibility</th><th>Last seen</th></tr></thead>
          <tbody>
            {assets.data?.items.map((a) => (
              <tr key={a.id} onClick={() => nav(`/assets/${a.id}`)}>
                <td>
                  <div className="device-cell"><DeviceIcon type={a.type} />
                    <div>{a.hostname ?? (a.sysName ? <span title="SNMP sysName (discovery)">{a.sysName} <span className="muted small">sysName</span></span>
                      : a.displayName !== a.ip ? <span title="MQTT client id (agentless probe)">{a.displayName} <span className="muted small">MQTT client</span></span>
                      : <span className="muted" title={a.lastProbeAt ? "No protocol reported a hostname" : "Run agentless probe"}>
                          {a.lastProbeAt ? "no hostname" : "not probed"}</span>)}
                      {a.isRogue && <> <Pill value="ROGUE" /></>}
                      <div className="muted mono small">{a.mac}</div></div>
                  </div>
                </td>
                <td className="mono">{a.ip}</td>
                <td>{a.type ?? <span className="muted">unclassified</span>}</td>
                <td>{a.os ?? <span className="muted">—</span>}</td>
                <td><LevelBadge level={a.level} /></td><td><Pill value={a.criticality} /></td><td><Pill value={a.status} /></td>
                <td><Pill value={a.agentState} /></td>
                <td><Pill value={a.eligibility} title={a.eligibilityReason} /></td>
                <td title={a.lastSeen}>{ago(a.lastSeen)}</td>
              </tr>
            ))}
            {assets.data?.items.length === 0 && <tr><td colSpan={10} className="muted">No assets match these filters.</td></tr>}
          </tbody>
        </table>
        {assets.data && <Pager total={assets.data.total} next={assets.data.nextCursor} hasPrev={!!cursor}
          onNext={() => setCursor(assets.data!.nextCursor)} onFirst={() => setCursor(null)} />}
      </>)}
    </div>
  );
}
