import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { apiGet } from "../api";
import { ago, ErrorBox, Pager, Pill } from "../components/ui";
import type { AssetSummary, Page } from "../types";

export function Assets() {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const assets = useQuery({ queryKey: ["assets", q, status, cursor],
    queryFn: () => apiGet<Page<AssetSummary>>("/assets", { q, status, cursor, limit: 50 }) });
  return (
    <div className="page">
      <h1>Assets</h1>
      <div className="toolbar">
        <input placeholder="Filter IP / hostname / MAC / type" value={q} onChange={(e) => { setQ(e.target.value); setCursor(null); }} />
        <select value={status} onChange={(e) => { setStatus(e.target.value); setCursor(null); }}>
          <option value="">All statuses</option><option>ONLINE</option><option>OFFLINE</option><option>UNKNOWN</option>
        </select>
      </div>
      <ErrorBox error={assets.error} />
      <table className="dense clickable">
        <thead><tr><th>IP</th><th>Hostname</th><th>Type</th><th>OS</th><th>Level</th><th>Criticality</th><th>Status</th>
          <th>Agent state</th><th>Eligibility</th><th>Last seen</th></tr></thead>
        <tbody>
          {assets.data?.items.map((a) => (
            <tr key={a.id} onClick={() => nav(`/assets/${a.id}`)}>
              <td className="mono">{a.ip}</td>
              <td>{a.hostname ?? (a.sysName ? <span className="muted" title="SNMP sysName (discovery)">{a.sysName} (sysName)</span>
                : <span className="muted" title="Run agentless probe">—</span>)}
                {a.isRogue && <> <Pill value="ROGUE" /></>}</td>
              <td>{a.type ?? <span className="muted">unclassified</span>}</td>
              <td>{a.os ?? <span className="muted">—</span>}</td>
              <td>L{a.level}</td><td><Pill value={a.criticality} /></td><td><Pill value={a.status} /></td>
              <td><Pill value={a.agentState} /></td>
              <td><Pill value={a.eligibility} title={a.eligibilityReason} /></td>
              <td title={a.lastSeen}>{ago(a.lastSeen)}</td>
            </tr>
          ))}
          {assets.data?.items.length === 0 && <tr><td colSpan={10} className="muted">No assets. Run a discovery.</td></tr>}
        </tbody>
      </table>
      {assets.data && <Pager total={assets.data.total} next={assets.data.nextCursor} hasPrev={!!cursor}
        onNext={() => setCursor(assets.data!.nextCursor)} onFirst={() => setCursor(null)} />}
    </div>
  );
}
