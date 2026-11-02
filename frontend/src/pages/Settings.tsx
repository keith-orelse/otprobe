import { useQuery } from "@tanstack/react-query";
import { apiGet } from "../api";
import { Panel, Pill } from "../components/ui";
import type { DashboardSummary, VaultProfile, Zone } from "../types";

export function Settings() {
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => apiGet<Zone[]>("/zones") });
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => apiGet<VaultProfile[]>("/vault/profiles") });
  const dash = useQuery({ queryKey: ["dashboard"], queryFn: () => apiGet<DashboardSummary>("/dashboard/summary") });
  return (
    <div className="page">
      <h1>Settings</h1>
      <Panel title="Network zones">
        <table className="dense"><thead><tr><th>Zone</th><th>CIDR</th><th>Default level</th><th>Safe mode</th><th>Scannable</th><th>Notes</th></tr></thead>
          <tbody>{zones.data?.map((z) => (
            <tr key={z.id}><td>{z.name}</td><td className="mono">{z.cidr}</td><td>{z.defaultLevel}</td>
              <td>{z.safeMode ? <Pill value="WARNING" title="safe mode" /> : "off"}</td><td>{z.scannable ? "yes" : "no"}</td>
              <td className="muted">{z.description}</td></tr>))}
          </tbody></table>
        <p className="hint">Deliberate simplification: a single simulated conduit separates the DMZ from Level 2 and below
          (shown on the Network Map).</p>
      </Panel>
      <Panel title="Credential vault (simulated, synthetic secrets)">
        <table className="dense"><thead><tr><th>Profile</th><th>Protocol</th><th>Username</th><th>Secret</th></tr></thead>
          <tbody>{vault.data?.map((p) => (
            <tr key={p.name}><td className="mono">{p.name}</td><td>{p.protocol}</td><td className="mono">{p.username}</td>
              <td className="mono">{p.secret}</td></tr>))}
          </tbody></table>
      </Panel>
      <Panel title="Protocol adapters">
        <table className="dense"><thead><tr><th>Protocol</th><th>Implementation</th><th>Label</th></tr></thead>
          <tbody>{dash.data?.adapters.map((a) => (
            <tr key={a.protocol}><td>{a.protocol}</td><td>{a.implementation}</td><td>{a.label}</td></tr>))}
          </tbody></table>
      </Panel>
    </div>
  );
}
