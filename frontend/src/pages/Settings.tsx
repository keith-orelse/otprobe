import { useQuery } from "@tanstack/react-query";
import { apiGet } from "../api";
import { Panel, Pill } from "../components/ui";
import { useEnvironment } from "../components/Safety";
import type { DashboardSummary, Zone } from "../types";
import { LiveSettings } from "./SettingsLive";

export function Settings() {
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => apiGet<Zone[]>("/zones") });
  const dash = useQuery({ queryKey: ["dashboard"], queryFn: () => apiGet<DashboardSummary>("/dashboard/summary") });
  const env = useEnvironment();
  const live = env.data?.mode === "LIVE";
  return (
    <div className="page">
      {live && <LiveSettings />}
      <Panel title={live ? "Network zones (created from the scan scope)" : "Network zones"}>
        <table className="dense"><thead><tr><th>Zone</th><th>CIDR</th><th>Default level</th><th>Safe mode</th><th>Scannable</th><th>Notes</th></tr></thead>
          <tbody>{zones.data?.map((z) => (
            <tr key={z.id}><td>{z.name}</td><td className="mono">{z.cidr}</td><td>{z.defaultLevel}</td>
              <td>{z.safeMode ? <Pill value="WARNING" title="safe mode" /> : "off"}</td><td>{z.scannable ? "yes" : "no"}</td>
              <td className="muted">{z.description}</td></tr>))}
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
