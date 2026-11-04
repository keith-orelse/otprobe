import { useQuery } from "@tanstack/react-query";
import { apiGet } from "../api";
import { Panel, Pill } from "../components/ui";
import { useEnvironment } from "../components/Safety";
import type { DashboardSummary, Package, VaultProfile, Zone } from "../types";
import { LiveSettings } from "./SettingsLive";

export function Settings() {
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => apiGet<Zone[]>("/zones") });
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => apiGet<VaultProfile[]>("/vault/profiles") });
  const packages = useQuery({ queryKey: ["packages"], queryFn: () => apiGet<Package[]>("/packages") });
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
        {!live && <p className="hint">Deliberate simplification: a single simulated conduit separates the DMZ from Level 2 and below
          (shown on the Network Map).</p>}
      </Panel>
      {!live && <Panel title="Credential vault (simulated, synthetic secrets)">
        <table className="dense"><thead><tr><th>Profile</th><th>Protocol</th><th>Username</th><th>Secret</th></tr></thead>
          <tbody>{vault.data?.map((p) => (
            <tr key={p.name}><td className="mono">{p.name}</td><td>{p.protocol}</td><td className="mono">{p.username}</td>
              <td className="mono">{p.secret}</td></tr>))}
          </tbody></table>
      </Panel>}
      {!live && <Panel title="Package repository (simulated transfer, real metadata and SHA-256)">
        <table className="dense"><thead><tr><th>Package</th><th>Version</th><th>Arch</th><th>Status</th><th>SHA-256</th>
          <th className="num">Size</th><th>Supported OS</th><th>Created</th></tr></thead>
          <tbody>{packages.data?.map((p) => (
            <tr key={p.id}><td>{p.name}</td><td>{p.version}</td><td>{p.architecture}</td><td><Pill value={p.status === "ACTIVE" ? "OK" : "WARNING"} title={p.status} />{p.status}</td>
              <td className="mono small" title={p.sha256}>{p.sha256.slice(0, 16)}…</td>
              <td className="num">{(p.sizeBytes / 1_048_576).toFixed(1)} MB</td><td>{p.supportedOs.join(", ")}</td>
              <td>{new Date(p.createdAt).toLocaleDateString()}</td></tr>))}
          </tbody></table>
      </Panel>}
      <Panel title="Protocol adapters">
        <table className="dense"><thead><tr><th>Protocol</th><th>Implementation</th><th>Label</th></tr></thead>
          <tbody>{dash.data?.adapters.map((a) => (
            <tr key={a.protocol}><td>{a.protocol}</td><td>{a.implementation}</td><td>{a.label}</td></tr>))}
          </tbody></table>
      </Panel>
    </div>
  );
}
