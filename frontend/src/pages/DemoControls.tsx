import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiAction, apiGet } from "../api";
import { can, useMe } from "../auth";
import { ErrorBox, Panel, Pill } from "../components/ui";
import type { DemoState } from "../types";

export function DemoControls() {
  const me = useMe();
  const qc = useQueryClient();
  const allowed = can(me.data, "demo.control");
  const q = useQuery({ queryKey: ["demo"], queryFn: () => apiGet<DemoState>("/demo/state"), enabled: allowed,
    refetchInterval: 3000 });
  const config = useMutation({
    mutationFn: (v: { device: string; control: string; value: string }) =>
      apiAction(`/demo/devices/${v.device}/config`, { control: v.control, value: v.value }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["demo"] }),
  });
  const toggle = useMutation({
    mutationFn: (v: { device: string; fault: string; enabled: boolean }) =>
      apiAction(`/demo/devices/${v.device}/faults`, { fault: v.fault, enabled: v.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["demo"] }),
  });
  return (
    <div className="page">
      <h1>SIMULATION CONTROLS</h1>
      <div className="note">These controls change the <b>simulated</b> world only. OTProbe notices the effect the way a real
        product would: through probes, precheck, deployment and agent heartbeats. Admin only. Every change is audited.
        Telemetry, rogue injection and Reset POC arrive in Phase 5.</div>
      {!allowed && me.data && <div className="error-box">Role {me.data.role} cannot use simulation controls (admin only).</div>}
      <ErrorBox error={q.error ?? toggle.error ?? config.error} />
      {q.data && (
        <Panel title="Host configuration (drives assessment drift)">
          <table className="dense">
            <thead><tr><th>Host</th>{Object.keys(q.data.configControls).map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}</tr></thead>
            <tbody>{q.data.devices.filter((d) => Object.keys(d.config).length).map((d) => (
              <tr key={d.deviceId}>
                <td>{d.hostname}<div className="muted mono small">{d.deviceId}</div></td>
                {Object.entries(q.data!.configControls).map(([control, values]) => (
                  <td key={control}>
                    <div className="mono small">{d.config[control]}</div>
                    {values.map((v) => (
                      <button key={v} className="btn btn-sm" disabled={config.isPending || d.config[control] === v}
                        onClick={() => config.mutate({ device: d.deviceId, control, value: v })}>{v}</button>))}
                  </td>))}
              </tr>))}
            </tbody>
          </table>
          <p className="hint">Changes the simulated host only. OTProbe sees the change on the next deep assessment (or agentless
            probe for firewall/antivirus): a PASS → FAIL rule change raises CONFIGURATION_DRIFT_DETECTED and a finding.</p>
        </Panel>
      )}
      {q.data && (
        <Panel title="Device faults">
          <table className="dense">
            <thead><tr><th>Device</th><th>IP</th><th>Type</th><th>State</th><th>Active faults</th><th>Set / clear fault</th></tr></thead>
            <tbody>{q.data.devices.map((d) => (
              <tr key={d.deviceId}>
                <td>{d.hostname}<div className="muted mono small">{d.deviceId}</div></td><td className="mono">{d.ip}</td>
                <td>{d.type}{d.agentInstalled && <> <span className="pill pill-info">AGENT</span></>}</td>
                <td><Pill value={d.online ? "ONLINE" : "OFFLINE"} /></td>
                <td>{d.faults.map((f) => (
                  <button key={f} className="btn btn-sm fault-on" title="Clear"
                    onClick={() => toggle.mutate({ device: d.deviceId, fault: f, enabled: false })}>{f} ✕</button>))}</td>
                <td>
                  <select value="" onChange={(e) => e.target.value && toggle.mutate({ device: d.deviceId, fault: e.target.value, enabled: true })}>
                    <option value="">Inject fault…</option>
                    {Object.entries(q.data!.availableFaults).filter(([k]) => !d.faults.includes(k)).map(([k, label]) => (
                      <option key={k} value={k}>{k}: {label}</option>))}
                  </select>
                </td>
              </tr>))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  );
}
