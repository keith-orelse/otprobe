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
        The full Phase 5 control set (configuration drift, telemetry, rogue injection, Reset POC) is not here yet.</div>
      {!allowed && me.data && <div className="error-box">Role {me.data.role} cannot use simulation controls (admin only).</div>}
      <ErrorBox error={q.error ?? toggle.error} />
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
