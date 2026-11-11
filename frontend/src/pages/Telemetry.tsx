import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "../api";
import { ago, ErrorBox, Panel, time } from "../components/ui";
import type { TelemetryTopic } from "../types";

function numericKey(payload: any): string | null {
  if (payload === null || typeof payload !== "object") return null;
  return Object.keys(payload).find((k) => typeof payload[k] === "number" && k !== "cycleMs") ?? null;
}

/** A trend point: the number itself, or the first numeric field of an object payload. */
function point(payload: any, key: string | null): number {
  return key ? Number(payload?.[key]) : typeof payload === "number" ? payload : Number(payload);
}

function show(payload: any): string {
  if (payload !== null && typeof payload === "object" && !Array.isArray(payload)) {
    return Object.entries(payload).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ");
  }
  return typeof payload === "string" ? payload : JSON.stringify(payload);
}

function Spark({ points }: { points: number[] }) {
  if (points.length < 2) return null;
  const min = Math.min(...points), max = Math.max(...points), span = max - min || 1;
  const d = points.map((p, i) => `${(i / (points.length - 1)) * 160},${28 - ((p - min) / span) * 24}`).join(" ");
  return <svg className="spark" viewBox="0 0 160 30" role="img" aria-label="recent values"><polyline points={d} /></svg>;
}

export function Telemetry() {
  const q = useQuery({ queryKey: ["telemetry", "topics"], queryFn: () => apiGet<TelemetryTopic[]>("/telemetry/topics"),
    refetchInterval: 5000 });
  return (
    <div className="page">
      <p className="hint">MQTT telemetry from the bundled broker. Devices publish with their own account (Settings → MQTT
        device accounts); each message goes to the asset linked to that account, or to the asset at the address the
        device connects from. <span className="mono">rules/telemetry.yaml</span> checks every message: thresholds and
        silent devices raise TELEMETRY findings.</p>
      <ErrorBox error={q.error} />
      <Panel title="Topics">
        <table className="dense">
          <thead><tr><th>Topic</th><th>Account</th><th>Asset</th><th>Last value</th><th>Trend</th><th>Last message</th>
            <th className="num">Messages</th><th>Open findings</th></tr></thead>
          <tbody>{q.data?.map((t) => {
            const key = numericKey(t.lastPayload);
            return (
              <tr key={t.topic}>
                <td className="mono">{t.topic}</td><td className="mono">{t.clientId}</td>
                <td>{t.assetId ? <Link to={`/assets/${t.assetId}`}>{t.assetName}</Link>
                  : <Link className="muted" to="/settings" title="Link the account to an asset in Settings">not linked</Link>}</td>
                <td className="mono">{show(t.lastPayload)}</td>
                <td><Spark points={t.recent.map((r) => point(r.payload, key)).filter((n) => !Number.isNaN(n))} /></td>
                <td title={time(t.lastAt)}>{ago(t.lastAt)}</td><td className="num">{t.messages}</td>
                <td>{t.openFindings.length ? t.openFindings.map((f) => <span key={f} className="pill pill-fail">{f}</span>)
                  : <span className="muted">none</span>}</td>
              </tr>);
          })}
          {q.data?.length === 0 && <tr><td colSpan={8} className="muted">No telemetry yet. Create a device account in Settings → MQTT
            device accounts, then point the device (or scripts/fake_sensor.py) at this machine.</td></tr>}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
