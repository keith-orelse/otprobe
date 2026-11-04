import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { apiGet } from "../api";
import { ago, ErrorBox, Panel, time } from "../components/ui";
import type { TelemetryTopic } from "../types";

function numericKey(payload: Record<string, any>): string | null {
  return Object.keys(payload).find((k) => typeof payload[k] === "number" && k !== "cycleMs") ?? null;
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
      <p className="hint">In-process broker (simulated, logically on historian-01:8883). The separate telemetry simulator publishes;
        OTProbe subscribes to <span className="mono">factory/#</span>, attributes each publisher to an asset via the broker's client
        list, and evaluates <span className="mono">rules/telemetry.yaml</span>. Thresholds and staleness raise TELEMETRY findings.</p>
      <ErrorBox error={q.error} />
      <Panel title="Topics">
        <table className="dense">
          <thead><tr><th>Topic</th><th>Client</th><th>Asset</th><th>Last value</th><th>Trend</th><th>Last message</th>
            <th className="num">Messages</th><th>Open findings</th></tr></thead>
          <tbody>{q.data?.map((t) => {
            const key = numericKey(t.lastPayload ?? {});
            return (
              <tr key={t.topic}>
                <td className="mono">{t.topic}</td><td className="mono">{t.clientId}</td>
                <td>{t.assetId ? <Link to={`/assets/${t.assetId}`}>{t.assetName}</Link> : <span className="muted">unattributed</span>}</td>
                <td className="mono">{Object.entries(t.lastPayload ?? {}).map(([k, v]) => `${k}=${v}`).join("  ")}</td>
                <td>{key && <Spark points={t.recent.map((r) => Number(r.payload[key])).filter((n) => !Number.isNaN(n))} />}</td>
                <td title={time(t.lastAt)}>{ago(t.lastAt)}</td><td className="num">{t.messages}</td>
                <td>{t.openFindings.length ? t.openFindings.map((f) => <span key={f} className="pill pill-fail">{f}</span>)
                  : <span className="muted">none</span>}</td>
              </tr>);
          })}
          {q.data?.length === 0 && <tr><td colSpan={8} className="muted">No telemetry yet. Is the telemetry simulator running?</td></tr>}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
