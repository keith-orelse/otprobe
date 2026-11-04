import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { apiGet } from "../api";
import { duration, ErrorBox, Panel, Pill, StepList, time, Value } from "../components/ui";
import type { Page, ProbeRun } from "../types";

export function Probes() {
  const [params, setParams] = useSearchParams();
  const selected = params.get("id");
  const runs = useQuery({ queryKey: ["probes", "list"], queryFn: () => apiGet<Page<ProbeRun>>("/probes", { limit: 50 }) });
  return (
    <div className="page">
      <p className="hint">Probes run from an asset page (RUN AGENTLESS PROBE). Each protocol step and every collected
        field records its source.</p>
      <ErrorBox error={runs.error} />
      <table className="dense clickable">
        <thead><tr><th>Started</th><th>Asset</th><th>Status</th><th>Classification</th><th>Eligibility</th><th>Duration</th><th>By</th></tr></thead>
        <tbody>{runs.data?.items.map((r) => (
          <tr key={r.id} className={r.id === selected ? "selected" : ""} onClick={() => setParams({ id: r.id })}>
            <td className="mono">{time(r.startedAt ?? r.createdAt)}</td>
            <td><Link to={`/assets/${r.assetId}`} onClick={(e) => e.stopPropagation()}>{r.assetName}</Link></td>
            <td><Pill value={r.status} /></td>
            <td>{r.classification ? `${r.classification.type} (${r.classification.confidence}%)` : <span className="muted">—</span>}</td>
            <td><Pill value={r.eligibility} title={r.eligibilityReason ?? ""} /></td>
            <td className="mono">{duration(r.startedAt, r.finishedAt)}</td><td>{r.requestedBy}</td>
          </tr>))}
          {runs.data?.items.length === 0 && <tr><td colSpan={7} className="muted">No probes yet.</td></tr>}
        </tbody>
      </table>
      {selected && <ProbeDetail id={selected} />}
    </div>
  );
}

function ProbeDetail({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["probes", id], queryFn: () => apiGet<ProbeRun>(`/probes/${id}`) });
  const p = q.data;
  if (!p) return null;
  return (
    <div className="grid-2">
      <Panel title={<>Probe of {p.assetName} <Pill value={p.status} /></>}>
        <StepList steps={p.steps} />
        <div className="muted mono small">correlation {p.correlationId}</div>
      </Panel>
      <Panel title="Raw protocol results">
        {p.results.map((r, i) => (
          <details key={i} className="result">
            <summary><b>{r.protocol}</b> <Pill value={r.status} /> {r.latencyMs != null && <span className="muted mono">{r.latencyMs} ms</span>}
              {r.errorDetail && <span className="muted"> · {r.errorDetail}</span>}</summary>
            {r.stages.length > 0 && <div className="stages">{r.stages.map((s) => (
              <span key={s.name} className={`stage ${s.status === "OK" ? "stage-ok" : "stage-fail"}`} title={s.detail}>{s.name}</span>))}</div>}
            <table className="dense fields"><tbody>{Object.entries(r.data).map(([k, v]) => (
              <tr key={k}><th className="mono">{k}</th><td><Value value={v} /></td></tr>))}</tbody></table>
          </details>
        ))}
      </Panel>
    </div>
  );
}
