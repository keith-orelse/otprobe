import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { apiGet } from "../api";
import { ErrorBox, Panel, SourceBadge, Value } from "../components/ui";
import type { CompareCell, Comparison } from "../types";

const STRONG = new Set(["Full", "Detailed", "Collected", "Yes"]);
const WEAK = new Set(["Not collected", "No", "N/A"]);

function Cell({ c }: { c: CompareCell }) {
  const tone = STRONG.has(c.level) ? "lvl-strong" : WEAK.has(c.level) ? "lvl-weak" : "lvl-mid";
  return (
    <td>
      <span className={`lvl ${tone}`}>{c.level}</span>
      {c.value != null && c.value !== "" && <> <Value value={c.value} /></>}
      {c.source && <> <SourceBadge source={c.source} /></>}
      {c.detail && <div className="muted small">{c.detail}</div>}
    </td>
  );
}

export function ComparisonTable({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["asset", id, "compare"], queryFn: () => apiGet<Comparison>(`/assets/${id}/comparison`) });
  if (q.error) return <ErrorBox error={q.error} />;
  const c = q.data;
  if (!c) return <div className="muted">Loading…</div>;
  return (
    <Panel title="Agentless vs Deep Agent">
      <p className="hint compare-hint">Computed from what was actually collected (provenance stages AGENTLESS and DEEP), not from a
        static table.{!c.hasDeepEvidence && " No deep evidence yet: deploy an agent and run an assessment."}</p>
      <table className="dense compare">
        <thead><tr><th>Capability</th><th>Agentless probe</th><th>Deep agent</th></tr></thead>
        <tbody>{c.rows.map((r) => (
          <tr key={r.capability}><th>{r.capability}</th><Cell c={r.agentless} /><Cell c={r.deep} /></tr>))}
        </tbody>
      </table>
    </Panel>
  );
}

/** Standalone route kept for deep links (/assets/:id/compare). */
export function Compare() {
  const { id = "" } = useParams();
  return (
    <div className="page">
      <div className="crumbs"><Link to="/assets">Assets</Link> / <Link to={`/assets/${id}?tab=compare`}>asset</Link> / comparison</div>
      <ComparisonTable id={id} />
    </div>
  );
}
