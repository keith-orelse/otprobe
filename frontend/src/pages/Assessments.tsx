import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiGet } from "../api";
import { ErrorBox, Panel, Pill, time, Value } from "../components/ui";
import type { AssessmentRun, Page } from "../types";

export function Score({ score, unknown }: { score: number | null | undefined; unknown?: number }) {
  if (score == null) return <span className="muted">—</span>;
  const tone = score >= 90 ? "ok" : score >= 70 ? "warn" : "fail";
  return <span className={`score score-${tone}`}>{score}%{unknown ? <span className="muted"> · {unknown} unknown</span> : null}</span>;
}

export function Counts({ c }: { c: Record<string, number> }) {
  return (
    <span className="counts">
      <span className="c-pass">{c.pass ?? 0} pass</span><span className="c-fail">{c.fail ?? 0} fail</span>
      <span className="c-warn">{c.warning ?? 0} warning</span><span className="c-unk">{c.unknown ?? 0} unknown</span>
    </span>
  );
}

export function Assessments() {
  const nav = useNavigate();
  const q = useQuery({ queryKey: ["assessments", "list"], queryFn: () => apiGet<Page<AssessmentRun>>("/assessments", { limit: 100 }) });
  return (
    <div className="page">
      <p className="hint">Deep assessments run on the agent (it collects evidence; the server evaluates the data-driven
        rules in <span className="mono">rules/</span>). Agentless runs are evaluated after each probe using only rules that
        accept agentless evidence. Score = weighted pass rate, UNKNOWN excluded and shown separately.</p>
      <ErrorBox error={q.error} />
      <table className="dense clickable">
        <thead><tr><th>Created</th><th>Asset</th><th>Policy</th><th>Source</th><th>Trigger</th><th>Status</th>
          <th>Score</th><th>Results</th><th>By</th></tr></thead>
        <tbody>{q.data?.items.map((r) => (
          <tr key={r.id} onClick={() => nav(`/assessments/${r.id}`)}>
            <td className="mono">{time(r.createdAt)}</td><td>{r.assetName}</td>
            <td className="mono small">{r.policyKey}@{r.policyVersion}</td><td><Pill value={r.source} /></td>
            <td>{r.trigger}</td><td><Pill value={r.status} /></td><td><Score score={r.score} /></td>
            <td>{r.status === "EVALUATED" && <Counts c={r.counts} />}</td><td>{r.requestedBy}</td>
          </tr>))}
          {q.data?.items.length === 0 && <tr><td colSpan={9} className="muted">No assessments yet.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

export function AssessmentDetail() {
  const { id = "" } = useParams();
  const q = useQuery({ queryKey: ["assessments", id], queryFn: () => apiGet<AssessmentRun>(`/assessments/${id}`) });
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data;
  if (!r) return <div className="muted">Loading…</div>;
  return (
    <div className="page">
      <div className="crumbs"><Link to="/assessments">Assessments</Link> / {r.id.slice(0, 8)}</div>
      <h1>{r.policyKey} on <Link to={`/assets/${r.assetId}`}>{r.assetName}</Link> <Pill value={r.status} /> <Pill value={r.source} /></h1>
      <div className="meta"><span>{r.trigger} by {r.requestedBy}</span><span>{time(r.finishedAt ?? r.createdAt)}</span>
        {r.previousRunId && <Link to={`/assessments/${r.previousRunId}`}>previous run</Link>}
        <span className="mono">correlation {r.correlationId}</span></div>
      {r.error && <div className="error-box">{r.error}</div>}
      {r.status === "EVALUATED" && <div className="kpis kpis-4">
        <div className="kpi"><span>Compliance score</span><b><Score score={r.score} /></b></div>
        <div className="kpi kpi-ok"><span>Pass</span><b>{r.counts.pass}</b></div>
        <div className="kpi kpi-fail"><span>Fail / warning</span><b>{r.counts.fail} / {r.counts.warning}</b></div>
        <div className="kpi"><span>Unknown (excluded)</span><b>{r.counts.unknown}</b></div>
      </div>}
      {r.driftEvents.length > 0 && (
        <Panel title="Configuration drift detected">
          <table className="dense"><tbody>{r.driftEvents.map((d) => (
            <tr key={d.id}><td className="mono">{d.ruleId}</td><td><Pill value={d.fromStatus} /> → <Pill value={d.toStatus} /></td>
              <td className="mono">{d.evidencePath}: <Value value={d.before} /> → <Value value={d.after} /></td>
              <td>{d.findingId && <Link to={`/findings/${d.findingId}`}>finding →</Link>}</td></tr>))}
          </tbody></table>
        </Panel>)}
      <Panel title="Rule results">
        <table className="dense">
          <thead><tr><th>Rule</th><th>Title</th><th>Status</th><th>Previous</th><th>Severity</th><th>Evidence</th>
            <th>Observed</th><th>Expected</th><th>Note</th></tr></thead>
          <tbody>{r.results.map((x) => (
            <tr key={x.ruleId} className={x.previousStatus === "PASS" && ["FAIL", "WARNING"].includes(x.status) ? "drift-row" : ""}>
              <td className="mono">{x.ruleId}</td><td>{x.title}</td><td><Pill value={x.status} /></td>
              <td>{x.previousStatus ? <Pill value={x.previousStatus} /> : <span className="muted">—</span>}</td>
              <td><Pill value={x.severity} /></td><td className="mono small">{x.evidencePath}</td>
              <td><Value value={x.observed} /></td><td className="small">{x.expected}</td>
              <td className="small muted">{x.message ?? x.references.join(", ")}</td>
            </tr>))}
          </tbody>
        </table>
      </Panel>
      <div className="grid-2">
        <Panel title={`Configuration changes vs previous run (${r.evidenceChanges.length})`}>
          {r.evidenceChanges.length ? <table className="dense"><tbody>{r.evidenceChanges.map((c) => (
            <tr key={c.path}><td className="mono small">{c.path}</td><td><Value value={c.before} /></td><td>→</td><td><Value value={c.after} /></td></tr>))}
          </tbody></table> : <p className="muted">{r.previousRunId ? "No changes." : "First run: nothing to compare."}</p>}
        </Panel>
        <Panel title="Evidence document">
          {r.evidence ? <details><summary>Show uploaded evidence ({Object.keys(r.evidence).length} sections)</summary>
            <pre className="evidence">{JSON.stringify(r.evidence, null, 2)}</pre></details> : <p className="muted">No evidence.</p>}
        </Panel>
      </div>
    </div>
  );
}
