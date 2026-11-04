import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ago, ErrorBox, Panel, Pill, SourceBadge, StepList, time, Value } from "../components/ui";
import type { Agent, AssessmentRun, AssetDetail as Asset, Deployment, Finding, Package, Page, ProbeRun } from "../types";
import { Counts, Score } from "./Assessments";

export function AssetDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [requesting, setRequesting] = useState(false);
  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => apiGet<Asset>(`/assets/${id}`) });
  const probeId = asset.data?.lastProbeId;
  const probe = useQuery({ queryKey: ["probes", probeId], enabled: !!probeId,
    queryFn: () => apiGet<ProbeRun>(`/probes/${probeId}`) });
  const run = useMutation({
    mutationFn: () => apiAction<ProbeRun>(`/assets/${id}/probes`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset", id] }),
  });
  if (asset.error) return <ErrorBox error={asset.error} />;
  const a = asset.data;
  if (!a) return <div className="muted">Loading…</div>;

  return (
    <div className="page">
      <div className="crumbs"><Link to="/assets">Assets</Link> / {a.displayName}</div>
      <div className="asset-head">
        <div>
          <h1>{a.displayName} {a.isRogue && <Pill value="ROGUE" />}</h1>
          <div className="meta">
            <span className="mono">{a.ip}</span><span className="mono">{a.mac}</span>
            <span>{a.type ?? "unclassified"}</span><span>L{a.level}</span>
            {a.zone && <span>{a.zone.name}</span>}<Pill value={a.status} /><span className="muted">last seen {ago(a.lastSeen)}</span>
          </div>
        </div>
        <div className="actions">
          <button className="btn btn-primary" disabled={!a.agentless.enabled || run.isPending} title={a.agentless.reason}
            onClick={() => run.mutate()}>RUN AGENTLESS PROBE</button>
          <div className="action-with-reason">
            <button className="btn" disabled={!a.deployAgent.enabled} title={a.deployAgent.reason}
              onClick={() => setRequesting(true)}>DEPLOY AGENT</button>
            <div className={a.deployAgent.enabled ? "reason reason-ok" : "reason"}>{a.deployAgent.reason}</div>
          </div>
        </div>
      </div>
      <ErrorBox error={run.error} />
      {requesting && <DeployRequest asset={a} onClose={() => setRequesting(false)} />}
      {a.currentAgentId && <AgentStrip id={a.currentAgentId} />}
      {a.compliance && <ComplianceStrip asset={a} />}
      {a.notes.map((n) => <div key={n} className="note">{n}</div>)}

      <div className="grid-3">
        <Panel title="Classification">
          {a.classification ? (
            <>
              <div className="cls-type">{a.classification.type}</div>
              <div className="confidence"><div style={{ width: `${a.classification.confidence}%` }} />
                <span>{a.classification.confidence}% confidence</span></div>
              <table className="dense"><thead><tr><th>Evidence</th><th>Observed</th><th className="num">Weight</th></tr></thead>
                <tbody>{a.classification.evidence.map((e) => (
                  <tr key={e.signal}><td>{e.signal}<div className="muted mono small">{e.field}</div></td>
                    <td><Value value={e.value} /></td><td className="num">{e.weight}</td></tr>))}
                </tbody></table>
            </>
          ) : <p className="muted">Not classified yet. Discovery alone yields IP, MAC, reachability and (where SNMP works)
            sysName/vendor/model. Run an agentless probe.</p>}
        </Panel>
        <Panel title="Agent eligibility">
          <Pill value={a.eligibility} />
          <p>{a.eligibilityReason}</p>
          <table className="kv"><tbody>
            <tr><th>Agentless</th><td>{a.agentless.reason}</td></tr>
            <tr><th>Agent state</th><td><Pill value={a.agentState} /></td></tr>
            <tr><th>Criticality</th><td><Pill value={a.criticality} /></td></tr>
            <tr><th>Discovered by</th><td>{a.discoveredBy.map((m) => <SourceBadge key={m} source={m} />)}</td></tr>
            <tr><th>First seen</th><td>{time(a.firstSeen)}</td></tr>
            <tr><th>Last probe</th><td>{time(a.lastProbeAt)}</td></tr>
          </tbody></table>
        </Panel>
        <Panel title={<>Agentless probe {probe.data && <Pill value={probe.data.status} />}</>}
          actions={probe.data && <Link to={`/probes?id=${probe.data.id}`}>details →</Link>}>
          {probe.data ? <StepList steps={probe.data.steps} /> : <p className="muted">No probe has run on this asset.</p>}
        </Panel>
      </div>

      <div className="groups">
        {Object.entries(a.groups).map(([group, fields]) => (
          <Panel key={group} title={group}>
            <table className="dense fields"><tbody>
              {fields.map((f) => (
                <tr key={f.path}><th className="mono">{f.path}</th><td><Value value={f.value} /></td>
                  <td className="src-cell"><SourceBadge source={f.source} label={f.sourceLabel} stage={f.stage} /></td>
                  <td className="muted small" title={f.collectedAt}>{f.stage.toLowerCase()} · {ago(f.collectedAt)}</td></tr>
              ))}
            </tbody></table>
          </Panel>
        ))}
      </div>

      {a.relationships.length > 0 && (
        <Panel title="Observed relationships">
          <table className="dense"><thead><tr><th>Kind</th><th>Direction</th><th>Peer</th><th>Protocol</th><th>Port</th><th>Source</th></tr></thead>
            <tbody>{a.relationships.map((r, i) => (
              <tr key={i}><td>{r.kind}</td><td>{r.direction}</td><td><Link to={`/assets/${r.peerAssetId}`}>{r.peerName}</Link></td>
                <td>{r.protocol}</td><td className="mono">{r.port ?? "—"}</td><td><SourceBadge source={r.source} /></td></tr>))}
            </tbody></table>
        </Panel>
      )}
    </div>
  );
}

function isoLocal(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function DeployRequest({ asset, onClose }: { asset: Asset; onClose: () => void }) {
  const nav = useNavigate();
  const packages = useQuery({ queryKey: ["packages"], queryFn: () => apiGet<Package[]>("/packages") });
  const [pkg, setPkg] = useState("");
  const [purpose, setPurpose] = useState("Deep compliance monitoring");
  const [useWindow, setUseWindow] = useState(asset.maintenanceWindowRequired);
  const [start, setStart] = useState(isoLocal(new Date()));
  const [end, setEnd] = useState(isoLocal(new Date(Date.now() + 2 * 3600_000)));
  const active = (packages.data ?? []).filter((p) => p.status === "ACTIVE");
  const selected = pkg || active[0]?.id || "";
  const submit = useMutation({
    mutationFn: () => apiAction<Deployment>("/deployments", {
      assetId: asset.id, packageId: selected, purpose,
      maintenanceWindow: useWindow ? { start: new Date(start).toISOString(), end: new Date(end).toISOString() } : null,
    }),
    onSuccess: (d) => nav(`/deployments/${d.id}`),
  });
  return (
    <Panel title={`Request agent deployment · ${asset.displayName}`} actions={<button className="btn btn-sm" onClick={onClose}>Close</button>}>
      <div className="form-grid">
        <label>Package
          <select value={selected} onChange={(e) => setPkg(e.target.value)}>
            {packages.data?.map((p) => (
              <option key={p.id} value={p.id} disabled={p.status !== "ACTIVE"}>
                {p.name} {p.version} ({p.architecture}) · {p.status}</option>))}
          </select>
        </label>
        <label>Credential profile<input value="OT-WINDOWS-INSTALLER" disabled /></label>
        <label className="wide">Purpose<input value={purpose} onChange={(e) => setPurpose(e.target.value)} /></label>
        <label className="check"><input type="checkbox" checked={useWindow} disabled={asset.maintenanceWindowRequired}
          onChange={(e) => setUseWindow(e.target.checked)} />Maintenance window
          {asset.maintenanceWindowRequired && <span className="pill pill-warn">REQUIRED</span>}</label>
        {useWindow && <>
          <label>Start<input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} /></label>
          <label>End<input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} /></label>
        </>}
      </div>
      <button className="btn btn-primary" disabled={!selected || submit.isPending} onClick={() => submit.mutate()}>
        SUBMIT FOR APPROVAL</button>
      <p className="hint">The request needs an approver who is not you. Precheck and deployment run after approval.</p>
      <ErrorBox error={submit.error} />
    </Panel>
  );
}

function AgentStrip({ id }: { id: string }) {
  const agent = useQuery({ queryKey: ["agents", id], queryFn: () => apiGet<Agent>(`/agents/${id}`), refetchInterval: 2000 });
  const a = agent.data;
  if (!a) return null;
  return (
    <div className="agent-strip">
      <span>Probe Agent <b className="mono">{a.id.slice(0, 8)}</b> v{a.version}</span>
      <Pill value={a.status} />
      <span>Last heartbeat: {a.secondsSinceHeartbeat == null ? "—" : `${a.secondsSinceHeartbeat} seconds ago`}</span>
      <Link to={`/agents/${a.id}`}>agent →</Link>
    </div>
  );
}

function ComplianceStrip({ asset }: { asset: Asset }) {
  const qc = useQueryClient();
  const c = asset.compliance!;
  const findings = useQuery({ queryKey: ["findings", "asset", asset.id],
    queryFn: () => apiGet<Page<Finding>>("/findings", { assetId: asset.id, status: "OPEN,REOPENED,ACCEPTED_RISK" }) });
  const run = useMutation({
    mutationFn: () => apiAction<AssessmentRun>(`/assets/${asset.id}/assessments`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["asset", asset.id] }),
  });
  return (
    <Panel title="Compliance · Windows Engineering Baseline" actions={<>
      <Link to={`/assets/${asset.id}/compare`}>Agentless vs Deep Agent →</Link>{" "}
      {c.lastRunId && <Link to={`/assessments/${c.lastRunId}`}>last run →</Link>}</>}>
      <div className="compliance">
        <div><span className="muted small">Score</span><div className="big"><Score score={c.score} /></div>
          {c.source && <span className="muted small">from {c.source.toLowerCase()} run</span>}</div>
        <div><span className="muted small">Results</span><div>{c.score != null ? <Counts c={c.counts} /> : "—"}</div></div>
        <div><span className="muted small">Last assessment</span><div>{time(c.lastAssessmentAt)}</div>
          {c.lastDeepStatus && <Pill value={c.lastDeepStatus} />}</div>
        <div><span className="muted small">Next scheduled</span><div>{time(c.nextAssessmentAt)}</div></div>
        <div><span className="muted small">Open findings</span><div className="big">{c.openFindings}</div></div>
        <div className="action-with-reason">
          <button className="btn btn-primary" disabled={!c.runAction.enabled || run.isPending} title={c.runAction.reason}
            onClick={() => run.mutate()}>RUN DEEP ASSESSMENT</button>
          <div className={c.runAction.enabled ? "reason reason-ok" : "reason"}>{c.runAction.reason}</div>
        </div>
      </div>
      <ErrorBox error={run.error} />
      {findings.data && findings.data.items.length > 0 && (
        <table className="dense"><tbody>{findings.data.items.map((f) => (
          <tr key={f.id}><td><Pill value={f.severity} /></td><td><Pill value={f.status} /></td>
            <td className="mono"><Link to={`/findings/${f.id}`}>{f.ruleId}</Link></td><td>{f.title}</td>
            <td><Value value={f.observed} /></td><td><Pill value={f.source} /></td></tr>))}
        </tbody></table>)}
    </Panel>
  );
}
