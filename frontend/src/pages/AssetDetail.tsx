import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { apiAction, apiGet } from "../api";
import { ago, ErrorBox, Panel, Pill, SourceBadge, StepList, time, Value } from "../components/ui";
import type { AssetDetail as Asset, ProbeRun } from "../types";

export function AssetDetail() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
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
            <button className="btn" disabled={!a.deployAgent.enabled} title={a.deployAgent.reason}>DEPLOY AGENT</button>
            {!a.deployAgent.enabled && <div className="reason">{a.deployAgent.reason}</div>}
          </div>
        </div>
      </div>
      <ErrorBox error={run.error} />
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
