import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useEnvironment } from "../components/Safety";
import { apiAction, apiGet } from "../api";
import { onServerEvent } from "../events";
import { ErrorBox, Panel, Pill, Progress, StepList, time } from "../components/ui";
import type { DiscoveryJob, DiscoveryMethod, Observation, Page, VaultProfile, Zone } from "../types";

export function Discovery() {
  const qc = useQueryClient();
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => apiGet<Zone[]>("/zones") });
  const jobs = useQuery({ queryKey: ["discovery", "jobs"], queryFn: () => apiGet<Page<DiscoveryJob>>("/discovery/jobs", { limit: 20 }) });
  const catalogue = useQuery({ queryKey: ["discovery", "methods"], queryFn: () => apiGet<DiscoveryMethod[]>("/discovery/methods") });
  const [targets, setTargets] = useState<string[]>([]);
  const [methods, setMethods] = useState<string[]>([]);
  useEffect(() => { if (catalogue.data && methods.length === 0) setMethods(catalogue.data.map((m) => m.method)); }, [catalogue.data]);
  const [selected, setSelected] = useState<string | null>(null);
  const env = useEnvironment();
  const live = env.data?.mode === "LIVE";
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => apiGet<VaultProfile[]>("/vault/profiles"), enabled: live });
  const snmpProfiles = (vault.data ?? []).filter((p) => p.protocol === "SNMP");
  const [snmpProfile, setSnmpProfile] = useState("");
  const [custom, setCustom] = useState("");
  const scannable = (zones.data ?? []).filter((z) => z.scannable);
  useEffect(() => { if (zones.data && targets.length === 0 && !live) setTargets(scannable.map((z) => z.cidr)); }, [zones.data, live]);
  const all = [...targets, ...custom.split(/[\s,]+/).filter(Boolean)];

  const start = useMutation({
    mutationFn: () => apiAction<DiscoveryJob>("/discovery/jobs", { targets: all, methods,
      ...(snmpProfile ? { snmpProfile } : {}) }),
    onSuccess: (job) => { setSelected(job.id); qc.invalidateQueries({ queryKey: ["discovery"] }); },
  });
  const current = selected ?? jobs.data?.items[0]?.id ?? null;
  const toggle = (list: string[], v: string) => (list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div className="page">
      <Panel title="New discovery job">
        <div className="form-row">
          <fieldset><legend>{live ? "Targets (approved scan scope only)" : "Targets (simulated zones only)"}</legend>
            {live && scannable.length === 0 && (
              <div className="hint">No scan scope configured. An admin adds approved subnets under
                <Link to="/settings"> Settings → Scan scope</Link>. Until then nothing is scanned.</div>)}
            {scannable.map((z) => (
              <label key={z.id} className="check">
                <input type="checkbox" checked={targets.includes(z.cidr)} onChange={() => setTargets(toggle(targets, z.cidr))} />
                <span className="mono">{z.cidr}</span> {z.name}
                {z.safeMode && <span className="pill pill-warn" title={z.description}>{live ? "OT-SENSITIVE" : "SAFE MODE"}</span>}
              </label>
            ))}
            {live && scannable.length > 0 && (
              <label className="field">Or a host / smaller subnet inside the scope
                <input className="mono" placeholder="10.20.1.15  or  10.20.1.0/28" value={custom}
                  onChange={(e) => setCustom(e.target.value)} /></label>)}
          </fieldset>
          <fieldset><legend>Methods</legend>
            {catalogue.data?.map((m) => (
              <label key={m.method} className="check" title={m.description}>
                <input type="checkbox" checked={methods.includes(m.method)} onChange={() => setMethods(toggle(methods, m.method))} />
                {m.method} {m.label !== m.method && <span className="muted small">{m.label}</span>}
              </label>
            ))}
          </fieldset>
          {live && methods.includes("SNMP") && (
            <fieldset><legend>SNMP credential</legend>
              <select value={snmpProfile} onChange={(e) => setSnmpProfile(e.target.value)}>
                <option value="">OT-SNMPV3-RO (default)</option>
                {snmpProfiles.map((p) => <option key={p.name} value={p.name}>{p.name} ({p.username})</option>)}
              </select>
              {snmpProfiles.length === 0 && <div className="hint">No SNMP profile in the vault: the SNMP step is skipped.</div>}
            </fieldset>)}
          <div className="form-actions">
            <button className="btn btn-primary" disabled={!all.length || !methods.length || start.isPending}
              onClick={() => start.mutate()}>START DISCOVERY</button>
          </div>
        </div>
        {live
          ? <p className="hint">Order: ICMP sweep, then the kernel ARP table (local segments), then TCP connect and SNMP GET on
              hosts already seen. OT-sensitive ranges and safe mode: ≤10 packets/s per range, ≤1 operation/s per host. Every
              packet passes the scope check; STOP ALL halts everything at once.</p>
          : <p className="hint">Level 0/1 zones run in SAFE MODE: passive ARP, rate-limited ICMP (≤1 op/s per host), SNMP
              GET-only with a read-only profile. No WinRM/WMI. No ICMP reply does not mean a device is offline.</p>}
        <ErrorBox error={start.error} />
      </Panel>
      {current && <JobDetail id={current} />}
      <Panel title="Discovery history">
        <ErrorBox error={jobs.error} />
        <table className="dense clickable"><thead><tr><th>Started</th><th>Targets</th><th>Methods</th><th>Status</th>
          <th>Progress</th><th className="num">Devices</th><th className="num">New</th><th className="num">Rogue</th><th>By</th></tr></thead>
          <tbody>{jobs.data?.items.map((j) => (
            <tr key={j.id} className={j.id === current ? "selected" : ""} onClick={() => setSelected(j.id)}>
              <td className="mono">{time(j.startedAt ?? j.createdAt)}</td><td className="mono">{j.targets.join(", ")}</td>
              <td>{j.methods.join(" · ")}</td><td><Pill value={j.status} /></td><td><Progress value={j.progress} /></td>
              <td className="num">{j.devicesFound}</td><td className="num">{j.newAssets}</td>
              <td className="num">{j.rogueCount ? <Pill value="ROGUE" title={`${j.rogueCount}`} /> : 0}</td><td>{j.requestedBy}</td>
            </tr>))}
          </tbody></table>
      </Panel>
    </div>
  );
}

interface Found { ip: string; mac: string | null; assetId: string; new: boolean; rogue: boolean }

function JobDetail({ id }: { id: string }) {
  const job = useQuery({ queryKey: ["discovery", "job", id], queryFn: () => apiGet<DiscoveryJob>(`/discovery/jobs/${id}`) });
  const obs = useQuery({ queryKey: ["discovery", "obs", id],
    queryFn: () => apiGet<Page<Observation>>(`/discovery/jobs/${id}/observations`, { limit: 200 }) });
  const [feed, setFeed] = useState<Found[]>([]);
  useEffect(() => {
    setFeed([]);
    return onServerEvent((e) => {
      if (e.type === "discovery.device_found" && e.entity.id === id) setFeed((f) => [...f, e.data as Found]);
    });
  }, [id]);
  const j = job.data;
  if (!j) return null;
  const cancel = () => apiAction(`/discovery/jobs/${id}/cancel`);
  return (
    <div className="grid-2">
      <Panel title={<>Job <span className="mono">{id.slice(0, 8)}</span> <Pill value={j.status} /></>}
        actions={j.actions.cancel?.enabled && <button className="btn btn-sm" onClick={cancel}>Cancel</button>}>
        <Progress value={j.progress} />
        <StepList steps={j.steps} />
        {j.error && <div className="error-box">{j.error}</div>}
        <div className="muted mono small">correlation {j.correlationId}</div>
      </Panel>
      <Panel title={`Devices observed (${j.devicesFound})`}>
        {feed.length > 0 && (
          <div className="feed">{feed.map((f) => (
            <div key={f.assetId} className="feed-item"><span className="mono">{f.ip}</span> <span className="mono muted">{f.mac ?? "no MAC (remote)"}</span>
              {f.new && <span className="pill pill-info">NEW</span>}{f.rogue && <span className="pill pill-fail">ROGUE</span>}</div>))}
          </div>
        )}
        <table className="dense"><thead><tr><th>IP</th><th>MAC</th><th>Method</th><th>Response</th><th /></tr></thead>
          <tbody>{obs.data?.items.map((o) => (
            <tr key={o.id}><td className="mono">{o.ip}</td><td className="mono">{o.mac ?? "—"}</td><td>{o.method}</td>
              <td>{o.responded ? <Pill value="OK" /> : <Pill value={String(o.result["reachability.icmp"] ?? "NO REPLY")} />}</td>
              <td>{o.assetId && <Link to={`/assets/${o.assetId}`}>asset →</Link>}</td></tr>))}
          </tbody></table>
      </Panel>
    </div>
  );
}
