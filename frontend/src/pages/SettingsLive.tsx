import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiAction, apiGet, apiSend } from "../api";
import { useMe } from "../auth";
import { ErrorBox, Panel, Pill, ago } from "../components/ui";
import type { SafetyView, ScanScope, VaultProfile } from "../types";

const LEVELS = ["?", "0", "1", "2", "3", "3.5", "4", "DMZ"];

/** Live mode only: scan scope, safety controls and credential profiles. Admin-only writes. */
export function LiveSettings() {
  const me = useMe();
  const admin = me.data?.role === "ADMIN";
  return (
    <>
      <SafetyPanel admin={admin} />
      <ScopePanel admin={admin} />
      <VaultPanel admin={admin} />
    </>
  );
}

function SafetyPanel({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const safety = useQuery({ queryKey: ["safety"], queryFn: () => apiGet<SafetyView>("/safety"), refetchInterval: 5000 });
  const toggle = useMutation({
    mutationFn: (body: { enabled: boolean; reason: string }) => apiAction("/safety/safe-mode", body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["safety"] }); qc.invalidateQueries({ queryKey: ["environment"] }); },
  });
  const s = safety.data;
  const flip = () => {
    if (!s) return;
    const reason = window.prompt(`${s.safeMode ? "Turn OFF" : "Turn ON"} safe mode: reason (audited)`, "");
    if (reason && reason.trim().length >= 3) toggle.mutate({ enabled: !s.safeMode, reason: reason.trim() });
  };
  return (
    <Panel title="Safety" actions={admin && s && (
      <button className="btn btn-sm" disabled={toggle.isPending} onClick={flip}>
        {s.safeMode ? "Turn safe mode off" : "Turn safe mode on"}</button>)}>
      <ErrorBox error={safety.error ?? toggle.error} />
      {s && (
        <dl className="kv">
          <dt>Network activity</dt><dd>{s.armed ? <Pill value="OK" title="armed" /> : <Pill value="FAILED" title="stopped" />}
            {s.armed ? " armed" : ` STOPPED by ${s.changedBy}: ${s.reason}`}</dd>
          <dt>Safe mode</dt><dd>{s.safeMode ? "ON: every range uses the OT-sensitive limits, protocol plugins off" : "off"}</dd>
          <dt>Last change</dt><dd>{s.changedBy ? `${s.changedBy}, ${ago(s.changedAt)}: ${s.reason}` : "—"}</dd>
          <dt>Traffic since start</dt><dd className="mono">{s.traffic ? `${s.traffic.sent} operations · blocked ${
            Object.entries(s.traffic.blocked).map(([k, v]) => `${k} ${v}`).join(", ") || "none"} · rate-limited ${
            s.traffic.rateLimitedSec}s` : "—"}</dd>
          <dt>Running workflows</dt><dd className="mono">{s.runningWorkflows.join(", ") || "none"}</dd>
        </dl>)}
      <p className="hint">STOP ALL (top bar) closes the network gate at once and cancels running work. Operators and admins
        can stop; only an admin can re-arm. The state survives restarts.</p>
    </Panel>
  );
}

function ScopePanel({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const scope = useQuery({ queryKey: ["scope"], queryFn: () => apiGet<ScanScope[]>("/scope") });
  const blank = { cidr: "", kind: "INCLUDE", profile: "OT_SENSITIVE", level: "?", label: "", authorization: "" };
  const [form, setForm] = useState(blank);
  const refresh = () => ["scope", "zones", "environment", "safety"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
  const add = useMutation({ mutationFn: () => apiAction<ScanScope>("/scope", form),
    onSuccess: () => { setForm(blank); refresh(); } });
  const remove = useMutation({ mutationFn: (id: string) => apiSend("DELETE", `/scope/${id}`), onSuccess: refresh });
  const set = (k: keyof typeof blank) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const submit = (e: FormEvent) => { e.preventDefault(); add.mutate(); };
  return (
    <Panel title="Scan scope">
      <table className="dense"><thead><tr><th>Range</th><th>Kind</th><th>Profile</th><th>Level</th><th>Label</th>
        <th>Authorization</th><th>Added</th><th /></tr></thead>
        <tbody>{scope.data?.map((e) => (
          <tr key={e.id}><td className="mono">{e.cidr}</td>
            <td>{e.kind === "INCLUDE" ? <Pill value="OK" title="include" /> : <Pill value="FAILED" title="exclude" />}{e.kind}</td>
            <td>{e.kind === "INCLUDE" ? e.profile : "—"}</td><td>{e.kind === "INCLUDE" ? e.level : "—"}</td><td>{e.label}</td>
            <td className="muted small">{e.authorization}</td><td className="small">{e.createdBy}, {ago(e.createdAt)}</td>
            <td>{admin && <button className="btn btn-sm" disabled={remove.isPending}
              onClick={() => window.confirm(`Remove ${e.kind} ${e.cidr} from the scan scope?`) && remove.mutate(e.id)}>Remove</button>}</td>
          </tr>))}
          {scope.data?.length === 0 && <tr><td colSpan={8} className="muted">No scope: nothing is scanned.</td></tr>}
        </tbody></table>
      {admin && (
        <form className="form-grid" onSubmit={submit} style={{ marginTop: 16 }}>
          <label>Range (CIDR or single IP)<input className="mono" placeholder="10.20.1.0/24" value={form.cidr} onChange={set("cidr")} /></label>
          <label>Kind<select value={form.kind} onChange={set("kind")}>
            <option value="INCLUDE">INCLUDE (may be scanned)</option><option value="EXCLUDE">EXCLUDE (never touched)</option></select></label>
          <label>Safety profile<select value={form.profile} onChange={set("profile")} disabled={form.kind === "EXCLUDE"}>
            <option value="OT_SENSITIVE">OT-sensitive (10 pkt/s, 1 op/s per host)</option>
            <option value="IT">IT (50 pkt/s)</option></select></label>
          <label>Default Purdue level<select value={form.level} onChange={set("level")} disabled={form.kind === "EXCLUDE"}>
            {LEVELS.map((l) => <option key={l} value={l}>{l}</option>)}</select></label>
          <label className="wide">Label<input placeholder="Line 1 controllers" value={form.label} onChange={set("label")} /></label>
          <label className="full">Authorization (who approved scanning this range, and when)
            <input placeholder="Approved by plant manager, change ticket CHG-1234" value={form.authorization}
              onChange={set("authorization")} /></label>
          <div><button className="btn btn-primary" disabled={!form.cidr || add.isPending}>ADD TO SCOPE</button></div>
        </form>)}
      <ErrorBox error={scope.error ?? add.error ?? remove.error} />
      <p className="hint">Nothing outside an INCLUDE range is ever sent a packet. Exclusions always win. Ranges wider than
        /16 are refused. Every change is audited.</p>
    </Panel>
  );
}

function VaultPanel({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => apiGet<VaultProfile[]>("/vault/profiles") });
  const blank = { name: "OT-SNMPV3-RO", protocol: "SNMP", username: "", secret: "", description: "", version: "3",
    auth: "SHA-256", priv: "AES-128", privSecret: "", port: "" };
  const [form, setForm] = useState(blank);
  const set = (k: keyof typeof blank) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const save = useMutation({
    mutationFn: () => {
      const params: Record<string, string | number> = {};
      if (form.protocol === "SNMP") {
        params.version = form.version;
        if (form.version === "3") { params.auth = form.auth; params.priv = form.priv; if (form.privSecret) params.privSecret = form.privSecret; }
        if (form.port) params.port = Number(form.port);
      }
      return apiSend("PUT", `/vault/profiles/${encodeURIComponent(form.name)}`, { protocol: form.protocol,
        username: form.username || (form.version === "2c" ? "community" : ""), description: form.description,
        params, ...(form.secret ? { secret: form.secret } : {}) });
    },
    onSuccess: () => { setForm(blank); qc.invalidateQueries({ queryKey: ["vault"] }); },
  });
  const remove = useMutation({ mutationFn: (name: string) => apiSend("DELETE", `/vault/profiles/${encodeURIComponent(name)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vault"] }) });
  const snmp = form.protocol === "SNMP";
  return (
    <Panel title="Credential vault">
      <table className="dense"><thead><tr><th>Profile</th><th>Protocol</th><th>Username</th><th>Secret</th><th /></tr></thead>
        <tbody>{vault.data?.map((p) => (
          <tr key={p.name}><td className="mono">{p.name}</td><td>{p.protocol}</td><td className="mono">{p.username}</td>
            <td className="mono">{p.secret}</td>
            <td>{admin && <button className="btn btn-sm" onClick={() => window.confirm(`Delete profile ${p.name}?`) && remove.mutate(p.name)}>
              Delete</button>}</td></tr>))}
          {vault.data?.length === 0 && <tr><td colSpan={5} className="muted">No credentials yet.</td></tr>}
        </tbody></table>
      {admin && (
        <form className="form-grid" style={{ marginTop: 16 }} onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <label>Profile name<input className="mono" value={form.name} onChange={set("name")} /></label>
          <label>Protocol<select value={form.protocol} onChange={set("protocol")}>
            {["SNMP", "WinRM", "SSH", "MQTT"].map((p) => <option key={p}>{p}</option>)}</select></label>
          {snmp && <label>SNMP version<select value={form.version} onChange={set("version")}>
            <option value="3">v3 (authPriv)</option><option value="2c">v2c (community)</option></select></label>}
          {!(snmp && form.version === "2c") && <label>Username<input value={form.username} onChange={set("username")} /></label>}
          <label>{snmp && form.version === "2c" ? "Community" : snmp ? "Auth passphrase" : "Password"}
            <input type="password" autoComplete="new-password" placeholder="(unchanged if empty)" value={form.secret} onChange={set("secret")} /></label>
          {snmp && form.version === "3" && <>
            <label>Auth protocol<select value={form.auth} onChange={set("auth")}>
              {["SHA-256", "SHA-512", "SHA", "MD5"].map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>Privacy protocol<select value={form.priv} onChange={set("priv")}>
              {["AES-128", "AES-256", "DES", "NONE"].map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>Privacy passphrase<input type="password" autoComplete="new-password" placeholder="(same as auth if empty)"
              value={form.privSecret} onChange={set("privSecret")} /></label></>}
          {snmp && <label>UDP port<input className="narrow" placeholder="161" value={form.port} onChange={set("port")} /></label>}
          <label className="wide">Description<input value={form.description} onChange={set("description")} /></label>
          <div><button className="btn btn-primary" disabled={!form.name || save.isPending}>SAVE PROFILE</button></div>
        </form>)}
      <ErrorBox error={vault.error ?? save.error ?? remove.error} />
      <p className="hint">Secrets are encrypted at rest and write-only: the API never returns them. Discovery and probes use
        OT-SNMPV3-RO, OT-WINDOWS-READONLY and OT-LINUX-SSH-RO by default.</p>
    </Panel>
  );
}
