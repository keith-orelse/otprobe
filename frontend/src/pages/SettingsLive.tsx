import { FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiAction, apiGet, apiSend } from "../api";
import { useMe } from "../auth";
import { ErrorBox, Panel, Pill, ago } from "../components/ui";
import type { AgentBuild, PluginInfo, SafetyView, ScanScope, VaultProfile } from "../types";

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
      <BuildsPanel admin={admin} />
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
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: () => apiGet<PluginInfo[]>("/plugins") });
  const blank = { cidr: "", kind: "INCLUDE", profile: "OT_SENSITIVE", level: "?", label: "", authorization: "",
    plugins: [] as string[] };
  const [form, setForm] = useState(blank);
  const togglePlugin = (list: string[], name: string) => list.includes(name) ? list.filter((x) => x !== name) : [...list, name];
  const patchPlugins = useMutation({
    mutationFn: ({ id, list }: { id: string; list: string[] }) => apiSend("PATCH", `/scope/${id}`, { plugins: list }),
    onSuccess: refreshScope });
  function refreshScope() { ["scope", "zones", "environment", "safety"].forEach((k) => qc.invalidateQueries({ queryKey: [k] })); }
  const refresh = refreshScope;
  const add = useMutation({ mutationFn: () => apiAction<ScanScope>("/scope", form),
    onSuccess: () => { setForm(blank); refresh(); } });
  const remove = useMutation({ mutationFn: (id: string) => apiSend("DELETE", `/scope/${id}`), onSuccess: refresh });
  const set = (k: keyof typeof blank) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const submit = (e: FormEvent) => { e.preventDefault(); add.mutate(); };
  return (
    <Panel title="Scan scope">
      <table className="dense"><thead><tr><th>Range</th><th>Kind</th><th>Profile</th><th>Level</th><th>Label</th>
        <th>OT plugins</th><th>Authorization</th><th>Added</th><th /></tr></thead>
        <tbody>{scope.data?.map((e) => (
          <tr key={e.id}><td className="mono">{e.cidr}</td>
            <td>{e.kind === "INCLUDE" ? <Pill value="OK" title="include" /> : <Pill value="FAILED" title="exclude" />}{e.kind}</td>
            <td>{e.kind === "INCLUDE" ? e.profile : "—"}</td><td>{e.kind === "INCLUDE" ? e.level : "—"}</td><td>{e.label}</td>
            <td className="small">{e.kind !== "INCLUDE" ? "—" : (plugins.data ?? []).map((pl) => {
              const on = e.plugins.includes(pl.name);
              const implied = !on && e.profile === "IT" && !pl.udp;
              return (
                <button key={pl.name} type="button" disabled={!admin || patchPlugins.isPending}
                  className={`pchip${on ? " pchip-on" : implied ? " pchip-implied" : ""}`}
                  title={on ? "Enabled on this range" : implied ? "On by default for IT ranges" : "Off for this range"}
                  onClick={() => patchPlugins.mutate({ id: e.id, list: togglePlugin(e.plugins, pl.name) })}>{pl.name}</button>);
            })}</td>
            <td className="muted small">{e.authorization}</td><td className="small">{e.createdBy}, {ago(e.createdAt)}</td>
            <td>{admin && <button className="btn btn-sm" disabled={remove.isPending}
              onClick={() => window.confirm(`Remove ${e.kind} ${e.cidr} from the scan scope?`) && remove.mutate(e.id)}>Remove</button>}</td>
          </tr>))}
          {scope.data?.length === 0 && <tr><td colSpan={9} className="muted">No scope: nothing is scanned.</td></tr>}
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
          {form.kind === "INCLUDE" && (
            <fieldset className="full"><legend>Read-only OT plugins for this range</legend>
              {(plugins.data ?? []).map((pl) => (
                <label key={pl.name} className="check" title={`${pl.label} · ports ${pl.udp ? "UDP" : pl.ports.join(", ")} · risk ${pl.risk}`}>
                  <input type="checkbox" checked={form.plugins.includes(pl.name) || (form.profile === "IT" && !pl.udp)}
                    disabled={form.profile === "IT" && !pl.udp}
                    onChange={() => setForm({ ...form, plugins: togglePlugin(form.plugins, pl.name) })} />
                  {pl.label}{pl.risk !== "LOW" && <span className="pill pill-warn">{pl.risk} risk</span>}
                </label>))}
              <div className="hint">IT ranges: TCP plugins run by default. OT-sensitive ranges: only what is ticked here.
                Safe mode turns all plugins off.</div>
            </fieldset>)}
          <label className="full">Authorization (who approved scanning this range, and when)
            <input placeholder="Approved by plant manager, change ticket CHG-1234" value={form.authorization}
              onChange={set("authorization")} /></label>
          <div><button className="btn btn-primary" disabled={!form.cidr || add.isPending}>ADD TO SCOPE</button></div>
        </form>)}
      <ErrorBox error={scope.error ?? add.error ?? remove.error ?? patchPlugins.error} />
      <p className="hint">Nothing outside an INCLUDE range is ever sent a packet. Exclusions always win. Ranges wider than
        /16 are refused. Every change is audited.</p>
    </Panel>
  );
}

function VaultPanel({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const vault = useQuery({ queryKey: ["vault"], queryFn: () => apiGet<VaultProfile[]>("/vault/profiles") });
  const blank = { name: "OT-SNMPV3-RO", protocol: "SNMP", username: "", secret: "", description: "", version: "3",
    auth: "SHA-256", priv: "AES-128", privSecret: "", port: "", winrmAuth: "negotiate", caPem: "", skipCertCheck: false,
    sshAuth: "password" };
  const [form, setForm] = useState(blank);
  const set = (k: keyof typeof blank) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const DEFAULT_NAMES: Record<string, string> = { SNMP: "OT-SNMPV3-RO", WinRM: "OT-WINDOWS-READONLY", SSH: "OT-LINUX-SSH-RO",
    MQTT: "OT-MQTT" };
  const setProtocol = (e: { target: { value: string } }) =>
    setForm({ ...form, protocol: e.target.value, name: DEFAULT_NAMES[e.target.value] ?? form.name });
  const save = useMutation({
    mutationFn: () => {
      const params: Record<string, string | number | boolean> = {};
      if (form.protocol === "SNMP") {
        params.version = form.version;
        if (form.version === "3") { params.auth = form.auth; params.priv = form.priv; if (form.privSecret) params.privSecret = form.privSecret; }
        if (form.port) params.port = Number(form.port);
      } else if (form.protocol === "WinRM") {
        params.auth = form.winrmAuth;
        if (form.port) params.port = Number(form.port);
        if (form.caPem.trim()) params.caPem = form.caPem.trim();
        if (form.skipCertCheck) params.skipCertCheck = true;
      } else if (form.protocol === "SSH") {
        if (form.port) params.port = Number(form.port);
        if (form.sshAuth === "key") params.auth = "key";
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
          <label>Protocol<select value={form.protocol} onChange={setProtocol}>
            {["SNMP", "WinRM", "SSH", "MQTT"].map((p) => <option key={p}>{p}</option>)}</select></label>
          {snmp && <label>SNMP version<select value={form.version} onChange={set("version")}>
            <option value="3">v3 (authPriv)</option><option value="2c">v2c (community)</option></select></label>}
          {!(snmp && form.version === "2c") && <label>Username<input value={form.username} onChange={set("username")} /></label>}
          {form.protocol === "SSH" && form.sshAuth === "key"
            ? <label className="full">Private key (OpenSSH or PEM)<textarea className="mono" rows={4}
                placeholder="(unchanged if empty)" value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })} /></label>
            : <label>{snmp && form.version === "2c" ? "Community" : snmp ? "Auth passphrase" : "Password"}
                <input type="password" autoComplete="new-password" placeholder="(unchanged if empty)" value={form.secret}
                  onChange={set("secret")} /></label>}
          {snmp && form.version === "3" && <>
            <label>Auth protocol<select value={form.auth} onChange={set("auth")}>
              {["SHA-256", "SHA-512", "SHA", "MD5"].map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>Privacy protocol<select value={form.priv} onChange={set("priv")}>
              {["AES-128", "AES-256", "DES", "NONE"].map((a) => <option key={a}>{a}</option>)}</select></label>
            <label>Privacy passphrase<input type="password" autoComplete="new-password" placeholder="(same as auth if empty)"
              value={form.privSecret} onChange={set("privSecret")} /></label></>}
          {snmp && <label>UDP port<input className="narrow" placeholder="161" value={form.port} onChange={set("port")} /></label>}
          {form.protocol === "WinRM" && <>
            <label>Authentication<select value={form.winrmAuth} onChange={set("winrmAuth")}>
              <option value="negotiate">Negotiate (Kerberos, else NTLM)</option><option value="ntlm">NTLM</option>
              <option value="kerberos">Kerberos</option></select></label>
            <label>Port<input className="narrow" placeholder="5986 (HTTPS)" value={form.port} onChange={set("port")} /></label>
            <label className="full">CA certificate that signed the hosts' WinRM certificates (PEM, optional)
              <textarea className="mono" rows={3} placeholder="-----BEGIN CERTIFICATE-----" value={form.caPem}
                onChange={(e) => setForm({ ...form, caPem: e.target.value })} /></label>
            <label className="check full"><input type="checkbox" checked={form.skipCertCheck}
              onChange={(e) => setForm({ ...form, skipCertCheck: e.target.checked })} />
              Skip certificate validation (lab only: shown as "unverified" on every probe)</label></>}
          {form.protocol === "SSH" && <>
            <label>Login with<select value={form.sshAuth} onChange={set("sshAuth")}>
              <option value="password">Password</option><option value="key">Private key</option></select></label>
            <label>Port<input className="narrow" placeholder="22" value={form.port} onChange={set("port")} /></label></>}
          <label className="wide">Description<input value={form.description} onChange={set("description")} /></label>
          <div><button className="btn btn-primary" disabled={!form.name || save.isPending}>SAVE PROFILE</button></div>
        </form>)}
      <ErrorBox error={vault.error ?? save.error ?? remove.error} />
      <p className="hint">Secrets are encrypted at rest and write-only: the API never returns them. Discovery and probes use
        OT-SNMPV3-RO, OT-WINDOWS-READONLY and OT-LINUX-SSH-RO. Agent deployment, removal and restart use
        OT-WINDOWS-INSTALLER (an administrator account on the target).</p>
    </Panel>
  );
}

function BuildsPanel({ admin }: { admin: boolean }) {
  const qc = useQueryClient();
  const builds = useQuery({ queryKey: ["agent-builds"], queryFn: () => apiGet<AgentBuild[]>("/agent-builds") });
  const rescan = useMutation({
    mutationFn: () => apiAction<{ registered: { version: string; builds: number }[];
      rejected: { version: string; reason: string }[] }>("/agent-builds/rescan"),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["agent-builds"] }); qc.invalidateQueries({ queryKey: ["packages"] }); },
  });
  return (
    <Panel title="Agent builds (signed releases)" actions={admin && (
      <button className="btn btn-sm" disabled={rescan.isPending} onClick={() => rescan.mutate()}>Rescan releases</button>)}>
      <table className="dense"><thead><tr><th>Version</th><th>Build</th><th>Platform</th><th>Runs on</th>
        <th className="num">Size</th><th>SHA-256</th></tr></thead>
        <tbody>{builds.data?.map((b) => (
          <tr key={b.id}><td>{b.version}</td><td className="mono">{b.buildId}</td>
            <td>{b.os}/{b.arch}{b.variant === "legacy" && <span className="pill pill-warn">LEGACY</span>}</td>
            <td className="small">{b.minOs}</td><td className="num">{(b.sizeBytes / 1_048_576).toFixed(1)} MB</td>
            <td className="mono small" title={b.sha256}>{b.sha256.slice(0, 16)}…</td></tr>))}
          {builds.data?.length === 0 && <tr><td colSpan={6} className="muted">No verified release. Build with
            agent-go/build.sh, sign with scripts/sign_release.py, then Rescan.</td></tr>}
        </tbody></table>
      {rescan.data?.rejected.map((r) => (
        <div key={r.version} className="error-box">Release {r.version} rejected: {r.reason}</div>))}
      <ErrorBox error={builds.error ?? rescan.error} />
      <p className="hint">Only releases whose signature verifies against the release key, with every file matching the
        signed SHA256SUMS, are listed. Each build is deployable as a package (Deployments → request). Legacy builds run on
        Windows 7 / Server 2008 R2–2012 and are compiled with Go 1.20, which no longer receives security fixes.</p>
    </Panel>
  );
}
