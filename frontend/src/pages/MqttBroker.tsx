import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiAction, apiGet, apiSend } from "../api";
import { getToken } from "../auth";
import { ErrorBox, Panel, Pill, ago, time } from "../components/ui";
import type { AssetSummary, MqttAccount, MqttAccountSecret, MqttBrokerStatus, Page } from "../types";

async function downloadCa() {
  const token = getToken();
  const res = await fetch("/api/v1/mqtt/ca.pem", { headers: token ? { Authorization: `Bearer ${token}` } : {} });
  if (!res.ok) return;
  const url = URL.createObjectURL(await res.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: "otprobe-ca.pem" });
  a.click();
  URL.revokeObjectURL(url);
}

/** Bundled MQTT broker (Mode A): status, security checks and device accounts. Writes are admin-only. */
export function MqttPanel({ admin }: { admin: boolean }) {
  const broker = useQuery({ queryKey: ["mqtt", "broker"], queryFn: () => apiGet<MqttBrokerStatus>("/mqtt/broker"),
    refetchInterval: 5000 });
  const b = broker.data;
  if (b?.mode === "off") {
    return (
      <Panel title="MQTT broker">
        <p className="hint">The bundled MQTT broker is off, so OTProbe receives no telemetry. To turn it on, install
          Mosquitto on the OTProbe machine (<span className="mono">brew install mosquitto</span> or <span className="mono">
          apt install mosquitto</span>), start OTProbe with <span className="mono">MQTT_BROKER=bundled</span> and
          restart. Devices then connect to this machine on port 8883 (TLS).</p>
      </Panel>
    );
  }
  return (
    <>
      <BrokerStatus b={b} admin={admin} error={broker.error} />
      {b && <Accounts admin={admin} broker={b} />}
    </>
  );
}

function BrokerStatus({ b, admin, error }: { b?: MqttBrokerStatus; admin: boolean; error: unknown }) {
  return (
    <Panel title="MQTT broker" actions={b?.caAvailable && (
      <button className="btn btn-sm" onClick={downloadCa}>Download CA certificate</button>)}>
      <ErrorBox error={error} />
      {b && <>
        <dl className="kv">
          <dt>Broker</dt><dd>{b.running ? <Pill value="OK" title="running" /> : <Pill value="FAILED" title="stopped" />}
            {b.running ? ` Mosquitto ${b.version}, pid ${b.pid}, since ${ago(b.startedAt)}` : " not running"}
            {b.restarts > 0 && ` · restarted ${b.restarts}×`}</dd>
          <dt>Devices connect to</dt><dd className="mono">{b.listeners.length
            ? b.listeners.map((l) => `${b.host || "<this machine>"}:${l.port} ${l.tls ? "(TLS)" : "(NO TLS)"}`).join(" · ")
            : "nothing: no TLS certificate configured"}</dd>
          <dt>Connected now</dt><dd>{b.connected} device(s) · {b.accounts} account(s)
            {Object.keys(b.dropped).length > 0 && ` · not stored: ${Object.entries(b.dropped)
              .map(([k, v]) => `${v} ${k}`).join(", ")}`}</dd>
        </dl>
        {b.error && <div className="error-box">{b.error}</div>}
        <table className="dense" style={{ marginTop: 12 }}>
          <thead><tr><th>Check</th><th>Result</th><th>Severity</th><th>Detail</th></tr></thead>
          <tbody>{b.checks.map((c) => (
            <tr key={c.ruleId}><td><span className="mono small">{c.ruleId}</span> {c.title}</td>
              <td><Pill value={c.status} /></td><td><Pill value={c.severity} /></td><td className="small">{c.detail}</td>
            </tr>))}</tbody>
        </table>
        {admin && b.refused.length > 0 && <>
          <h3 className="sub">Refused logins</h3>
          <table className="dense"><thead><tr><th>When</th><th>Client id</th><th>From</th></tr></thead>
            <tbody>{[...b.refused].reverse().map((r, i) => (
              <tr key={i}><td title={time(r.at)}>{ago(r.at)}</td><td className="mono">{r.clientId}</td>
                <td className="mono">{r.ip}</td></tr>))}</tbody></table></>}
        {admin && b.log.length > 0 && (
          <details style={{ marginTop: 12 }}><summary>Broker log (last {b.log.length} lines)</summary>
            <pre className="mono small log">{b.log.join("\n")}</pre></details>)}
      </>}
      <p className="hint">OTProbe runs the broker itself and only reads from it: its own account can subscribe and cannot
        publish. Every device has its own account and may publish only under its own topic prefix.</p>
    </Panel>
  );
}

function Accounts({ admin, broker }: { admin: boolean; broker: MqttBrokerStatus }) {
  const qc = useQueryClient();
  const accounts = useQuery({ queryKey: ["mqtt", "accounts"], queryFn: () => apiGet<MqttAccount[]>("/mqtt/accounts"),
    refetchInterval: 5000 });
  const assets = useQuery({ queryKey: ["assets", "all"], queryFn: () => apiGet<Page<AssetSummary>>("/assets", { limit: 500 }),
    enabled: admin });
  const blank = { username: "", topicPrefix: "plant/line1/", assetId: "", description: "" };
  const [form, setForm] = useState(blank);
  const [secret, setSecret] = useState<MqttAccountSecret | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ["mqtt"] });
  const create = useMutation({
    mutationFn: () => apiAction<MqttAccountSecret>("/mqtt/accounts", { username: form.username.trim(),
      topicPrefix: form.topicPrefix.trim().replace(/\/+$/, ""), assetId: form.assetId || null,
      description: form.description }),
    onSuccess: (s) => { setSecret(s); setForm(blank); refresh(); },
  });
  const patch = useMutation({
    mutationFn: ({ username, body }: { username: string; body: Record<string, unknown> }) =>
      apiSend("PATCH", `/mqtt/accounts/${username}`, body),
    onSuccess: refresh,
  });
  const rotate = useMutation({
    mutationFn: (username: string) => apiAction<MqttAccountSecret>(`/mqtt/accounts/${username}/password`),
    onSuccess: (s) => { setSecret(s); refresh(); },
  });
  const remove = useMutation({ mutationFn: (username: string) => apiSend("DELETE", `/mqtt/accounts/${username}`),
    onSuccess: refresh });
  const set = (k: keyof typeof blank) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const assetOptions = assets.data?.items ?? [];

  return (
    <Panel title="MQTT device accounts">
      {secret && <SecretBox s={secret} broker={broker} onClose={() => setSecret(null)} />}
      <table className="dense">
        <thead><tr><th>Account</th><th>May publish under</th><th>Asset</th><th>Connection</th><th>Last message</th></tr></thead>
        <tbody>{accounts.data?.map((a) => (
          <tr key={a.username} className={a.enabled ? "" : "muted"}>
            <td><span className="mono">{a.username}</span>{a.description && <div className="small muted">{a.description}</div>}
              {admin && <div className="row-actions">
              <button className="btn btn-sm" onClick={() => patch.mutate({ username: a.username, body: { enabled: !a.enabled } })}>
                {a.enabled ? "Disable" : "Enable"}</button>
              <button className="btn btn-sm" onClick={() => window.confirm(
                `New password for ${a.username}? The device is disconnected until it uses the new one.`) && rotate.mutate(a.username)}>
                New password</button>
              <button className="btn btn-sm" onClick={() => window.confirm(`Delete ${a.username}? The device is disconnected.`)
                && remove.mutate(a.username)}>Delete</button></div>}</td>
            <td className="mono">{a.topicPrefix}/#</td>
            <td>{admin
              ? <select className="compact" value={a.assetId ?? ""} onChange={(e) => patch.mutate({ username: a.username,
                  body: { assetId: e.target.value || null } })}>
                  <option value="">(not linked)</option>
                  {a.assetId && !assetOptions.some((x) => x.id === a.assetId) &&
                    <option value={a.assetId}>{a.assetName}</option>}
                  {assetOptions.map((x) => <option key={x.id} value={x.id}>{x.displayName} ({x.ip})</option>)}
                </select>
              : a.assetName ?? <span className="muted">not linked</span>}</td>
            <td>{!a.enabled ? <Pill value="BLOCKED" title="disabled" />
              : a.connected ? <><Pill value="ONLINE" /> <span className="mono small">
                  {a.connections.map((c) => `${c.ip} (${c.clientId})`).join(", ")}</span></>
              : <><Pill value="OFFLINE" />{a.lastSeen && <span className="small muted"> last {ago(a.lastSeen.at)} from{" "}
                  {a.lastSeen.ip}</span>}</>}</td>
            <td title={time(a.lastMessageAt)}>{a.lastMessageAt ? ago(a.lastMessageAt) : <span className="muted">never</span>}
              {a.topics.length > 0 && <div className="small muted mono">{a.topics.slice(0, 3).join(", ")}
                {a.topics.length > 3 && ` +${a.topics.length - 3}`}</div>}</td>
          </tr>))}
          {accounts.data?.length === 0 && <tr><td colSpan={5} className="muted">No device accounts yet.</td></tr>}
        </tbody>
      </table>
      {admin && (
        <form className="form-grid" style={{ marginTop: 16 }} onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <label>Account name<input className="mono" placeholder="sensor01" value={form.username} onChange={set("username")} /></label>
          <label>Topic prefix<input className="mono" placeholder="plant/line1/sensor01" value={form.topicPrefix}
            onChange={set("topicPrefix")} /></label>
          <label>Asset (optional)<select value={form.assetId} onChange={set("assetId")}>
            <option value="">(link later, or by its IP address)</option>
            {assetOptions.map((x) => <option key={x.id} value={x.id}>{x.displayName} ({x.ip})</option>)}</select></label>
          <label className="wide">Description<input value={form.description} onChange={set("description")} /></label>
          <div><button className="btn btn-primary" disabled={!form.username || !form.topicPrefix || create.isPending}>
            CREATE ACCOUNT</button></div>
        </form>)}
      <ErrorBox error={accounts.error ?? create.error ?? patch.error ?? rotate.error ?? remove.error} />
      <p className="hint">The password is shown once; OTProbe keeps only a hash. Topic prefixes never overlap, so every
        message has one possible sender. Messages go to the linked asset, or to the asset with the address the device
        connects from. A plain number on <span className="mono">…/temperature</span> is read as a temperature
        (<span className="mono">rules/telemetry.yaml</span>).</p>
    </Panel>
  );
}

function SecretBox({ s, broker, onClose }: { s: MqttAccountSecret; broker: MqttBrokerStatus; onClose: () => void }) {
  const c = s.connection;
  const host = broker.host || "<OTProbe IP>";
  const cmd = `backend/.venv/bin/python scripts/fake_sensor.py --host ${host} --port ${c.port ?? 8883} ` +
    `--ca backend/tls/otprobe-ca.pem --username ${c.username} --password '${s.password}' ` +
    `--topic ${s.account.topicPrefix}/temperature --value 42`;
  return (
    <div className="notice" role="status">
      <strong>Account {c.username}: copy the password now. It is not shown again.</strong>
      <dl className="kv" style={{ marginTop: 8 }}>
        <dt>Broker</dt><dd className="mono">{host}:{c.port ?? "—"} {c.tls ? "TLS (install the CA certificate on the device)" : "no TLS"}</dd>
        <dt>Username</dt><dd className="mono">{c.username}</dd>
        <dt>Password</dt><dd className="mono"><input readOnly className="mono" value={s.password} size={30}
          onFocus={(e) => e.target.select()} /> <button className="btn btn-sm" type="button"
          onClick={() => navigator.clipboard?.writeText(s.password)}>Copy</button></dd>
        <dt>Publish to</dt><dd className="mono">{c.topic}</dd>
        <dt>Test with</dt><dd><code className="mono small">{cmd}</code></dd>
      </dl>
      <button className="btn btn-sm" onClick={onClose}>I have copied it</button>
    </div>
  );
}
