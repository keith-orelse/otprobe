import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiGet } from "../api";
import { ErrorBox, Pager, time } from "../components/ui";
import type { AuditEvent, Page } from "../types";

export function AuditLogs() {
  const [action, setAction] = useState("");
  const [correlationId, setCorrelationId] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const events = useQuery({ queryKey: ["audit", action, correlationId, cursor],
    queryFn: () => apiGet<Page<AuditEvent>>("/audit-events", { action, correlationId, cursor, limit: 100 }) });
  const verify = useQuery({ queryKey: ["audit", "verify"], queryFn: () => apiGet<{ valid: boolean; events: number }>("/audit-events/verify") });
  return (
    <div className="page">
      <div className="toolbar">
        <input placeholder="Action (e.g. ROGUE_DEVICE_DETECTED)" value={action} onChange={(e) => { setAction(e.target.value.toUpperCase()); setCursor(null); }} />
        <input placeholder="Correlation ID" value={correlationId} onChange={(e) => { setCorrelationId(e.target.value); setCursor(null); }} />
        {verify.data && <span className={`pill ${verify.data.valid ? "pill-ok" : "pill-fail"}`}>
          hash chain {verify.data.valid ? "valid" : "BROKEN"} · {verify.data.events} events</span>}
      </div>
      <ErrorBox error={events.error} />
      <table className="dense">
        <thead><tr><th className="num">#</th><th>Time</th><th>Actor</th><th>Action</th><th>Entity</th><th>Correlation</th><th>Details</th></tr></thead>
        <tbody>{events.data?.items.map((e) => (
          <tr key={e.seq}>
            <td className="num mono">{e.seq}</td><td className="mono">{time(e.at)}</td>
            <td>{e.actorName}<span className="muted small"> {e.actorType.toLowerCase()}</span></td>
            <td className="mono">{e.action}</td>
            <td className="mono small">{e.entityKind}{e.entityId ? `:${e.entityId.slice(0, 8)}` : ""}</td>
            <td className="mono small clickable-text" onClick={() => e.correlationId && setCorrelationId(e.correlationId)}>
              {e.correlationId?.slice(0, 13)}</td>
            <td className="mono small">{Object.entries(e.details).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  ")}</td>
          </tr>))}
        </tbody>
      </table>
      {events.data && <Pager total={events.data.total} next={events.data.nextCursor} hasPrev={!!cursor}
        onNext={() => setCursor(events.data!.nextCursor)} onFirst={() => setCursor(null)} />}
    </div>
  );
}
