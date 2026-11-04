import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Info, ShieldAlert, X, XCircle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { onServerEvent } from "../events";
import type { SseEvent } from "../types";

type Tone = "ok" | "warn" | "fail" | "info";
interface Toast { id: number; tone: Tone; title: string; body: string; to?: string }

const short = (id: string | null) => (id ? id.slice(0, 8) : "");

/** Operational alerts derived from live server events (the event says what happened; the UI only words it). */
function toToast(e: SseEvent): Omit<Toast, "id"> | null {
  const s = e.data?.status as string | undefined;
  const id = e.entity.id;
  switch (e.type) {
    case "drift.detected":
      return { tone: "fail", title: "Configuration drift detected", body: `${e.data.ruleId} changed from PASS on an asset`,
        to: `/assessments/${e.data.runId}` };
    case "asset.rogue":
      return { tone: "fail", title: "Rogue device detected", body: `Unknown MAC ${e.data.mac} at ${e.data.ip}`,
        to: `/assets/${id}` };
    case "agent.status":
      if (s === "STALE" || s === "OFFLINE" || s === "ERROR")
        return { tone: s === "STALE" ? "warn" : "fail", title: `Agent ${s}`, body: `Agent ${short(id)}: ${e.data.reason ?? s}`,
          to: `/agents/${id}` };
      if (s === "ONLINE" && e.data.from && e.data.from !== "ENROLLING")
        return { tone: "ok", title: "Agent recovered", body: `Agent ${short(id)} is ONLINE again`, to: `/agents/${id}` };
      if (s === "ONLINE") return { tone: "ok", title: "Agent enrolled", body: `Agent ${short(id)} is ONLINE`, to: `/agents/${id}` };
      return null;
    case "deployment.status":
      if (s === "COMPLETED") return { tone: "ok", title: "Deployment completed", body: `Deployment ${short(id)}: agent enrolled`, to: `/deployments/${id}` };
      if (s === "FAILED") return { tone: "fail", title: "Deployment failed", body: e.data.reason ?? `Deployment ${short(id)}`, to: `/deployments/${id}` };
      if (s === "PRECHECK_FAILED") return { tone: "warn", title: "Precheck failed", body: e.data.reason ?? "", to: `/deployments/${id}` };
      return null;
    case "removal.status":
      if (s === "COMPLETED") return { tone: "ok", title: "Rollback completed", body: "Agent removed; history retained", to: `/removals/${id}` };
      if (s === "FAILED") return { tone: "fail", title: "Rollback failed", body: e.data.reason ?? "", to: `/removals/${id}` };
      return null;
    case "discovery.status":
      if (s === "COMPLETED") return { tone: "info", title: "Discovery completed", body: `Job ${short(id)}`, to: "/discovery" };
      return null;
    case "demo.reset":
      return { tone: "info", title: "POC reset", body: "Seed state restored", to: "/" };
    default:
      return null;
  }
}

const ICON = { ok: CheckCircle2, warn: AlertTriangle, fail: XCircle, info: Info };

export function Toaster() {
  const nav = useNavigate();
  const [toasts, setToasts] = useState<Toast[]>([]);
  useEffect(() => {
    let seq = 0;
    return onServerEvent((e) => {
      const t = toToast(e);
      if (!t) return;
      const id = ++seq;
      setToasts((list) => [...list.slice(-3), { ...t, id }]);
      window.setTimeout(() => setToasts((list) => list.filter((x) => x.id !== id)), 7000);
    });
  }, []);
  if (!toasts.length) return null;
  return (
    <div className="toaster" role="log" aria-live="polite">
      {toasts.map((t) => {
        const Icon = t.tone === "fail" && t.title.startsWith("Rogue") ? ShieldAlert : ICON[t.tone];
        return (
          <div key={t.id} className={`toast toast-${t.tone}`} onClick={() => t.to && nav(t.to)}>
            <Icon size={18} />
            <div><b>{t.title}</b><span>{t.body}</span></div>
            <button aria-label="Dismiss" onClick={(ev) => { ev.stopPropagation(); setToasts((l) => l.filter((x) => x.id !== t.id)); }}>
              <X size={14} /></button>
          </div>
        );
      })}
    </div>
  );
}
