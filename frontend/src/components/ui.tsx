import type { ReactNode } from "react";
import { ApiError } from "../api";
import type { WorkflowStep } from "../types";

const TONE: Record<string, string> = {
  ONLINE: "ok", OK: "ok", COMPLETED: "ok", ELIGIBLE: "ok", PASS: "ok", AGENTLESS: "info",
  RUNNING: "info", QUEUED: "muted", PENDING: "muted", SKIPPED: "muted", UNKNOWN: "muted", NOT_INSTALLED: "muted",
  PARTIAL: "warn", REVIEW_REQUIRED: "warn", HIGH_LATENCY: "warn", BLOCKED: "warn", WARNING: "warn", CANCELLED: "muted",
  OFFLINE: "fail", FAILED: "fail", TIMEOUT: "fail", NOT_ELIGIBLE: "neutral", NOT_SUPPORTED: "neutral",
  CRITICAL: "fail", HIGH: "warn", MEDIUM: "info", LOW: "muted", ROGUE: "fail",
};

export function Pill({ value, title }: { value: string | null | undefined; title?: string }) {
  if (!value) return <span className="muted">—</span>;
  return <span className={`pill pill-${TONE[value] ?? "neutral"}`} title={title}>{value.replace(/_/g, " ")}</span>;
}

export function SourceBadge({ source, label, stage }: { source: string; label?: string; stage?: string }) {
  return (
    <span className={`src src-${source.toLowerCase()}`} title={stage ? `${label ?? source} · stage ${stage}` : label}>
      {label ?? source}
    </span>
  );
}

export function Panel({ title, actions, children, className }:
  { title: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className ?? ""}`}>
      <header className="panel-head"><h2>{title}</h2>{actions && <div className="panel-actions">{actions}</div>}</header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const p = error instanceof ApiError ? error.problem : null;
  return (
    <div className="error-box" role="alert">
      <strong>{p ? `${p.status} ${p.title}` : "Request failed"}</strong>
      {p?.detail && <div>{p.detail}</div>}
      {p?.errors?.map((e) => <div key={e.field}>{e.field}: {e.message}</div>)}
      {p?.correlationId && <div className="muted mono">correlation {p.correlationId}</div>}
    </div>
  );
}

export function Progress({ value }: { value: number }) {
  return <div className="progress"><div className="progress-bar" style={{ width: `${Math.min(100, value)}%` }} />
    <span>{value}%</span></div>;
}

export function StepList({ steps }: { steps: WorkflowStep[] }) {
  return (
    <ol className="steps">
      {steps.map((s) => (
        <li key={s.seq} className={`step step-${s.status.toLowerCase()}`}>
          <span className="step-icon" aria-hidden>{ICON[s.status]}</span>
          <span className="step-name">{s.name.replace(/_/g, " ")}</span>
          <span className="step-detail">
            {s.detail}
            {Array.isArray(s.data?.stages) && (
              <span className="stages">
                {s.data.stages.map((st: { name: string; status: string; detail: string }) => (
                  <span key={st.name} title={st.detail} className={`stage ${st.status === "OK" ? "stage-ok" : "stage-fail"}`}>
                    {st.name.replace(/_/g, " ")}
                  </span>
                ))}
              </span>
            )}
          </span>
          <span className="step-time mono">{duration(s.startedAt, s.finishedAt)}</span>
        </li>
      ))}
    </ol>
  );
}

const ICON: Record<string, string> = { PENDING: "○", RUNNING: "◌", OK: "✓", FAILED: "✕", SKIPPED: "–" };

export function duration(start: string | null, end: string | null): string {
  if (!start) return "";
  const ms = (end ? Date.parse(end) : Date.now()) - Date.parse(start);
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

export function ago(ts: string | null | undefined): string {
  if (!ts) return "—";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(ts)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function time(ts: string | null | undefined): string {
  return ts ? new Date(ts).toLocaleString(undefined, { hour12: false }) : "—";
}

export function Value({ value }: { value: any }) {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  if (typeof value === "boolean") return <span>{value ? "yes" : "no"}</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">none</span>;
    if (value.every((v) => typeof v !== "object")) return <span className="mono">{value.join(", ")}</span>;
    return (
      <details className="value-list">
        <summary>{value.length} item{value.length === 1 ? "" : "s"}</summary>
        <ul>{value.map((v, i) => <li key={i} className="mono">{summarize(v)}</li>)}</ul>
      </details>
    );
  }
  if (typeof value === "object") return <span className="mono">{summarize(value)}</span>;
  return <span className="mono">{String(value)}</span>;
}

function summarize(v: any): string {
  if (v && typeof v === "object") return Object.entries(v).map(([k, x]) => `${k}=${x ?? "—"}`).join("  ");
  return String(v);
}

export function Pager({ next, onNext, onFirst, hasPrev, total }:
  { next: string | null; onNext: () => void; onFirst: () => void; hasPrev: boolean; total: number }) {
  return (
    <div className="pager">
      <span className="muted">{total} total</span>
      <button className="btn btn-sm" disabled={!hasPrev} onClick={onFirst}>First</button>
      <button className="btn btn-sm" disabled={!next} onClick={onNext}>Next</button>
    </div>
  );
}
