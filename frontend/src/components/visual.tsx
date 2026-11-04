import type { LucideIcon } from "lucide-react";
import {
  Check, Cpu, Database, HelpCircle, Laptop, MonitorDot, Network, Thermometer, X,
} from "lucide-react";

/** Presentation only: an icon for a classification label returned by the API. */
export function deviceIcon(type: string | null | undefined): LucideIcon {
  const t = (type ?? "").toLowerCase();
  if (t.includes("workstation")) return Laptop;
  if (t.includes("scada")) return MonitorDot;
  if (t.includes("historian") || t.includes("server")) return Database;
  if (t.includes("plc")) return Cpu;
  if (t.includes("switch")) return Network;
  if (t.includes("sensor")) return Thermometer;
  return HelpCircle;
}

export function DeviceIcon({ type, size = 16 }: { type: string | null | undefined; size?: number }) {
  const Icon = deviceIcon(type);
  return <span className="device-icon"><Icon size={size} /></span>;
}

export function LevelBadge({ level }: { level: string }) {
  return <span className={`level level-${level.toLowerCase()}`}>{level === "DMZ" ? "DMZ" : `L${level}`}</span>;
}

export interface LifecycleStage { key: string; label: string }

/** Horizontal lifecycle for a workflow. `failedAt` marks the stage where it stopped. */
export function Lifecycle({ stages, current, failedAt, failedLabel }:
  { stages: LifecycleStage[]; current: number; failedAt?: number; failedLabel?: string }) {
  return (
    <ol className="lifecycle">
      {stages.map((s, i) => {
        const state = failedAt === i ? "failed" : i < current || (i === current && current === stages.length - 1 && failedAt === undefined)
          ? "done" : i === current ? "current" : "todo";
        return (
          <li key={s.key} className={`lc lc-${state}`}>
            <span className="lc-dot">{state === "done" ? <Check size={13} /> : state === "failed" ? <X size={13} /> : i + 1}</span>
            <span className="lc-label">{state === "failed" && failedLabel ? failedLabel : s.label}</span>
          </li>
        );
      })}
    </ol>
  );
}
