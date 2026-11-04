import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { XOctagon, ShieldCheck } from "lucide-react";
import { apiAction, apiGet } from "../api";
import type { Environment } from "../types";

/** Environment banner state. Public endpoint, so the login page can show it too. */
export function useEnvironment() {
  return useQuery({ queryKey: ["environment"], queryFn: () => apiGet<Environment>("/environment"),
    refetchInterval: 15000 });
}

export function EnvBanner() {
  const env = useEnvironment();
  if (!env.data) return <div className="sim-banner live-banner-warning" role="status">CONNECTING…</div>;
  const cls = env.data.mode === "SIMULATED" ? "sim-banner" : `sim-banner live-banner-${env.data.severity}`;
  return <div className={cls} role="status">{env.data.banner}</div>;
}

export function EnvChip() {
  const env = useEnvironment();
  if (!env.data) return null;
  return <span className={`env-chip${env.data.mode === "LIVE" ? " env-live" : ""}`}>{env.data.mode}</span>;
}

/** Kill switch in the top bar: anyone who can start work can stop it; only an admin can re-arm. */
export function StopAllButton({ role }: { role?: string }) {
  const qc = useQueryClient();
  const env = useEnvironment();
  const done = () => { qc.invalidateQueries({ queryKey: ["environment"] }); qc.invalidateQueries({ queryKey: ["safety"] }); };
  const stop = useMutation({ mutationFn: (reason: string) => apiAction("/safety/stop", { reason }), onSuccess: done });
  const rearm = useMutation({ mutationFn: (reason: string) => apiAction("/safety/rearm", { reason }), onSuccess: done });
  if (env.data?.mode !== "LIVE") return null;
  const ask = (verb: string, fallback: string, run: (r: string) => void) => {
    const reason = window.prompt(`${verb}: reason (recorded in the audit log)`, fallback);
    if (reason && reason.trim().length >= 3) run(reason.trim());
  };
  if (env.data.armed) {
    if (role === "APPROVER") return null;
    return (
      <button className="btn btn-sm btn-kill" disabled={stop.isPending} title="Stop all network activity now"
        onClick={() => ask("STOP ALL network activity", "Stopped from the console", (r) => stop.mutate(r))}>
        <XOctagon size={15} />STOP ALL</button>
    );
  }
  return role === "ADMIN" ? (
    <button className="btn btn-sm" disabled={rearm.isPending} title="Allow network activity again"
      onClick={() => ask("Re-arm network activity", "", (r) => rearm.mutate(r))}><ShieldCheck size={15} />Re-arm</button>
  ) : <span className="env-chip env-live" title="Only an admin can re-arm">STOPPED</span>;
}
