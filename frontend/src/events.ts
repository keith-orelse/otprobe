import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { apiAction } from "./api";
import type { SseEvent } from "./types";

type Listener = (e: SseEvent) => void;
const listeners = new Set<Listener>();

export function onServerEvent(fn: Listener): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** One EventSource for the whole console. SSE only signals; REST stays the source of truth. */
export function useServerEvents(): void {
  const qc = useQueryClient();
  useEffect(() => {
    let es: EventSource | null = null;
    let closed = false;
    let retry: number | undefined;
    const connect = async () => {
      try {
        const { ticket } = await apiAction<{ ticket: string }>("/auth/stream-ticket");
        if (closed) return;
        es = new EventSource(`/api/v1/events/stream?ticket=${encodeURIComponent(ticket)}`);
        types.forEach((t) => es!.addEventListener(t, handle as EventListener));
        es.onerror = () => { es?.close(); if (!closed) retry = window.setTimeout(connect, 3000); };
      } catch {
        if (!closed) retry = window.setTimeout(connect, 3000);
      }
    };
    const handle = (msg: MessageEvent) => {
      const e = JSON.parse(msg.data) as SseEvent;
      listeners.forEach((l) => l(e));
      const topic = e.type.split(".")[0];
      if (topic === "discovery") qc.invalidateQueries({ queryKey: ["discovery"] });
      if (topic === "asset" || e.type === "discovery.device_found" || e.type === "probe.status") {
        qc.invalidateQueries({ queryKey: ["assets"] });
        qc.invalidateQueries({ queryKey: ["asset"] });
        qc.invalidateQueries({ queryKey: ["topology"] });
        qc.invalidateQueries({ queryKey: ["dashboard"] });
      }
      if (topic === "probe") qc.invalidateQueries({ queryKey: ["probes"] });
      if (topic === "audit") qc.invalidateQueries({ queryKey: ["audit"] });
      if (topic === "deployment" || topic === "approval") {
        qc.invalidateQueries({ queryKey: ["deployments"] });
        qc.invalidateQueries({ queryKey: ["approvals"] });
        qc.invalidateQueries({ queryKey: ["asset"] });
      }
      if (topic === "agent") {
        qc.invalidateQueries({ queryKey: ["agents"] });
        if (e.type !== "agent.heartbeat") qc.invalidateQueries({ queryKey: ["asset"] });
      }
    };
    const types = ["discovery.status", "discovery.progress", "discovery.device_found", "discovery.step",
      "asset.updated", "asset.rogue", "probe.status", "probe.step", "audit.event", "deployment.status",
      "deployment.step", "deployment.precheck", "approval.status", "agent.status", "agent.heartbeat"];
    connect();
    return () => { closed = true; window.clearTimeout(retry); es?.close(); };
  }, [qc]);
}
