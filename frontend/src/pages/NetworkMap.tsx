import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import cytoscape from "cytoscape";
import { apiGet } from "../api";
import { ErrorBox, Panel, Pill } from "../components/ui";
import type { Topology, TopologyNode } from "../types";

const STATE_COLOR: Record<string, string> = {
  ONLINE: "#1e8e3e", OFFLINE: "#d93025", AGENTLESS: "#1a73e8", AGENT_INSTALLED: "#7c3aed", WARNING: "#e9a100",
  FAILED: "#d93025", UNKNOWN: "#94a3b8",
};
const LEGEND = ["ONLINE", "AGENTLESS", "AGENT_INSTALLED", "WARNING", "OFFLINE", "FAILED", "UNKNOWN"];

/** Layout uses only structural fields from the API: node kind, zone order and asset tier. */
function layout(nodes: TopologyNode[]): Record<string, { x: number; y: number }> {
  const pos: Record<string, { x: number; y: number }> = {};
  const row = (list: TopologyNode[], y: number) =>
    list.forEach((n, i) => (pos[n.id] = { x: i * 170 - ((list.length - 1) * 170) / 2, y }));
  const zones = nodes.filter((n) => n.kind === "zone").sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  const assets = nodes.filter((n) => n.kind === "asset");
  let y = 0;
  zones.forEach((z, i) => {
    const members = nodes.filter((n) => n.parent === z.id);
    if (i === 0) {
      row(members, y);                                              // top zone (probe server)
      y += 150;
      row(nodes.filter((n) => n.kind === "conduit"), y);            // conduit below it
      y += 80;
      return;
    }
    if (!members.length) return;
    const infra = members.filter((n) => n.tier === "infrastructure");
    if (infra.length) { row(infra, y); y += 130; }                 // switches above the hosts they link
    row(members.filter((n) => n.tier !== "infrastructure"), y);
    y += 220;
  });
  assets.filter((n) => !pos[n.id]).forEach((n, i) => (pos[n.id] = { x: i * 170, y }));
  return pos;
}

export function NetworkMap() {
  const topo = useQuery({ queryKey: ["topology"], queryFn: () => apiGet<Topology>("/topology") });
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const [selected, setSelected] = useState<TopologyNode | null>(null);
  const [flows, setFlows] = useState(true);

  const elements = useMemo(() => {
    if (!topo.data) return [];
    const pos = layout(topo.data.nodes);
    const used = new Set(topo.data.nodes.filter((n) => n.parent).map((n) => n.parent));
    return [
      ...topo.data.nodes.filter((n) => n.kind !== "zone" || used.has(n.id)).map((n) => ({
        data: { id: n.id, label: n.kind === "asset" && n.label !== n.ip ? `${n.label}\n${n.ip}` : n.label, parent: n.parent ?? undefined,
          kind: n.kind, color: STATE_COLOR[n.state ?? "UNKNOWN"] ?? "#6e7781" },
        position: pos[n.id],
      })),
      ...topo.data.edges.filter((e) => flows || e.kind !== "FLOW").map((e) => ({
        data: { id: e.id, source: e.source, target: e.target, kind: e.kind,
          label: e.kind === "FLOW" ? `${e.protocol}${e.port ? `:${e.port}` : ""}` : "" },
      })),
    ];
  }, [topo.data, flows]);

  useEffect(() => {
    if (!ref.current) return;
    cy.current?.destroy();
    const c = cytoscape({
      container: ref.current, elements, layout: { name: "preset" }, wheelSensitivity: 0.2, autoungrabify: false,
      style: [
        { selector: "node", style: { "background-color": "#ffffff", "border-width": 3, "border-color": "data(color)",
          label: "data(label)", color: "#0f172a", "font-size": 10, "text-wrap": "wrap", "text-valign": "bottom",
          "text-margin-y": 6, width: 34, height: 34, "font-family": "Inter, system-ui, sans-serif", "font-weight": 600 } },
        { selector: "node[kind='server']", style: { shape: "round-rectangle", "border-color": "#d02e27", "background-color": "#fce8e6" } },
        { selector: "node[kind='conduit']", style: { shape: "diamond", "border-color": "#d02e27", width: 40, height: 40 } },
        { selector: ":parent", style: { "background-color": "#f8fafc", "background-opacity": 0.9, "border-width": 1,
          "border-color": "#e2e8f0", shape: "round-rectangle", label: "data(label)", "text-valign": "top",
          "text-halign": "left", "text-margin-x": 120, color: "#94a3b8", "font-size": 11, "font-weight": 700, padding: "28px" } },
        { selector: "edge", style: { width: 1.5, "line-color": "#cbd5e1", "curve-style": "bezier" } },
        { selector: "edge[kind='FLOW']", style: { "line-style": "dashed", "line-color": "#d02e27", "target-arrow-shape": "triangle",
          "target-arrow-color": "#d02e27", label: "data(label)", "font-size": 8, color: "#b32520",
          "text-background-color": "#ffffff", "text-background-opacity": 1 } },
        { selector: ":selected", style: { "border-color": "#0f172a", "border-width": 4 } },
      ],
    });
    c.on("tap", "node", (evt) => {
      const n = topo.data?.nodes.find((x) => x.id === evt.target.id());
      setSelected(n && n.kind !== "zone" ? n : null);
    });
    c.fit(undefined, 30);
    cy.current = c;
    return () => c.destroy();
  }, [elements]);

  return (
    <div className="page">
      <ErrorBox error={topo.error} />
      <div className="toolbar">
        <label className="check"><input type="checkbox" checked={flows} onChange={(e) => setFlows(e.target.checked)} /> Show communication flows</label>
        <div className="legend">{LEGEND.map((s) => <span key={s}><i style={{ borderColor: STATE_COLOR[s] }} />{s.replace("_", " ").toLowerCase()}</span>)}</div>
      </div>
      <div className="map-wrap">
        <div ref={ref} className="map" />
        <Panel title="Selection" className="map-side">
          {selected ? (
            <table className="kv"><tbody>
              <tr><th>Name</th><td>{selected.label}</td></tr>
              {selected.ip && <tr><th>IP</th><td className="mono">{selected.ip}</td></tr>}
              {selected.type && <tr><th>Type</th><td>{selected.type}</td></tr>}
              <tr><th>State</th><td><Pill value={selected.state} /></td></tr>
              {selected.assetId && <tr><td colSpan={2}><Link to={`/assets/${selected.assetId}`}>Open asset →</Link></td></tr>}
            </tbody></table>
          ) : <p className="muted">Select a node. The graph shows only what OTProbe has observed: physical links come from the
            switch's LLDP/FDB table (after probing it), flows from WMI netstat and MQTT.</p>}
        </Panel>
      </div>
    </div>
  );
}
