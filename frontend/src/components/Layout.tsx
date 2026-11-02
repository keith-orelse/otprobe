import { Navigate, NavLink, Outlet } from "react-router-dom";
import { getToken, logout, useMe } from "../auth";
import { useServerEvents } from "../events";

export const NAV: { label: string; to: string; phase?: number }[] = [
  { label: "Dashboard", to: "/" },
  { label: "Network Map", to: "/network-map" },
  { label: "Discovery", to: "/discovery" },
  { label: "Assets", to: "/assets" },
  { label: "Agentless Probing", to: "/probes" },
  { label: "Deployments", to: "/deployments" },
  { label: "Approvals", to: "/approvals" },
  { label: "Agents", to: "/agents" },
  { label: "Assessments", to: "/assessments", phase: 4 },
  { label: "Findings", to: "/findings", phase: 4 },
  { label: "MQTT Telemetry", to: "/telemetry", phase: 5 },
  { label: "Audit Logs", to: "/audit" },
  { label: "Demo Controls", to: "/demo" },
  { label: "Settings", to: "/settings" },
];

export function Layout() {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <Shell />;
}

function Shell() {
  useServerEvents();
  const me = useMe();
  return (
    <div className="shell">
      <div className="sim-banner" role="status">SIMULATED ENVIRONMENT - NO REAL DEVICES ARE BEING SCANNED</div>
      <nav className="nav" aria-label="Main">
        <div className="brand">OT<span>Probe</span></div>
        {NAV.map((n) => (
          <NavLink key={n.to} to={n.to} end={n.to === "/"}
            className={({ isActive }) => `nav-item${isActive ? " active" : ""}${n.phase ? " pending" : ""}`}>
            {n.label}{n.phase && <span className="nav-phase">P{n.phase}</span>}
          </NavLink>
        ))}
        <div className="nav-foot">
          {me.data && <div className="user-box"><b>{me.data.displayName}</b>
            <span className="pill pill-info">{me.data.role}</span></div>}
          <button className="btn btn-sm" onClick={logout}>Sign out</button>
          <div className="muted">POC · simulated OT network</div>
        </div>
      </nav>
      <main className="main"><Outlet /></main>
    </div>
  );
}
