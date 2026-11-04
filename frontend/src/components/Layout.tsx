import type { LucideIcon } from "lucide-react";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, AlertTriangle, BadgeCheck, ClipboardCheck, Cpu, FlaskConical, LayoutDashboard, LogOut, Network,
  PanelLeftClose, PanelLeftOpen, Radar, Rocket, ScanSearch, ScrollText, Server, Settings,
} from "lucide-react";
import { Navigate, NavLink, Outlet, useLocation } from "react-router-dom";
import { apiGet } from "../api";
import { getToken, logout, useMe } from "../auth";
import { useServerEvents, useStreamStatus } from "../events";
import type { NavCounts } from "../types";
import { ErrorBoundary } from "./ErrorBoundary";
import { EnvBanner, EnvChip, StopAllButton, useEnvironment } from "./Safety";
import { Logo, LogoMark } from "./Logo";
import { Toaster } from "./Toaster";

export interface NavEntry { label: string; to: string; icon: LucideIcon; group: string; title?: string; description: string;
  badge?: (c: NavCounts) => { n: number; tone: "fail" | "warn" | "info"; title: string } | null }

export const NAV: NavEntry[] = [
  { label: "Dashboard", to: "/", icon: LayoutDashboard, group: "Overview",
    description: "Inventory, compliance, monitoring and recent activity at a glance" },
  { label: "Network Map", to: "/network-map", icon: Network, group: "Overview",
    description: "Purdue-level topology built only from what OTProbe has observed" },
  { label: "Discovery", to: "/discovery", icon: Radar, group: "Discover",
    description: "ICMP, ARP, TCP and SNMP discovery, only inside the approved scan scope" },
  { label: "Assets", to: "/assets", icon: Server, group: "Discover",
    description: "Every discovered device, with provenance for each field",
    badge: (c) => (c.rogueAssets ? { n: c.rogueAssets, tone: "fail", title: "rogue devices" } : null) },
  { label: "Agentless Probing", to: "/probes", icon: ScanSearch, group: "Discover",
    description: "Read-only protocol probes: ICMP, ARP, WinRM, WMI, SNMP, SSH, MQTT" },
  { label: "Deployments", to: "/deployments", icon: Rocket, group: "Deep Agent",
    description: "Approved agent deployments: precheck, transfer, install, enrollment" },
  { label: "Approvals", to: "/approvals", icon: BadgeCheck, group: "Deep Agent",
    description: "Four-eyes decisions on deployments and removals",
    badge: (c) => (c.pendingApprovals ? { n: c.pendingApprovals, tone: "info", title: "pending approvals" } : null) },
  { label: "Agents", to: "/agents", icon: Cpu, group: "Deep Agent",
    description: "Outbound-only Probe Agents: heartbeats, restart and rollback",
    badge: (c) => (c.agentsAttention ? { n: c.agentsAttention, tone: "warn", title: "agents STALE, OFFLINE or ERROR" } : null) },
  { label: "Assessments", to: "/assessments", icon: ClipboardCheck, group: "Compliance",
    description: "Rule evaluation runs, scores, drift and configuration changes" },
  { label: "Findings", to: "/findings", icon: AlertTriangle, group: "Compliance",
    description: "Deduplicated findings with lifecycle, drift and risk acceptance",
    badge: (c) => (c.openFindings ? { n: c.openFindings, tone: c.criticalFindings ? "fail" : "warn",
      title: `open findings (${c.criticalFindings} critical/high)` } : null) },
  { label: "MQTT Telemetry", to: "/telemetry", icon: Activity, group: "Compliance",
    description: "Live sensor and PLC telemetry with threshold rules" },
  { label: "Audit Logs", to: "/audit", icon: ScrollText, group: "Administration",
    description: "Append-only, hash-chained record of every action and transition" },
  { label: "Demo Controls", to: "/demo", icon: FlaskConical, group: "Administration", title: "SIMULATION CONTROLS",
    description: "Change the simulated world. OTProbe notices only through probes and agents" },
  { label: "Settings", to: "/settings", icon: Settings, group: "Administration",
    description: "Scan scope, safety controls, credential vault and adapters" },
];

const GROUPS = [...new Set(NAV.map((n) => n.group))];

function current(pathname: string): { entry: NavEntry | undefined; exact: boolean } {
  const exact = NAV.find((n) => n.to === pathname);
  if (exact) return { entry: exact, exact: true };
  const prefix = NAV.filter((n) => n.to !== "/" && pathname.startsWith(n.to))
    .sort((a, b) => b.to.length - a.to.length)[0];
  return { entry: prefix, exact: false };
}

export function Layout() {
  if (!getToken()) return <Navigate to="/login" replace />;
  return <Shell />;
}

function readCollapsed(): boolean {
  try { return localStorage.getItem("otprobe.sidebar") === "collapsed"; } catch { return false; }
}

function Shell() {
  useServerEvents();
  const me = useMe();
  const stream = useStreamStatus();
  const counts = useQuery({ queryKey: ["nav"], queryFn: () => apiGet<NavCounts>("/nav/counts"), refetchInterval: 15000 });
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const toggle = () => {
    setCollapsed((c) => { try { localStorage.setItem("otprobe.sidebar", c ? "open" : "collapsed"); } catch { /* ignore */ } return !c; });
  };
  const { pathname } = useLocation();
  const { entry, exact } = current(pathname);
  const Icon = entry?.icon;
  const env = useEnvironment();
  const live = env.data?.mode === "LIVE";
  const nav = NAV.filter((n) => !(live && n.to === "/demo"));
  const initials = (me.data?.displayName ?? "?").split(" ").map((w) => w[0]).slice(0, 2).join("");
  return (
    <div className="app">
      <EnvBanner />
      <div className={`dashboard-layout${collapsed ? " collapsed" : ""}`}>
        <aside className="sidebar" aria-label="Main navigation">
          {collapsed ? <div className="sidebar-logo"><LogoMark /></div> : <Logo />}
          {GROUPS.map((group) => (
            <div className="nav-group" key={group}>
              <div className="nav-label">{group}</div>
              {nav.filter((n) => n.group === group).map((n) => {
                const badge = counts.data && n.badge ? n.badge(counts.data) : null;
                return (
                  <NavLink key={n.to} to={n.to} end={n.to === "/"} title={collapsed ? n.label : undefined}
                    className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}>
                    <n.icon size={18} strokeWidth={2} /><span className="nav-text">{n.label}</span>
                    {badge && <span className={`nav-badge nav-badge-${badge.tone}`} title={`${badge.n} ${badge.title}`}>{badge.n}</span>}
                  </NavLink>
                );
              })}
            </div>
          ))}
          <div className="sidebar-foot">{live
            ? <><b>LIVE</b> · real network<br />Only the approved scan scope is contacted.</>
            : <><b>POC</b> · simulated OT network<br />No real devices are contacted.</>}</div>
        </aside>
        <div className="main-content">
          <header className="top-bar">
            <div className="top-bar-left">
              <button className="icon-btn" onClick={toggle} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
                {collapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
              </button>
              <span className="top-bar-title">OTProbe · OT Discovery &amp; Probing Console</span>
            </div>
            <div className="top-bar-actions">
              {counts.data && counts.data.runningWorkflows > 0 && (
                <span className="jobs-chip" title="Discovery, probe, deployment or rollback jobs in progress">
                  <span className="spinner" />{counts.data.runningWorkflows} running</span>)}
              <span className={`live-chip live-${stream}`} title="Server-Sent Events connection">
                <span className="live-dot" />{stream === "live" ? "Live" : stream === "connecting" ? "Connecting" : "Reconnecting"}</span>
              <StopAllButton role={me.data?.role} />
              <EnvChip />
              {me.data && (
                <div className="user-profile">
                  <span className="avatar">{initials}</span>
                  <span>{me.data.displayName}<br /><span className="role">{me.data.role}</span></span>
                </div>
              )}
              <button className="btn btn-sm" onClick={logout} title="Sign out"><LogOut size={15} />Sign out</button>
            </div>
          </header>
          <main className="dashboard-page">
            {entry && exact && Icon && (
              <div className="page-header-container">
                <div className="breadcrumb">OTProbe / {entry.group} / {entry.label}</div>
                <div className="page-title-row">
                  <div className="header-icon-bg"><Icon size={26} strokeWidth={2} /></div>
                  <div><h1>{entry.title ?? entry.label}</h1><p>{entry.description}</p></div>
                </div>
              </div>
            )}
            <ErrorBoundary resetKey={pathname}><Outlet /></ErrorBoundary>
          </main>
          <Toaster />
        </div>
      </div>
    </div>
  );
}
