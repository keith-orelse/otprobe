import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout, NAV } from "./components/Layout";
import { AgentDetail, Agents, RemovalDetail } from "./pages/Agents";
import { Approvals } from "./pages/Approvals";
import { AssessmentDetail, Assessments } from "./pages/Assessments";
import { Compare } from "./pages/Compare";
import { FindingDetail, Findings } from "./pages/Findings";
import { AssetDetail } from "./pages/AssetDetail";
import { Assets } from "./pages/Assets";
import { AuditLogs } from "./pages/AuditLogs";
import { Dashboard } from "./pages/Dashboard";
import { DemoControls } from "./pages/DemoControls";
import { DeploymentDetail, Deployments } from "./pages/Deployments";
import { Discovery } from "./pages/Discovery";
import { Login } from "./pages/Login";
import { NetworkMap } from "./pages/NetworkMap";
import { Pending } from "./pages/Pending";
import { Probes } from "./pages/Probes";
import { Settings } from "./pages/Settings";
import { Telemetry } from "./pages/Telemetry";
import "./styles.css";

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2000, refetchOnWindowFocus: false } } });

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="login" element={<Login />} />
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="network-map" element={<NetworkMap />} />
            <Route path="discovery" element={<Discovery />} />
            <Route path="assets" element={<Assets />} />
            <Route path="assets/:id" element={<AssetDetail />} />
            <Route path="probes" element={<Probes />} />
            <Route path="audit" element={<AuditLogs />} />
            <Route path="settings" element={<Settings />} />
            <Route path="deployments" element={<Deployments />} />
            <Route path="deployments/:id" element={<DeploymentDetail />} />
            <Route path="approvals" element={<Approvals />} />
            <Route path="agents" element={<Agents />} />
            <Route path="agents/:id" element={<AgentDetail />} />
            <Route path="demo" element={<DemoControls />} />
            <Route path="assessments" element={<Assessments />} />
            <Route path="assessments/:id" element={<AssessmentDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="findings/:id" element={<FindingDetail />} />
            <Route path="assets/:id/compare" element={<Compare />} />
            <Route path="removals/:id" element={<RemovalDetail />} />
            <Route path="telemetry" element={<Telemetry />} />
            {NAV.filter((n) => n.phase).map((n) => <Route key={n.to} path={n.to.slice(1)} element={<Pending />} />)}
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
