import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout, NAV } from "./components/Layout";
import { AssetDetail } from "./pages/AssetDetail";
import { Assets } from "./pages/Assets";
import { AuditLogs } from "./pages/AuditLogs";
import { Dashboard } from "./pages/Dashboard";
import { Discovery } from "./pages/Discovery";
import { NetworkMap } from "./pages/NetworkMap";
import { Pending } from "./pages/Pending";
import { Probes } from "./pages/Probes";
import { Settings } from "./pages/Settings";
import "./styles.css";

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 2000, refetchOnWindowFocus: false } } });

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="network-map" element={<NetworkMap />} />
            <Route path="discovery" element={<Discovery />} />
            <Route path="assets" element={<Assets />} />
            <Route path="assets/:id" element={<AssetDetail />} />
            <Route path="probes" element={<Probes />} />
            <Route path="audit" element={<AuditLogs />} />
            <Route path="settings" element={<Settings />} />
            {NAV.filter((n) => n.phase).map((n) => <Route key={n.to} path={n.to.slice(1)} element={<Pending />} />)}
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
