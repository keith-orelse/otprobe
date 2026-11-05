import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  // OTPROBE_API lets a second stack run side by side (e.g. API on :8002)
  // secure: false lets the dev proxy reach an API that runs with the lab CA (scripts/make_lab_tls.py).
  server: { proxy: { "/api": { target: process.env.OTPROBE_API ?? "http://localhost:8000", secure: false } } },
});
