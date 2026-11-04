import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { chunkSizeWarningLimit: 1200 },
  // OTPROBE_API lets a second stack run side by side (e.g. API on :8002)
  server: { proxy: { "/api": process.env.OTPROBE_API ?? "http://localhost:8000" } },
});
