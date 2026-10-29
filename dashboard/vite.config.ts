import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// `npm run dev` on :5173 proxies the same paths nginx does in Docker. From a laptop with no analyst, point it at the
// homelab dashboard: VITE_API_TARGET=https://graph.jrushvj.dev npm run dev
declare const process: { env: Record<string, string | undefined> }; // Vite config runs in Node
const target = process.env.VITE_API_TARGET ?? "http://localhost:8004";
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": { target, changeOrigin: true, secure: true },
      "/ws": { target: target.replace(/^http/, "ws"), ws: true, changeOrigin: true, secure: true },
    },
  },
});
