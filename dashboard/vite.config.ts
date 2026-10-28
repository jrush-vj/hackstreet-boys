import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// `npm run dev` on :5173 proxies the same paths nginx does in Docker
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": "http://localhost:8004",
      "/ws": { target: "ws://localhost:8004", ws: true },
    },
  },
});
