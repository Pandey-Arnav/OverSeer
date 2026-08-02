import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/demo-bank/",
  plugins: [react()],
  server: {
    port: 4173,
    proxy: { "/api": "http://127.0.0.1:4100" },
  },
});
