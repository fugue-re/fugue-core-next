import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const backend = "http://127.0.0.1:8080";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api/changes": { target: backend, ws: true },
      "/api": { target: backend },
    },
  },
});
