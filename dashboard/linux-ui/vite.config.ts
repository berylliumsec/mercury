import { defineConfig } from "vite";

export default defineConfig(({ mode }) => ({
  base: mode === "demo" ? "./" : "/",
  server: {
    host: "127.0.0.1",
    port: 5173
  },
  build: {
    outDir: mode === "demo" ? "dist-demo" : "dist",
    sourcemap: false
  }
}));
