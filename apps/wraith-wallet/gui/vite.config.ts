import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri 2.x integration: Vite serves on a fixed port in dev so the
// Tauri shell knows where to find it; production build outputs to
// `dist/` which `tauri.conf.json` points `frontendDist` at.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // Don't trigger Vite reloads on Rust-side changes.
      ignored: ["**/src-tauri/**"],
    },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    target: "esnext",
    minify: "esbuild",
    sourcemap: true,
  },
});
