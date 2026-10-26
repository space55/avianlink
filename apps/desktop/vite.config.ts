import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// Tauri serves the frontend from this dev server and loads the built output
// from `dist/` in release. The port is fixed and `strictPort` is on because
// `tauri.conf.json` names it in `devUrl` and in the development CSP: if Vite
// silently moved to another port, the window would load nothing.
const DEV_PORT = 1420;

export default defineConfig({
  plugins: [svelte()],
  // Tauri's CLI owns the terminal; clearing it hides its output.
  clearScreen: false,
  server: {
    port: DEV_PORT,
    strictPort: true,
    // Loopback only. Nothing about this app should be reachable from the
    // network, not even in development.
    host: '127.0.0.1',
    watch: {
      // Rebuilding the frontend because a Rust file changed just makes the
      // Tauri rebuild slower.
      ignored: ['**/src-tauri/**'],
    },
  },
  build: {
    // Matches the oldest WebView each desktop target ships.
    target: 'es2022',
    sourcemap: true,
  },
});
