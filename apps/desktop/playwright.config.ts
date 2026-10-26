import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright drives the real frontend in a browser with the Tauri IPC mocked
 * (`tests/e2e/mock-backend.ts`). It does not build or launch the Tauri binary:
 * the Rust side has its own tests, and requiring a compiled webview app here
 * would make the suite too slow to run on every change.
 */
const PORT = 1421;

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // A separate port from the Tauri dev server, so running the suite does not
    // fight with `npm run app`.
    command: `npm run build && npx vite preview --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
