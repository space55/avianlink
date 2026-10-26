import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [svelte()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.ts', 'tests/*.test.ts'],
    // Playwright owns `tests/e2e`; without this, Vitest tries to run the
    // Playwright specs and fails with a confusing error about `test.describe`.
    exclude: ['tests/e2e/**', 'node_modules/**'],
  },
  resolve: {
    conditions: ['browser'],
  },
});
