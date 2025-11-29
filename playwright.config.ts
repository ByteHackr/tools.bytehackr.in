// @ts-check
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  timeout: 60 * 1000,
  retries: 0,
  use: {
    baseURL: 'http://127.0.0.1:4173',
    headless: true,
    viewport: { width: 1280, height: 720 },
    trace: 'on-first-retry'
  },
  webServer: {
    command: 'python -m http.server 4173',
    port: 4173,
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000
  }
});
