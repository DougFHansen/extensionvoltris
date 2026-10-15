import { defineConfig, devices } from '@playwright/test';
import { resolve } from 'node:path';

/**
 * End-to-end configuration.
 *
 * The extension is loaded into a REAL Chromium with `--load-extension`, which is
 * the only way to exercise declarativeNetRequest, the service worker and the
 * popup exactly as a user would.
 *
 * All test targets use RESERVED names (RFC 2606 `.test`, `.invalid`) served by a
 * local fixture server. No real malicious site is ever visited.
 */
export default defineConfig({
  testDir: './tests/e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],

  use: {
    baseURL: 'http://127.0.0.1:4319',
    trace: 'off',
    video: 'off',
    screenshot: 'off',
  },

  projects: [
    {
      name: 'chromium-extension',
      use: {
        ...devices['Desktop Chrome'],
        // Persistent context is mandatory for extensions.
        channel: 'chromium',
        // New headless mode: supports extensions and matches CI/desktop parity.
        headless: true,
        launchOptions: {
          args: [
            `--disable-extensions-except=${resolve(process.cwd(), 'dist/chrome')}`,
            `--load-extension=${resolve(process.cwd(), 'dist/chrome')}`,
            '--no-sandbox',
            '--disable-gpu',
          ],
        },
      },
    },
  ],

  webServer: {
    command: 'node tests/e2e/fixture-server.mjs',
    url: 'http://127.0.0.1:4319/health',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
