import { defineConfig, devices } from '@playwright/test';
import { resolve } from 'node:path';

/**
 * End-to-end configuration.
 *
 * The extension is loaded into a REAL Chromium with `--load-extension`, which is
 * the only way to exercise declarativeNetRequest, the service worker and the
 * popup exactly as a user would.
 *
 * All hostile targets are RESERVED names (RFC 2606 `.test`, `.invalid`) that
 * never resolve, served or synthesised locally. No real malicious site is ever
 * visited.
 *
 * `feeds.spec.ts` is the one exception: it downloads the real public threat
 * lists, because the feed pipeline shipped broken for exactly as long as every
 * test avoided it. It is in a separate project so the offline suite stays
 * offline, and both projects are excluded from the other project.
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
      // Offline: fictional threats seeded into storage, no network.
      name: 'chromium-extension',
      testIgnore: /feeds\.spec\.ts/,
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
    {
      // Online: downloads the real feeds. Slow, and depends on upstream being
      // reachable, so it is kept apart from the offline suite.
      name: 'live-feeds',
      testMatch: /feeds\.spec\.ts/,
      timeout: 180_000,
      use: {
        ...devices['Desktop Chrome'],
        channel: 'chromium',
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
