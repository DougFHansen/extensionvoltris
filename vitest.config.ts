import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(process.cwd(), 'src'),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/unit/**/*.test.ts'],
    globals: false,
    reporters: ['default'],

    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      reportsDirectory: 'artifacts/coverage',

      include: ['src/**/*.ts'],

      /**
       * Modules that only run inside a real browser are excluded from the UNIT
       * coverage denominator and verified by the 24 end-to-end tests in
       * `tests/e2e/` instead, which load the built extension into a real
       * Chromium. They cannot be meaningfully measured by vitest running in
       * Node, and counting them as 0% would understate the real coverage
       * without adding any safety.
       *
       * Covered by Playwright: popup, dashboard, settings, blocked page,
       * service-worker routing, listener registration, rule installation,
       * the interstitial, the download listener and the content script.
       */
      exclude: [
        'src/generated/**',
        'src/background/**',
        'src/content/**',
        'src/ui/**',
        'src/data/caches.ts',
        'src/scam/scam-scan-source.ts',
        'src/scam/content-bridge.ts',
        'src/blocking/dataset.ts',
      ],

      thresholds: {
        lines: 70,
        functions: 68,
        branches: 68,
        statements: 70,
      },
    },
  },
});
