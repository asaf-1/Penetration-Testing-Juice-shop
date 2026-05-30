import { defineConfig, devices } from '@playwright/test';
import { loadAuditConfig } from './src/config';

const auditConfig = loadAuditConfig();

export default defineConfig({
  testDir: './tests',
  // Only the end-to-end security specs are Playwright tests. Unit tests under
  // tests/unit/*.test.ts belong to Vitest and must be excluded here.
  testMatch: '**/*.spec.ts',
  outputDir: process.env.PLAYWRIGHT_TEST_RESULTS ?? 'test-results',
  timeout: 45_000,
  expect: {
    timeout: 10_000
  },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: process.env.PLAYWRIGHT_HTML_REPORT ?? 'playwright-report', open: 'never' }],
    ['./src/reporters/security-reporter.ts']
  ],
  // Start the local lab server automatically when no external TARGET_URL is provided.
  webServer: {
    command: 'node scripts/local-lab.mjs',
    url: 'http://localhost:3000',
    reuseExistingServer: true,
    timeout: 30_000
  },
  use: {
    baseURL: auditConfig.targetUrl,
    actionTimeout: 10_000,
    navigationTimeout: 20_000,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure'
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] }
    }
  ]
});
