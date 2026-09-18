import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './browser-tests',
  testMatch: '**/*.spec.mjs',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 2,
  timeout: 45_000,
  expect: { timeout: 30_000 },
  reporter: 'line',
  outputDir: 'artifacts/browser-smoke',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    browserName: 'chromium',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node scripts/serve-browser-smoke.mjs',
    url: 'http://127.0.0.1:4173/app/',
    reuseExistingServer: false,
    timeout: 15_000,
  },
  projects: [
    {
      name: 'desktop',
      grep: /normal motion/i,
      use: {
        viewport: { width: 1440, height: 900 },
        reducedMotion: 'no-preference',
      },
    },
    {
      name: 'mobile-reduced',
      grep: /reduced motion/i,
      use: {
        viewport: { width: 390, height: 844 },
        hasTouch: true,
        isMobile: true,
        reducedMotion: 'reduce',
      },
    },
  ],
});
