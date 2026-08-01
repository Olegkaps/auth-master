import { defineConfig, devices } from '@playwright/test'

// E2E tests drive the real SPA against a running backend + Mailpit.
//
// Prerequisites (see e2e/README.md):
//   - backend on :8080 with a bootstrap superuser (E2E_ADMIN_LOGIN / _PASSWORD)
//   - Mailpit on :8025 (OTP codes are read from its API)
// The Vite dev server is started automatically by the `webServer` block below.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1, // serial: tests share one Mailpit inbox and one backend DB
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
