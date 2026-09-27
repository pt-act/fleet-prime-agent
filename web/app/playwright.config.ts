import { defineConfig, devices } from "@playwright/test"

const port = process.env.PLAYWRIGHT_PORT ?? "3000"
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? `http://127.0.0.1:${port}`
const webServer = process.env.PLAYWRIGHT_BASE_URL
  ? undefined
  : {
      // Agentation is a developer annotation surface that can intentionally block
      // clicks; exclude it from product interaction smoke coverage.
      command: `VITE_FLEET_DISABLE_AGENTATION=1 pnpm exec vite dev --port ${port} --strictPort`,
      url: baseURL,
      reuseExistingServer: false,
      timeout: 120_000,
    }

/**
 * Playwright smoke for the Fleet Prime web frontend.
 *
 * Runs a single Chromium project against an isolated Vite dev server.
 */
export default defineConfig({
  testDir: "./playwright",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: "list",
  use: {
    baseURL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    // The request-boundary audit spec requires chromium/firefox/webkit
    // coverage. Extra engines are opt-in (FLEET_AUDIT_BROWSERS=1) so the
    // everyday smoke run stays single-engine; audit invocations set the flag
    // and select a project explicitly.
    ...(process.env.FLEET_AUDIT_BROWSERS === "1"
      ? [
          // Non-chromium engines (webkit especially) can exceed the 30s
          // default during page setup under the audit's scrubbed fixtures,
          // before a test body's own setTimeout takes effect.
          { name: "firefox", use: { ...devices["Desktop Firefox"] }, timeout: 120_000 },
          { name: "webkit", use: { ...devices["Desktop Safari"] }, timeout: 120_000 },
        ]
      : []),
  ],
  webServer,
})
