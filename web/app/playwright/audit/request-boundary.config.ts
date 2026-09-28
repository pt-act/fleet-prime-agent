import { defineConfig, devices } from "@playwright/test";

/**
 * Per-spec Playwright config for the request-boundary audit suite.
 *
 * Deliberately does NOT define a webServer: each case owns its fixtures —
 * disposable Vite dev servers and packaged-launcher child processes on
 * ephemeral ports — per the spec's fixture contract.
 */
export default defineConfig({
	testDir: ".",
	testMatch: "request-boundary.spec.ts",
	fullyParallel: false,
	workers: 1,
	retries: 0,
	forbidOnly: true,
	reporter: "list",
	timeout: 120_000,
	use: {
		trace: "off",
		screenshot: "off",
	},
	projects: [
		{ name: "chromium", use: { ...devices["Desktop Chrome"] } },
		{ name: "firefox", use: { ...devices["Desktop Firefox"] } },
		{ name: "webkit", use: { ...devices["Desktop Safari"] } },
	],
});
