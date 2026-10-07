import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: true,
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:4173",
    serviceWorkers: "block",
    // The app's default look is the dark theme; pin dark so only tests that
    // opt into light (emulateMedia / data-theme) see the light tokens.
    colorScheme: "dark",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run serve:test",
    port: 4173,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
