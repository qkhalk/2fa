import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  fullyParallel: true,
  // The PBKDF2-bound backup/unlock specs are CPU-bound; machine-dependent
  // default workers (8 here, 2-4 on CI) oversubscribe cores and make the
  // slowest flows exceed their expect windows. Pin parallelism explicitly.
  workers: process.env.CI ? 2 : 4,
  // Keep the flat per-spec snapshot dirs used so far ({arg}-win32.png);
  // the default template would inject project-name segments now that the
  // suite is split into named projects below.
  snapshotPathTemplate: "{snapshotDir}/{testFileDir}-snapshots/{arg}{-platform}{-ext}",
  projects: [
    {
      name: "web",
      testIgnore: /extension/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      // Every extension test boots its own persistent-context Chromium.
      // Under shared parallelism the PBKDF2-bound unlock flows outrun the
      // expect windows and clicks land mid-operation, which CI has proven
      // repeatedly (extension throttle, ring drift). Run them serially via
      // `playwright test --project=extension --workers=1`.
      name: "extension",
      testMatch: /extension.*\.spec\.js/,
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  use: {
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
