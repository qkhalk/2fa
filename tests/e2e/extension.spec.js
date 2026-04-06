import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { chromium, expect, test } from "@playwright/test";

test("extension popup supports adding and filtering OTP entries", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-"));
  const extensionPath = resolve("extension");

  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });

  try {
    let [serviceWorker] = context.serviceWorkers();
    if (!serviceWorker) {
      serviceWorker = await context.waitForEvent("serviceworker");
    }

    const extensionId = new URL(serviceWorker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("GitHub:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.locator("#period").fill("30");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await expect(page.locator(".entry-card")).toHaveCount(1);
    await expect(page.locator(".issuer")).toHaveText("GitHub");
    await expect(page.locator(".code")).toHaveText(/\d{3} \d{3}/);

    await page.locator("#search").fill("github");
    await expect(page.locator(".entry-card")).toHaveCount(1);
    await page.locator("#search").fill("personal");
    await expect(page.locator("#entries")).toContainText("No entries yet");
  } finally {
    await context.close();
  }
});
