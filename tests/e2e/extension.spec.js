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
    await page.locator("#tags").fill("work");
    await page.locator("#period").fill("30");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#label").fill("Backup:user@example.com");
    await page.locator("#secret").fill("NB2W45DFOIZA====");
    await page.locator("#period").fill("30");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await expect(page.locator(".entry-card")).toHaveCount(2);
    await expect(page.locator(".issuer")).toContainText(["Backup", "GitHub"]);
    await expect(page.locator(".code").first()).toHaveText(/\d{3} \d{3}/);
    await expect(page.locator(".tag")).toContainText(["work"]);

    await page.locator(".entry-card").nth(1).getByRole("button", { name: "Edit" }).click();
    await page.locator("#edit-label").fill("GitHub-updated:user@example.com");
    await page.locator("#save-edit").click();
    await expect(page.locator(".issuer")).toContainText(["Backup", "GitHub-updated"]);

    await page.locator("#sort-select").selectOption("custom");
    await expect(page.locator(".issuer").first()).toHaveText("GitHub-updated");
    await page.locator(".entry-card").first().getByRole("button", { name: "Down" }).click();
    await expect(page.locator(".issuer").first()).toHaveText("Backup");

    await page.locator("#search").fill("github-updated");
    await expect(page.locator(".entry-card")).toHaveCount(1);
    await page.locator("#search").fill("personal");
    await expect(page.locator("#entries")).toContainText("No entries yet");
  } finally {
    await context.close();
  }
});
