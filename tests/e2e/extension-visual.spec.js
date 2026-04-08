import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { chromium, expect, test } from "@playwright/test";

test.skip(process.platform !== "win32", "Visual snapshots are currently pinned for local Windows rendering.");

const FIXED_NOW = 1_700_000_000_000;

async function loadStableExtensionPopup(page, viewport) {
  await page.setViewportSize(viewport);
  await page.addInitScript(({ fixedNow }) => {
    const RealDate = Date;
    class MockDate extends RealDate {
      constructor(...args) {
        super(...(args.length === 0 ? [fixedNow] : args));
      }
      static now() {
        return fixedNow;
      }
    }
    Object.setPrototypeOf(MockDate, RealDate);
    window.Date = MockDate;
  }, { fixedNow: FIXED_NOW });
}

test("extension popup empty state visual regression", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-visual-empty-"));
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
    await loadStableExtensionPopup(page, { width: 400, height: 600 });
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(page).toHaveScreenshot("extension-popup-empty.png", {
      fullPage: true,
      animations: "disabled",
      maxDiffPixelRatio: 0.02,
    });
  } finally {
    await context.close();
  }
});

test("extension popup populated state visual regression", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-visual-populated-"));
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
    await loadStableExtensionPopup(page, { width: 400, height: 600 });
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("GitHub:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#label").fill("GitLab:user@example.com");
    await page.locator("#secret").fill("NB2W45DFOIZA====");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await expect(page).toHaveScreenshot("extension-popup-populated.png", {
      fullPage: true,
      animations: "disabled",
      maxDiffPixelRatio: 0.02,
    });
  } finally {
    await context.close();
  }
});

test("extension popup locked state visual regression", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-visual-locked-"));
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
    await loadStableExtensionPopup(page, { width: 400, height: 600 });
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("Secure:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();

    await expect(page).toHaveScreenshot("extension-popup-locked.png", {
      fullPage: true,
      animations: "disabled",
      maxDiffPixelRatio: 0.02,
    });
  } finally {
    await context.close();
  }
});
