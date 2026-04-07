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

test("extension popup supports encryption, unlock, and copy history", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-secure-"));
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
    if (!serviceWorker) serviceWorker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(serviceWorker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("Secure:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await page.locator("#unlock-passphrase").fill("correct horse battery");
    await page.locator("#unlock-passphrase").press("Enter");
    await expect(page.locator("#unlock-status")).toContainText("Vault unlocked");

    await page.locator(".entry-card").first().getByRole("button", { name: "Copy" }).click();
    await expect(page.locator(".history-item")).toHaveCount(1);
    await expect(page.locator(".history-item")).toContainText(["Secure:user@example.com"]);
  } finally {
    await context.close();
  }
});

test("extension keeps encryption controls unchanged when encrypted save fails", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-save-fail-"));
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
    if (!serviceWorker) serviceWorker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(serviceWorker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("Secure:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.evaluate(() => {
      const originalSet = chrome.storage.local.set.bind(chrome.storage.local);
      chrome.storage.local.set = async (items) => {
        if (items && typeof items === "object" && "otp_extension_encrypted_v1" in items) {
          throw new Error("Simulated extension encrypted storage failure");
        }
        return originalSet(items);
      };
    });

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");

    await expect(page.locator("#status")).toContainText("Simulated extension encrypted storage failure");
    await expect(page.locator("#encrypt-toggle")).not.toBeChecked();
    await expect(page.locator("#lock-btn")).toBeDisabled();
    await expect(page.locator("#unlock-panel")).toBeHidden();
    await expect(page.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension restores vault artifacts when encrypted save cleanup fails", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-artifact-rollback-"));
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
    if (!serviceWorker) serviceWorker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(serviceWorker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("Artifact:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.evaluate(() => {
      const originalSet = chrome.storage.local.set.bind(chrome.storage.local);
      const originalRemove = chrome.storage.local.remove.bind(chrome.storage.local);
      let encryptedWriteCount = 0;
      chrome.storage.local.set = async (items) => {
        if (items && typeof items === "object" && "otp_extension_encrypted_v1" in items) {
          encryptedWriteCount += 1;
        }
        return originalSet(items);
      };
      chrome.storage.local.remove = async (keys) => {
        const keyList = Array.isArray(keys) ? keys : [keys];
        if (keyList.includes("otp_extension_entries_v2") && encryptedWriteCount > 0) {
          throw new Error("Simulated extension artifact cleanup failure");
        }
        return originalRemove(keys);
      };
    });

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");

    await expect(page.locator("#status")).toContainText("Simulated extension artifact cleanup failure");
    await expect(page.locator("#encrypt-toggle")).not.toBeChecked();
    await expect(page.locator(".entry-card")).toHaveCount(1);

    const plainEntries = await page.evaluate(() =>
      new Promise((resolve) => chrome.storage.local.get("otp_extension_entries_v2", (r) => resolve(r.otp_extension_entries_v2)))
    );
    expect(plainEntries).not.toBeNull();
    expect(plainEntries).toHaveLength(1);
  } finally {
    await context.close();
  }
});

test("extension persists encrypted vault and unlocks after popup reopen", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-reopen-"));
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

    await page.locator("#label").fill("Persistent:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");
    await expect(page.locator(".entry-card")).toHaveCount(1);

    await page.close();

    const reopenedPage = await context.newPage();
    await reopenedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(reopenedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedPage.locator(".entry-card")).toHaveCount(0);

    await reopenedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedPage.getByRole("button", { name: "Unlock" }).click();
    await expect(reopenedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedPage.locator(".entry-card")).toHaveCount(1);
    await expect(reopenedPage.locator(".issuer")).toHaveText("Persistent");
    await expect(reopenedPage.locator("#encrypt-toggle")).toBeChecked();
  } finally {
    await context.close();
  }
});

test("extension removes individual entries with destructive actions", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-destructive-"));
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

    await page.locator("#label").fill("Alpha:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#label").fill("Beta:user@example.com");
    await page.locator("#secret").fill("NB2W45DFOIZA====");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await expect(page.locator(".entry-card")).toHaveCount(2);
    await expect(page.locator(".issuer")).toContainText(["Alpha", "Beta"]);

    await page.locator(".entry-card").first().getByRole("button", { name: "x" }).click();
    await expect(page.locator(".entry-card")).toHaveCount(1);
    await expect(page.locator(".issuer")).toHaveText("Beta");

    await page.locator(".entry-card").first().getByRole("button", { name: "x" }).click();
    await expect(page.locator(".entry-card")).toHaveCount(0);
    await expect(page.locator("#entries")).toContainText("No entries yet");
  } finally {
    await context.close();
  }
});

test("extension preserves entries when encrypted entry removal persistence fails", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-remove-fail-"));
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
    if (!serviceWorker) serviceWorker = await context.waitForEvent("serviceworker");
    const extensionId = new URL(serviceWorker.url()).host;
    const page = await context.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);

    await page.locator("#label").fill("Survivor:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.evaluate(() => {
      const originalRemove = chrome.storage.local.remove.bind(chrome.storage.local);
      chrome.storage.local.remove = async (keys) => {
        throw new Error("Simulated extension remove failure");
      };
    });

    await page.locator(".entry-card").first().getByRole("button", { name: "x" }).click();
    await expect(page.locator("#status")).toContainText("Simulated extension remove failure");
    await expect(page.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});
