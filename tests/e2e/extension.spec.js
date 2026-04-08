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

test("extension copy history keeps deduped recent labels while rapidly switching entries", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-copy-switch-"));
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

    await page.locator("#label").fill("Alpha:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#label").fill("Beta:user@example.com");
    await page.locator("#secret").fill("NB2W45DFOIZA====");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await expect(page.locator(".entry-card")).toHaveCount(2);

    const firstCard = page.locator(".entry-card").first();
    const secondCard = page.locator(".entry-card").nth(1);

    await firstCard.getByRole("button", { name: "Copy" }).click();
    await secondCard.getByRole("button", { name: "Copy" }).click();
    await firstCard.getByRole("button", { name: "Copy" }).click();
    await secondCard.getByRole("button", { name: "Copy" }).click();

    await expect(page.locator(".history-item")).toHaveCount(2);
    await expect(page.locator(".history-item").nth(0)).toContainText("Beta:user@example.com");
    await expect(page.locator(".history-item").nth(1)).toContainText("Alpha:user@example.com");
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

test("extension keeps failed-save security state stable after popup reopen and preserves unlock flow", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-save-fail-reopen-"));
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

    await page.locator("#label").fill("Reopen:user@example.com");
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

    await page.close();

    const reopenedPage = await context.newPage();
    await reopenedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedPage.locator("#encrypt-toggle")).not.toBeChecked();
    await expect(reopenedPage.locator("#lock-btn")).toBeDisabled();
    await expect(reopenedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedPage.locator(".entry-card")).toHaveCount(1);
    await expect(reopenedPage.locator(".issuer")).toHaveText("Reopen");

    await reopenedPage.locator("#encrypt-toggle").check();
    await reopenedPage.locator("#passphrase").fill("correct horse battery");
    await reopenedPage.locator("#passphrase-confirm").fill("correct horse battery");
    await reopenedPage.locator("#passphrase-confirm").press("Enter");
    await expect(reopenedPage.locator("#status")).toContainText("Encrypted extension vault saved");
    await expect(reopenedPage.locator("#lock-btn")).toBeEnabled();

    await reopenedPage.locator("#lock-btn").click();
    await expect(reopenedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedPage.locator(".entry-card")).toHaveCount(0);

    await reopenedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedPage.locator(".entry-card")).toHaveCount(1);
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

test("extension stays locked across repeated wrong unlock attempts before successful retry", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-unlock-retry-"));
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

    await page.locator("#label").fill("Retry:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("wrong one");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("wrong two");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(lockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension keeps entries hidden and resets failed-unlock messaging after popup reopen", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-unlock-reopen-reset-"));
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

    await page.locator("#label").fill("Locked:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("wrong one");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);
    await expect(reopenedLockedPage.locator("#unlock-status")).not.toContainText("Incorrect passphrase");

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension clears partial unlock input after popup reopen while staying locked", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-unlock-input-reopen-"));
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

    await page.locator("#label").fill("Partial:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("partial secret");
    await expect(lockedPage.locator("#unlock-passphrase")).toHaveValue("partial secret");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator("#unlock-passphrase")).toHaveValue("");
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension shows clean unlock status after multiple failed attempts and popup reopen", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-unlock-status-reopen-"));
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

    await page.locator("#label").fill("Status:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("wrong one");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.locator("#unlock-passphrase").fill("wrong two");
    await lockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(lockedPage.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(0);

    await lockedPage.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);
    await expect(reopenedLockedPage.locator("#unlock-status")).toHaveText("");

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension keeps locked view free of stale success message after relock and popup reopen", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-unlock-success-relock-reopen-"));
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

    await page.locator("#label").fill("Relock:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.locator("#unlock-passphrase").fill("correct horse battery");
    await page.locator("#unlock-passphrase").press("Enter");
    await expect(page.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(page.locator("#unlock-panel")).toBeHidden();
    await expect(page.locator(".entry-card")).toHaveCount(1);

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);
    await expect(reopenedLockedPage.locator("#unlock-status")).not.toContainText("Vault unlocked");

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension keeps locked state and clears stale failed-unlock error after popup reopen", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-failed-unlock-reopen-clean-"));
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

    await page.locator("#label").fill("FailLock:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.locator("#unlock-passphrase").fill("wrong passphrase");
    await page.locator("#unlock-passphrase").press("Enter");
    await expect(page.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);
    await expect(reopenedLockedPage.locator("#unlock-status")).not.toContainText("Incorrect passphrase");

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension preserves unlock continuity across wrong-then-correct attempt and starts next locked view clean", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-wrong-correct-relock-reopen-"));
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

    await page.locator("#label").fill("Continuity:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill("correct horse battery");
    await page.locator("#passphrase-confirm").fill("correct horse battery");
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.locator("#unlock-passphrase").fill("wrong passphrase");
    await page.locator("#unlock-passphrase").press("Enter");
    await expect(page.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.locator("#unlock-passphrase").fill("correct horse battery");
    await page.locator("#unlock-passphrase").press("Enter");
    await expect(page.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(page.locator("#unlock-panel")).toBeHidden();
    await expect(page.locator(".entry-card")).toHaveCount(1);

    await page.locator("#lock-btn").click();
    await expect(page.locator("#unlock-panel")).toBeVisible();
    await expect(page.locator(".entry-card")).toHaveCount(0);

    await page.close();

    const reopenedLockedPage = await context.newPage();
    await reopenedLockedPage.goto(`chrome-extension://${extensionId}/popup.html`);

    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeVisible();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(0);
    await expect(reopenedLockedPage.locator("#unlock-status")).toHaveText("");

    await reopenedLockedPage.locator("#unlock-passphrase").fill("correct horse battery");
    await reopenedLockedPage.locator("#unlock-passphrase").press("Enter");
    await expect(reopenedLockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(reopenedLockedPage.locator("#unlock-panel")).toBeHidden();
    await expect(reopenedLockedPage.locator(".entry-card")).toHaveCount(1);
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

test("extension security form must not silently change active passphrase", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-passphrase-bug-"));
  const extensionPath = resolve("extension");
  const originalPassphrase = "correct horse battery";
  const newPassphrase = "brand new passphrase";

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

    await page.locator("#label").fill("Passphrase:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill(originalPassphrase);
    await page.locator("#passphrase-confirm").fill(originalPassphrase);
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();

    await lockedPage.locator("#passphrase").fill(newPassphrase);
    await lockedPage.locator("#passphrase-confirm").fill(newPassphrase);
    await lockedPage.locator("#save-security").click();
    await expect(lockedPage.locator("#status")).toContainText("Encrypted extension vault saved");

    await lockedPage.locator("#unlock-passphrase").fill(originalPassphrase);
    await lockedPage.locator("#unlock-passphrase").press("Enter");

    await expect(lockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});

test("extension dedicated passphrase change updates unlock passphrase", async () => {
  const userDataDir = await mkdtemp(join(tmpdir(), "otp-vault-extension-passphrase-change-"));
  const extensionPath = resolve("extension");
  const originalPassphrase = "correct horse battery";
  const newPassphrase = "brand new passphrase";

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

    await page.locator("#label").fill("Passphrase:user@example.com");
    await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
    await page.getByRole("button", { name: "Add Entry" }).click();

    await page.locator("#encrypt-toggle").check();
    await page.locator("#passphrase").fill(originalPassphrase);
    await page.locator("#passphrase-confirm").fill(originalPassphrase);
    await page.locator("#passphrase-confirm").press("Enter");
    await expect(page.locator("#status")).toContainText("Encrypted extension vault saved");

    await page.locator("#change-passphrase-btn").click();
    await page.locator("#current-passphrase").fill(originalPassphrase);
    await page.locator("#new-passphrase").fill(newPassphrase);
    await page.locator("#new-passphrase-confirm").fill(newPassphrase);
    await page.locator("#change-passphrase-submit").click();
    await expect(page.locator("#status")).toContainText("Extension passphrase updated");

    await page.close();

    const lockedPage = await context.newPage();
    await lockedPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await expect(lockedPage.locator("#unlock-panel")).toBeVisible();

    await lockedPage.locator("#unlock-passphrase").fill(newPassphrase);
    await lockedPage.locator("#unlock-passphrase").press("Enter");

    await expect(lockedPage.locator("#unlock-status")).toContainText("Vault unlocked");
    await expect(lockedPage.locator(".entry-card")).toHaveCount(1);
  } finally {
    await context.close();
  }
});
