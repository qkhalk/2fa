import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";
const PASSPHRASE = "correct horse battery";

async function loadApp(page) {
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

  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
}

async function addEntry(page, { label, secret, digits = "6", period = "30" }) {
  await page.locator("#secret").fill(secret);
  await page.locator("#label").fill(label);
  await page.locator("#digits").selectOption(digits);
  await page.locator("#period").fill(period);
  await page.getByRole("button", { name: "Save Entry" }).click();
}

async function enableEncryptedPersistence(page) {
  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");
}

test("requires explicit confirmation before clearing all entries", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await expect(page.locator("#confirm-title")).toContainText("Clear all entries");
  await page.getByRole("button", { name: "Cancel" }).click();

  await expect(page.locator(".entry")).toHaveCount(1);
});

test("requires explicit confirmation before bulk remove", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });
  await addEntry(page, { label: "Beta:user@example.com", secret: "NB2W45DFOIZA====" });

  await page.locator(".entry-select").first().check();
  await page.getByRole("button", { name: "Remove Selected" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await expect(page.locator("#confirm-title")).toContainText("Remove selected entries");
  await page.getByRole("button", { name: "Cancel" }).click();

  await expect(page.locator(".entry")).toHaveCount(2);
});

test("rejects encrypted backup import with wrong passphrase", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Secure:user@example.com", secret: PRIMARY_SECRET });
  await enableEncryptedPersistence(page);

  const encryptedDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const encryptedDownload = await encryptedDownloadPromise;
  const encryptedBackup = await readFile(await encryptedDownload.path());

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.locator("#import-backup").setInputFiles({
    name: "encrypted-backup.json",
    mimeType: "application/json",
    buffer: encryptedBackup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-passphrase").fill("wrong passphrase");
  await page.locator("#confirm-backup-import").click();

  await expect(page.locator("#settings-status")).toContainText("Incorrect passphrase or unreadable encrypted data");
  await expect(page.locator(".entry")).toHaveCount(0);
});

test("rejects malformed backup files", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#import-backup").setInputFiles({
    name: "malformed-backup.json",
    mimeType: "application/json",
    buffer: Buffer.from('{"schemaVersion":4,"entries":"not-an-array"}', "utf8"),
  });

  await expect(page.locator("#settings-status")).toContainText("Backup version is not supported");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("allows retrying encrypted backup import after a wrong passphrase", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Secure:user@example.com", secret: PRIMARY_SECRET });
  await enableEncryptedPersistence(page);

  const encryptedDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const encryptedDownload = await encryptedDownloadPromise;
  const encryptedBackup = await readFile(await encryptedDownload.path());

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.locator("#import-backup").setInputFiles({
    name: "encrypted-backup.json",
    mimeType: "application/json",
    buffer: encryptedBackup,
  });

  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-passphrase").fill("wrong passphrase");
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#settings-status")).toContainText("Incorrect passphrase or unreadable encrypted data");
  await expect(page.locator("#backup-review-dialog")).toBeVisible();

  await page.locator("#backup-import-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("keeps existing entries on merge import when incoming entries are duplicates", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });

  const plainDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const plainDownload = await plainDownloadPromise;
  const plainBackup = await readFile(await plainDownload.path());

  await page.locator("#import-backup").setInputFiles({
    name: "plain-backup.json",
    mimeType: "application/json",
    buffer: plainBackup,
  });

  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-mode").selectOption("merge");
  await page.locator("#confirm-backup-import").click();

  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("replace import overwrites existing entries with backup entries", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });

  const plainDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const plainDownload = await plainDownloadPromise;
  const plainBackup = await readFile(await plainDownload.path());

  await addEntry(page, { label: "Beta:user@example.com", secret: "NB2W45DFOIZA====" });
  await expect(page.locator(".entry")).toHaveCount(2);

  await page.locator("#import-backup").setInputFiles({
    name: "plain-backup.json",
    mimeType: "application/json",
    buffer: plainBackup,
  });

  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-mode").selectOption("replace");
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();

  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Alpha");
});

test("preserves encrypted vault settings and unlock behavior after backup replace and reload", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Vault:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  const encryptedDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const encryptedDownload = await encryptedDownloadPromise;
  const encryptedBackup = await readFile(await encryptedDownload.path());

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.locator("#import-backup").setInputFiles({
    name: "encrypted-backup.json",
    mimeType: "application/json",
    buffer: encryptedBackup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-backup-import").click();

  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator("#persist-toggle")).toBeChecked();
  await expect(page.locator("#encrypt-toggle")).toBeChecked();
  await expect(page.locator("#unlock-panel")).toBeHidden();

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator("#persist-toggle")).toBeChecked();
  await expect(page.locator("#encrypt-toggle")).toBeChecked();
});
