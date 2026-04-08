import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";
const SECONDARY_SECRET = "NB2W45DFOIZA====";
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

async function acceptPersistWarning(page) {
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
}

test("adds entries manually and renders active OTP codes", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });

  await expect(page.locator("#import-status")).toHaveText("Entry added");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("GitHub");
  await expect(page.locator(".entry-account")).toHaveText("user@example.com");
  await expect(page.locator(".entry-code")).toHaveText(/\d{3} \d{3}/);
});

test("rejects invalid manual input and invalid URI false positives", async ({ page }) => {
  await loadApp(page);

  await addEntry(page, { label: "Broken", secret: "NOT-BASE32!" });
  await expect(page.locator("#import-status")).toContainText("Secret contains invalid Base32 characters");

  await page.locator("#uri").fill("otpauth://totp/Foo:bar?secret=BAD*&digits=6&period=30");
  await page.getByRole("button", { name: "Import otpauth:// URI" }).click();
  await expect(page.locator("#import-status")).toContainText("No valid otpauth:// URI found");
});

test("imports OTP URIs from surrounding text and supports search, pin, and remove", async ({ page }) => {
  await loadApp(page);

  await page.locator("#uri").fill(
    "Please import otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&period=30&digits=6."
  );
  await page.getByRole("button", { name: "Import otpauth:// URI" }).click();
  await expect(page.locator("#import-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Import Entries" }).click();
  await addEntry(page, { label: "Zeta:user@example.com", secret: SECONDARY_SECRET });

  await page.locator(".entry").nth(1).getByRole("button", { name: "Up" }).click();
  await expect(page.locator(".entry-label").first()).toHaveText("Zeta");

  await page.locator(".entry").nth(1).getByRole("button", { name: "Edit" }).click();
  await expect(page.locator("#edit-entry-dialog")).toBeVisible();
  await page.locator("#edit-label").fill("Example-updated:user@example.com");
  await page.locator("#edit-tags").fill("personal");
  await page.locator("#save-entry-edit").click();
  await expect(page.locator("#import-status")).toContainText("Entry updated");

  await page.locator("#search").fill("personal");
  await expect(page.locator(".entry")).toHaveCount(1);
  await page.locator("#search").fill("example-updated");
  await expect(page.locator(".entry")).toHaveCount(1);
  await page.locator("#search").fill("");
  await expect(page.locator(".entry")).toHaveCount(2);
  await page.locator("#search").fill("zeta");
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator(".entry").first().getByRole("button", { name: "Remove" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);
  await expect(page.locator("#entries")).toContainText("No matching entries.");
});

test("persists encrypted vaults and unlocks after reload", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").press("Enter");
  await acceptPersistWarning(page);

  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("migrates legacy plain entries when encryption is enabled but encrypted data does not exist", async ({ page }) => {
  await page.addInitScript(({ secret }) => {
    localStorage.setItem("personal_otp_vault_entries_v2", JSON.stringify([{
      id: "legacy-1",
      label: "Legacy:user@example.com",
      secret,
      digits: 6,
      period: 30,
      pinned: false,
    }]));
    localStorage.setItem("personal_otp_vault_settings_v3", JSON.stringify({
      persist: true,
      encrypt: true,
      unlockOnLoad: true,
      blurCodes: false,
      screenshotSafe: false,
      clearClipboard: false,
      sortBy: "pinned-alpha",
      groupBy: "none",
    }));
  }, { secret: PRIMARY_SECRET });

  await page.goto("/");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Legacy");
  await expect(page.locator("#unlock-panel")).toBeHidden();
});

test("exports and reimports backups in plain and encrypted modes", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });

  const plainDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const plainDownload = await plainDownloadPromise;
  const plainBackup = await readFile(await plainDownload.path());

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.locator("#import-backup").setInputFiles({
    name: "plain-backup.json",
    mimeType: "application/json",
    buffer: plainBackup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);

  const encryptedDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const encryptedDownload = await encryptedDownloadPromise;
  const encryptedBackup = await readFile(await encryptedDownload.path());

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  page.once("dialog", (dialog) => dialog.accept(PASSPHRASE));
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
});

test("keeps web settings and storage mode unchanged when encrypted save fails", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });

  await page.addInitScript(() => {
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (key === "personal_otp_vault_persist_warning_seen_v1") {
        return originalSetItem.call(this, key, value);
      }
      if (key === "personal_otp_vault_encrypted_v1") {
        throw new Error("Simulated encrypted storage failure");
      }
      return originalSetItem.call(this, key, value);
    };
  });
  await page.reload();
  await page.evaluate(() => {
    localStorage.setItem("personal_otp_vault_persist_warning_seen_v1", "true");
  });
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();

  await expect(page.locator("#settings-status")).toContainText("Simulated encrypted storage failure");
  await expect(page.locator("#persist-toggle")).not.toBeChecked();
  await expect(page.locator("#encrypt-toggle")).not.toBeChecked();
  await expect(page.locator("#summary-storage")).toHaveText("Session");
  await expect(page.locator("#unlock-panel")).toBeHidden();
  await expect(page.locator(".entry")).toHaveCount(1);

  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_settings_v3"))).toBeNull();
  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_encrypted_v1"))).toBeNull();
});

test("removes partial encrypted artifacts when cleanup fails after encrypted write", async ({ page }) => {
  await page.addInitScript(({ secret }) => {
    localStorage.setItem("personal_otp_vault_entries_v2", JSON.stringify([{
      id: "persisted-1",
      label: "GitHub:user@example.com",
      secret,
      digits: 6,
      period: 30,
      pinned: false,
    }]));
    localStorage.setItem("personal_otp_vault_settings_v3", JSON.stringify({
      persist: true,
      encrypt: false,
      unlockOnLoad: true,
      blurCodes: false,
      screenshotSafe: false,
      clearClipboard: false,
      sortBy: "pinned-alpha",
      groupBy: "none",
    }));
    localStorage.setItem("personal_otp_vault_persist_warning_seen_v1", "true");

    const originalRemoveItem = Storage.prototype.removeItem;
    Storage.prototype.removeItem = function(key) {
      if (key === "personal_otp_vault_entries_v2" && localStorage.getItem("personal_otp_vault_encrypted_v1")) {
        throw new Error("Simulated cleanup failure after encrypted write");
      }
      return originalRemoveItem.call(this, key);
    };
  }, { secret: PRIMARY_SECRET });

  await page.goto("/");
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();

  await expect(page.locator("#settings-status")).toContainText("Simulated cleanup failure after encrypted write");
  await expect(page.locator("#persist-toggle")).toBeChecked();
  await expect(page.locator("#encrypt-toggle")).not.toBeChecked();
  await expect(page.locator("#summary-storage")).toHaveText("Device");
  await expect(page.locator(".entry")).toHaveCount(1);

  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_settings_v3"))).not.toBeNull();
  await expect.poll(async () => page.evaluate(() => JSON.parse(localStorage.getItem("personal_otp_vault_settings_v3")))).toMatchObject({
    persist: true,
    encrypt: false,
  });
  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_entries_v2"))).not.toBeNull();
  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_encrypted_v1"))).toBeNull();
});

test("rolls back entries and passphrase when encrypted backup import persistence fails", async ({ page }) => {
  await page.addInitScript(({ fixedNow, secret, passphrase }) => {
    const RealDate = Date;
    class MockDate extends RealDate {
      constructor(...args) { super(...(args.length === 0 ? [fixedNow] : args)); }
      static now() { return fixedNow; }
    }
    Object.setPrototypeOf(MockDate, RealDate);
    window.Date = MockDate;

    localStorage.setItem("personal_otp_vault_settings_v3", JSON.stringify({
      persist: true,
      encrypt: true,
      unlockOnLoad: true,
      blurCodes: false,
      screenshotSafe: false,
      clearClipboard: false,
      sortBy: "pinned-alpha",
      groupBy: "none",
    }));
    localStorage.setItem("personal_otp_vault_persist_warning_seen_v1", "true");

    window.__blockNextEncryptedWrite = false;
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (key === "personal_otp_vault_encrypted_v1" && window.__blockNextEncryptedWrite) {
        window.__blockNextEncryptedWrite = false;
        throw new Error("Simulated persistence failure during import");
      }
      return originalSetItem.call(this, key, value);
    };
  }, { fixedNow: FIXED_NOW, secret: PRIMARY_SECRET, passphrase: PASSPHRASE });

  await page.goto("/");
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");

  await addEntry(page, { label: "Original:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator(".entry")).toHaveCount(1);

  const originalDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const originalDownload = await originalDownloadPromise;
  const originalBackup = await readFile(await originalDownload.path());

  await page.evaluate(() => { window.__blockNextEncryptedWrite = true; });

  await page.locator("#import-backup").setInputFiles({
    name: "encrypted-backup.json",
    mimeType: "application/json",
    buffer: originalBackup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-backup-import").click();

  await expect(page.locator("#settings-status")).toContainText("Simulated persistence failure during import");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Original");

  await page.locator("#backup-review-dialog").press("Escape");
  await expect(page.locator("#backup-review-dialog")).toBeHidden();

  const verifyDownloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const verifyDownload = await verifyDownloadPromise;
  const verifyBackup = await readFile(await verifyDownload.path());

  const verifyBackupParsed = JSON.parse(new TextDecoder().decode(verifyBackup));
  expect(verifyBackupParsed.encrypted).toBe(true);

  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.locator("#import-backup").setInputFiles({
    name: "verify-backup.json",
    mimeType: "application/json",
    buffer: verifyBackup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-backup-import").click();

  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Original");
});

test("preserves entries when clear all persistence fails", async ({ page }) => {
  await page.addInitScript(({ fixedNow, secret }) => {
    const RealDate = Date;
    class MockDate extends RealDate {
      constructor(...args) { super(...(args.length === 0 ? [fixedNow] : args)); }
      static now() { return fixedNow; }
    }
    Object.setPrototypeOf(MockDate, RealDate);
    window.Date = MockDate;

    localStorage.setItem("personal_otp_vault_settings_v3", JSON.stringify({
      persist: true,
      encrypt: false,
      unlockOnLoad: true,
      blurCodes: false,
      screenshotSafe: false,
      clearClipboard: false,
      sortBy: "pinned-alpha",
      groupBy: "none",
    }));
    localStorage.setItem("personal_otp_vault_persist_warning_seen_v1", "true");

    window.__blockNextPlainWrite = false;
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (key === "personal_otp_vault_entries_v2" && window.__blockNextPlainWrite) {
        window.__blockNextPlainWrite = false;
        throw new Error("Simulated clear-all persistence failure");
      }
      return originalSetItem.call(this, key, value);
    };
  }, { fixedNow: FIXED_NOW, secret: PRIMARY_SECRET });

  await page.goto("/");
  await addEntry(page, { label: "Survivor:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.evaluate(() => { window.__blockNextPlainWrite = true; });
  await page.getByRole("button", { name: "Clear All" }).click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();

  await expect(page.locator("#import-status")).toContainText("Simulated clear-all persistence failure");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Survivor");

  await expect.poll(async () => page.evaluate(() => localStorage.getItem("personal_otp_vault_entries_v2"))).not.toBeNull();
});

test("preserves entries when replace-mode backup import persistence fails", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Survivor:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator("#persist-toggle").check();
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const download = await downloadPromise;
  const backup = await readFile(await download.path());

  await page.evaluate(() => {
    window.__blockNextPlainWrite = false;
    const originalSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (key === "personal_otp_vault_entries_v2" && window.__blockNextPlainWrite) {
        window.__blockNextPlainWrite = false;
        throw new Error("Simulated replace persistence failure");
      }
      return originalSetItem.call(this, key, value);
    };
  });

  await page.locator("#import-backup").setInputFiles({
    name: "plain-backup.json",
    mimeType: "application/json",
    buffer: backup,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();

  await page.evaluate(() => { window.__blockNextPlainWrite = true; });
  await page.locator("#backup-import-mode").selectOption("replace");
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();

  await expect(page.locator("#settings-status")).toContainText("Simulated replace persistence failure");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Survivor");
});

test("web security form must not silently change active passphrase for existing encrypted vault", async ({ page }) => {
  const originalPassphrase = "correct horse battery";
  const newPassphrase = "brand new passphrase";

  await loadApp(page);
  await addEntry(page, { label: "Passphrase:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(originalPassphrase);
  await page.locator("#vault-passphrase-confirm").fill(originalPassphrase);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.locator("#vault-passphrase").fill(newPassphrase);
  await page.locator("#vault-passphrase-confirm").fill(newPassphrase);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(originalPassphrase);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("web dedicated passphrase change updates unlock passphrase", async ({ page }) => {
  const originalPassphrase = "correct horse battery";
  const newPassphrase = "brand new passphrase";

  await loadApp(page);
  await addEntry(page, { label: "Passphrase:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(originalPassphrase);
  await page.locator("#vault-passphrase-confirm").fill(originalPassphrase);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.getByRole("button", { name: "Change Passphrase" }).click();
  await expect(page.locator("#change-passphrase-dialog")).toBeVisible();
  await page.locator("#current-passphrase").fill(originalPassphrase);
  await page.locator("#new-passphrase").fill(newPassphrase);
  await page.locator("#new-passphrase-confirm").fill(newPassphrase);
  await page.getByRole("button", { name: "Update Passphrase" }).click();
  await expect(page.locator("#settings-status")).toContainText("Vault passphrase updated");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(newPassphrase);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("encrypted backup import with a different passphrase must not silently change active vault passphrase", async ({ page, browser }) => {
  const passphraseA = "correct horse battery";
  const passphraseB = "backup-only secret";

  await loadApp(page);
  await addEntry(page, { label: "VaultA:user@example.com", secret: PRIMARY_SECRET });

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(passphraseA);
  await page.locator("#vault-passphrase-confirm").fill(passphraseA);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  const backupContext = await browser.newContext();
  const backupPage = await backupContext.newPage();
  await loadApp(backupPage);
  await addEntry(backupPage, { label: "VaultB:user@example.com", secret: SECONDARY_SECRET });
  await backupPage.locator("#persist-toggle").check();
  await backupPage.locator("#encrypt-toggle").check();
  await backupPage.locator("#vault-passphrase").fill(passphraseB);
  await backupPage.locator("#vault-passphrase-confirm").fill(passphraseB);
  await backupPage.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(backupPage);
  await expect(backupPage.locator("#settings-status")).toContainText("Encrypted vault saved");

  const backupDownloadPromise = backupPage.waitForEvent("download");
  await backupPage.getByRole("button", { name: "Export Backup" }).click();
  const backupDownload = await backupDownloadPromise;
  const backupWithPassphraseB = await readFile(await backupDownload.path());
  await backupContext.close();

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(passphraseA);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");

  await page.locator("#import-backup").setInputFiles({
    name: "encrypted-backup-b.json",
    mimeType: "application/json",
    buffer: backupWithPassphraseB,
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-mode").selectOption("replace");
  await page.locator("#backup-import-passphrase").fill(passphraseB);
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator("#settings-status")).toContainText("Backup imported");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#unlock-passphrase").fill(passphraseA);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});
