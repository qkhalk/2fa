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
