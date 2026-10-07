import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";
const PASSPHRASE = "correct horse battery";
const NEW_PASSPHRASE = "a fresh vault passphrase 42";
const BIOMETRIC_RECORD_KEY = "personal_otp_vault_biometric_v1";
const ENCRYPTED_VAULT_KEY = "personal_otp_vault_encrypted_v1";

// Injects a deterministic fake WebAuthn PRF platform authenticator. PRF
// output = SHA-256(credentialId || prfSalt) — stable per credential and salt,
// so enroll → lock → assert round-trips through the real HKDF/wrap crypto.
// The credential registry rides sessionStorage so it survives reloads.
async function installPrfStub(page, { capable = true } = {}) {
  await page.addInitScript((capable) => {
    const registryKey = "__prf_credentials_v1";
    const b64uEncode = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const b64uDecode = (value) => {
      const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
      const text = atob(padded);
      return Uint8Array.from(text, (ch) => ch.charCodeAt(0));
    };
    const readRegistry = () => {
      try {
        return JSON.parse(sessionStorage.getItem(registryKey) || "{}");
      } catch {
        return {};
      }
    };
    const writeRegistry = (registry) => {
      sessionStorage.setItem(registryKey, JSON.stringify(registry));
    };
    const concatBytes = (left, right) => {
      const out = new Uint8Array(left.length + right.length);
      out.set(left, 0);
      out.set(right, left.length);
      return out;
    };

    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => Boolean(capable);
    if (typeof window.PublicKeyCredential.getClientCapabilities === "function") {
      window.PublicKeyCredential.getClientCapabilities = async () => ({ prf: Boolean(capable) });
    }

    const stubContainer = {
      async create({ publicKey }) {
        if (!capable) throw new DOMException("NotAllowedError", "NotAllowedError");
        const rawId = crypto.getRandomValues(new Uint8Array(32));
        const registry = readRegistry();
        registry[b64uEncode(rawId)] = { rawId: b64uEncode(rawId) };
        writeRegistry(registry);
        return {
          rawId,
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
        };
      },
      async get({ publicKey }) {
        const credentialId = b64uEncode(new Uint8Array(publicKey.allowCredentials[0].id));
        const registry = readRegistry();
        if (!registry[credentialId]) {
          throw new DOMException("The credential is gone", "NotAllowedError");
        }
        const extensions = publicKey.extensions?.prf || {};
        const salt = extensions.evalByCredential?.[credentialId]?.first
          || extensions.eval?.first;
        if (!salt) throw new DOMException("No PRF salt supplied", "NotSupportedError");
        const rawId = b64uDecode(registry[credentialId].rawId);
        const digest = await crypto.subtle.digest("SHA-256", concatBytes(rawId, new Uint8Array(salt)));
        return {
          rawId,
          getClientExtensionResults: () => ({ prf: { results: { first: digest } } }),
        };
      },
    };
    Object.defineProperty(navigator, "credentials", {
      value: stubContainer,
      configurable: true,
    });
  }, capable);
}

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

async function addEntry(page, { label, secret }) {
  await page.locator("#secret").fill(secret);
  await page.locator("#label").fill(label);
  await page.getByRole("button", { name: "Save Entry" }).click();
}

async function acceptPersistWarning(page) {
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
}

// Creates a persisted encrypted vault with one entry, unlocked in-session.
async function createEncryptedVault(page) {
  await loadApp(page);
  await addEntry(page, { label: "GitHub:user@example.com", secret: PRIMARY_SECRET });
  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await acceptPersistWarning(page);
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");
}

test("hides biometric UI when the platform authenticator is not PRF-capable", async ({ page }) => {
  await installPrfStub(page, { capable: false });
  await loadApp(page);

  await expect(page.locator("#biometric-settings")).toBeHidden();
  await expect(page.locator("#biometric-unlock-btn")).toBeHidden();
});

test("hides the unlock biometric button while no credential is enrolled", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  await expect(page.locator("#biometric-settings")).toBeVisible();
  await expect(page.locator("#biometric-status-line")).toContainText("Unlock with your platform authenticator");
  await expect(page.locator("#enroll-biometric-btn")).toBeVisible();

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await expect(page.locator("#biometric-unlock-btn")).toBeHidden();
});

test("reconciles an orphaned biometric record back to passphrase-only", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  // A record with no `dek` block in the envelope can never unwrap — the
  // vault must self-heal to passphrase-only at load (FR3).
  await page.evaluate(() => {
    localStorage.setItem("personal_otp_vault_biometric_v1", JSON.stringify({
      credentialId: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      prfSalt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      wrappedDek: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      wrappedIv: "AAAAAAAAAAAAAAAAAAAAAA",
    }));
  });

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  const record = await page.evaluate((key) => localStorage.getItem(key), BIOMETRIC_RECORD_KEY);
  expect(record).toBeNull();

  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
});

test("biometric unlock holds the DEK so mutations persist across reloads", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  await page.locator("#enroll-biometric-btn").click();
  await expect(page.locator("#settings-status")).toContainText("Biometric unlock enabled");
  await expect(page.locator("#disenroll-biometric-btn")).toBeVisible();

  // Biometric unlock must never set the passphrase (FR8) — saves ride the
  // held DEK only.
  const passphraseAfterEnroll = await page.evaluate(() => localStorage.getItem("personal_otp_vault_settings_v3"));
  expect(passphraseAfterEnroll).not.toContain(PASSPHRASE);

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await expect(page.locator("#biometric-unlock-btn")).toBeVisible();

  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");
  await expect(page.locator(".entry")).toHaveCount(1);

  await addEntry(page, { label: "Added:after@biometric.dev", secret: "KRSXG5DSM5UQ====" });
  await expect(page.locator(".entry")).toHaveCount(2);

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");
  await expect(page.locator(".entry")).toHaveCount(2);
});

test("exports a passphrase-restorable standard envelope in biometric mode", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  await page.locator("#enroll-biometric-btn").click();
  await expect(page.locator("#settings-status")).toContainText("Biometric unlock enabled");

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");

  // FR12: the export is gated behind one passphrase re-entry (prompt).
  page.once("dialog", (dialog) => dialog.accept(PASSPHRASE));
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const download = await downloadPromise;
  const backup = JSON.parse(await readFile(await download.path(), "utf8"));

  // FR10: standard envelope, no dek block, restorable by passphrase alone.
  expect(backup.payload.vault.kdf.mode).toBeUndefined();
  expect(backup.payload.vault.dek).toBeUndefined();

  // The exported backup restores by passphrase on a fresh vault.
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await addEntry(page, { label: "Seed:before@restore.dev", secret: "MFRGGZDFMZTWQ2LK" });
  await page.locator("#import-backup").setInputFiles({
    name: "biometric-backup.json",
    mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify(backup)),
  });
  await expect(page.locator("#backup-review-dialog")).toBeVisible();
  await page.locator("#backup-import-mode").selectOption("replace");
  await page.locator("#backup-import-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-backup-import").click();
  await expect(page.locator("#confirm-dialog")).toBeVisible();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator("#settings-status")).toContainText("Backup imported");
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("GitHub");
});

test("rejects the requirePassphrase gate when the wrong passphrase is entered", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  await page.locator("#enroll-biometric-btn").click();
  await expect(page.locator("#settings-status")).toContainText("Biometric unlock enabled");

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");

  page.once("dialog", (dialog) => dialog.accept("totally wrong passphrase"));
  const downloadPromise = page.waitForEvent("download", { timeout: 3000 }).catch(() => null);
  await page.getByRole("button", { name: "Export Backup" }).click();
  expect(await downloadPromise).toBeNull();
  await expect(page.locator("#settings-status")).toContainText("Incorrect passphrase");
});

test("passphrase change in biometric mode re-wraps the DEK without breaking biometrics", async ({ page }) => {
  await installPrfStub(page);
  await createEncryptedVault(page);

  await page.locator("#enroll-biometric-btn").click();
  await expect(page.locator("#settings-status")).toContainText("Biometric unlock enabled");

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");

  // FR12 gate prompts once for the current passphrase, then the re-wrap runs.
  page.once("dialog", (dialog) => dialog.accept(PASSPHRASE));
  await page.getByRole("button", { name: "Change Passphrase" }).click();
  await page.locator("#current-passphrase").fill(PASSPHRASE);
  await page.locator("#new-passphrase").fill(NEW_PASSPHRASE);
  await page.locator("#new-passphrase-confirm").fill(NEW_PASSPHRASE);
  await page.getByRole("button", { name: "Update Passphrase" }).click();
  await expect(page.locator("#settings-status")).toContainText("Vault passphrase updated");

  const envelopeBefore = await page.evaluate((key) => JSON.parse(localStorage.getItem(key)), ENCRYPTED_VAULT_KEY);
  expect(envelopeBefore.kdf.mode).toBe("dek-v1");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();

  // Old passphrase must now fail; the record survives (KEK wrap independent).
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toContainText("Incorrect passphrase");

  const record = await page.evaluate((key) => localStorage.getItem(key), BIOMETRIC_RECORD_KEY);
  expect(record).not.toBeNull();

  // FR11: biometric unlock still works after the re-wrap.
  await page.locator("#biometric-unlock-btn").click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked with biometrics");
  await expect(page.locator(".entry")).toHaveCount(1);

  // And the new passphrase unlocks too.
  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await page.locator("#unlock-passphrase").fill(NEW_PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});
