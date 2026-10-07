import QRCode from "qrcode";

import { expect, test } from "@playwright/test";

const PASSPHRASE = "correct horse battery";
const OTP_URI = "otpauth://totp/E2E:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=E2E&digits=6&period=30";

// Deterministic clock: MockDate starts at FIXED_NOW, advances in real time,
// and tests add extra offset via window.__advanceClockMs. Real setInterval(1s)
// keeps firing, so tick() sees the advanced idle time on its next beat.
const FIXED_NOW = 1_700_000_000_000;

async function loadAppWithClock(page, { rate = 1 } = {}) {
  await page.addInitScript(({ fixedNow, clockRate }) => {
    const RealDate = Date;
    const installedAtReal = RealDate.now();
    let offsetMs = 0;
    class MockDate extends RealDate {
      constructor(...args) {
        super(...(args.length === 0 ? [fixedNow + offsetMs + (RealDate.now() - installedAtReal) * clockRate] : args));
      }

      static now() {
        return fixedNow + offsetMs + (RealDate.now() - installedAtReal) * clockRate;
      }
    }
    Object.setPrototypeOf(MockDate, RealDate);
    window.Date = MockDate;
    window.__advanceClockMs = (ms) => {
      offsetMs += ms;
    };
  }, { fixedNow: FIXED_NOW, clockRate: rate });

  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("#secret")).toBeVisible();
}

async function addEntry(page, { label, secret }) {
  await page.locator("#secret").fill(secret);
  await page.locator("#label").fill(label);
  await page.getByRole("button", { name: "Save Entry" }).click();
}

async function enableEncryptedPersistence(page) {
  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(PASSPHRASE);
  await page.locator("#vault-passphrase-confirm").fill(PASSPHRASE);
  await page.locator("#auto-lock-select").selectOption("5");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");
}

test("locks the vault after the idle timeout and requires the passphrase again", async ({ page }) => {
  await loadAppWithClock(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: "JBSWY3DPEHPK3PXP" });
  await enableEncryptedPersistence(page);
  await expect(page.locator("#unlock-panel")).toBeHidden();

  await page.evaluate(() => window.__advanceClockMs(6 * 60 * 1000));
  await expect(page.locator("#unlock-panel")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator(".entry")).toHaveCount(0);
});

test("manual Lock Vault clears the passphrase so re-unlock is required", async ({ page }) => {
  await loadAppWithClock(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: "JBSWY3DPEHPK3PXP" });
  await enableEncryptedPersistence(page);
  await expect(page.locator("#unlock-panel")).toBeHidden();

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  await expect(page.locator(".entry")).toHaveCount(0);

  // The correct passphrase still unlocks — proving the lock cleared the
  // in-memory passphrase and the vault was not silently left unlocked.
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  await expect(page.locator(".entry")).toHaveCount(1);
});

test("throttles unlock attempts with a visible countdown after three failures", async ({ page }) => {
  // Frozen page clock: the 1s backoff window stays open until the test
  // advances time, making the countdown observable deterministically.
  await loadAppWithClock(page, { rate: 0 });
  await addEntry(page, { label: "Alpha:user@example.com", secret: "JBSWY3DPEHPK3PXP" });
  await enableEncryptedPersistence(page);

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await expect(page.locator("#unlock-panel")).toBeVisible();

  for (let attempt = 0; attempt < 3; attempt += 1) {
    await page.locator("#unlock-passphrase").fill("wrong wrong wrong");
    await page.getByRole("button", { name: "Unlock Vault" }).click();
    await expect(page.locator("#unlock-status")).toContainText("Incorrect passphrase");
  }

  // Backoff is active: countdown visible, button disabled, guard persisted.
  await expect(page.locator("#unlock-status")).toContainText("unlock available in");
  await expect(page.locator("#unlock-btn")).toBeDisabled();
  const guard = await page.evaluate(() => ({
    ...JSON.parse(localStorage.getItem("personal_otp_vault_unlock_guard_v1")),
    now: Date.now(),
  }));
  expect(guard.attempts).toBe(3);
  expect(guard.lockedUntil).toBeGreaterThan(guard.now);

  // Advancing past the backoff re-enables unlock and the passphrase works.
  await page.evaluate(() => window.__advanceClockMs(2000));
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
});

test("a successful unlock clears the throttle guard", async ({ page }) => {
  await loadAppWithClock(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: "JBSWY3DPEHPK3PXP" });
  await enableEncryptedPersistence(page);

  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await page.locator("#unlock-passphrase").fill("wrong wrong wrong");
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await page.locator("#unlock-passphrase").fill("wrong wrong wrong");
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");

  // Guard reset: two fresh failures must NOT trigger backoff (a retained
  // guard would continue at attempts 4-5 and show a lock countdown).
  await page.getByRole("button", { name: "Lock Vault", exact: true }).click();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page.locator("#unlock-passphrase").fill("wrong wrong wrong");
    await page.getByRole("button", { name: "Unlock Vault" }).click();
    await expect(page.locator("#unlock-status")).toContainText("Incorrect passphrase");
    await expect(page.locator("#unlock-status")).not.toContainText("Locked for");
  }
  await page.locator("#unlock-passphrase").fill(PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
});

test("QR image URL import keeps working under the CSP connect-src policy", async ({ page }) => {
  await loadAppWithClock(page);

  const pngBuffer = await QRCode.toBuffer(OTP_URI, { type: "png" });
  await page.route("**/fixture-qr.png", (route) => route.fulfill({
    status: 200,
    contentType: "image/png",
    body: pngBuffer,
  }));

  await page.locator("#qr-url").fill("http://127.0.0.1:4173/fixture-qr.png");
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.locator("#import-dialog")).toBeVisible({ timeout: 10_000 });
  await expect(page.locator("#import-preview-title")).toContainText("Review 1 candidate");
  await page.locator("#confirm-import").click();
  await expect(page.locator(".entry-label")).toHaveText("E2E");
});
