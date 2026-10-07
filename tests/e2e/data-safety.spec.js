import { readFile } from "node:fs/promises";

import { expect, test } from "@playwright/test";

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";
const DAY_MS = 24 * 60 * 60 * 1000;

async function loadApp(page) {
  await page.addInitScript(({ fixedNow }) => {
    const RealDate = Date;
    class MockDate extends RealDate {
      constructor(...args) { super(...(args.length === 0 ? [fixedNow] : args)); }
      static now() { return fixedNow; }
    }
    Object.setPrototypeOf(MockDate, RealDate);
    window.Date = MockDate;
  }, { fixedNow: FIXED_NOW });

  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("#secret")).toBeVisible();
}

async function addEntry(page, { label, secret }, second = null) {
  await page.locator("#secret").fill(secret);
  await page.locator("#label").fill(label);
  await page.getByRole("button", { name: "Save Entry" }).click();
  if (second) await addEntry(page, second);
}

test("undo restores a deleted entry at its original index", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });
  await addEntry(page, { label: "Beta:user@example.com", secret: "NB2W45DFOIZA" });
  await addEntry(page, { label: "Gamma:user@example.com", secret: "MZXW6YTBOI" });
  await expect(page.locator(".entry")).toHaveCount(3);

  await page.locator(".entry").nth(1).getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();

  const undoToast = page.locator(".toast.undo");
  await expect(undoToast).toBeVisible();
  await undoToast.getByRole("button", { name: "Undo" }).click();

  await expect(page.locator(".entry")).toHaveCount(3);
  await expect(page.locator(".entry-label")).toHaveText(["Alpha", "Beta", "Gamma"]);
});

test("undo expires after 10 seconds and purges the tombstone", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Alpha:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator(".entry").first().getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".toast.undo")).toBeVisible();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.waitForTimeout(10500);
  await expect(page.locator(".toast.undo")).toHaveCount(0);
  await expect(page.locator(".entry")).toHaveCount(0);
  await expect(page.locator(".entry-label")).toHaveCount(0);
  const tombstone = await page.evaluate(() => localStorage.getItem("personal_otp_vault_undo_tombstone_v1"));
  expect(tombstone).toBeNull();
});

test("undo survives a page reload via the tombstone", async ({ page }) => {
  await loadApp(page);
  await page.locator("#persist-toggle").check();
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Device storage updated");

  await addEntry(page, { label: "Persisted:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator(".entry")).toHaveCount(1);

  await page.locator(".entry").first().getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator(".entry")).toHaveCount(0);

  await page.reload();
  await expect(page.locator("#secret")).toBeVisible();
  const undoToast = page.locator(".toast.undo");
  await expect(undoToast).toBeVisible();
  await undoToast.getByRole("button", { name: "Undo" }).click();
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator(".entry-label")).toHaveText("Persisted");
});

test("backup reminder appears after 30 days and clears on export", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, { label: "Reminder:user@example.com", secret: PRIMARY_SECRET });
  await expect(page.locator("#backup-reminder-banner")).toBeVisible();

  // Stale lastBackupAt (31 days ago) still warns; fresh stamp clears it.
  // Persist the vault first so entries survive the reload (an empty vault
  // legitimately has nothing at risk).
  await page.locator("#persist-toggle").check();
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Device storage updated");

  await page.evaluate((stamp) => {
    const settings = JSON.parse(localStorage.getItem("personal_otp_vault_settings_v3") || "{}");
    settings.lastBackupAt = stamp;
    localStorage.setItem("personal_otp_vault_settings_v3", JSON.stringify(settings));
  }, FIXED_NOW - 31 * DAY_MS);
  await page.reload();
  await expect(page.locator(".entry")).toHaveCount(1);
  await expect(page.locator("#backup-reminder-banner")).toBeVisible();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export Backup" }).click();
  const download = await downloadPromise;
  const backup = JSON.parse(await readFile(await download.path(), "utf8"));
  expect(backup.version).toBe(2);

  await expect(page.locator("#last-export-line")).toContainText("Last export: today");
  await expect(page.locator("#backup-reminder-banner")).toBeHidden();
});

test("time drift warns past 5 seconds and stays silent within", async ({ page }) => {
  await loadApp(page);
  await page.locator("#time-drift-toggle").check();
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();

  // Same-origin HEAD with a +6s clock: banner.
  await page.route("**/*", async (route) => {
    const request = route.request();
    if (request.method() !== "HEAD") return route.fallback();
    await route.fulfill({
      status: 200,
      headers: { date: new Date(FIXED_NOW + 6000).toUTCString() },
      body: "",
    });
  });
  await page.getByRole("button", { name: "Check clock now" }).click();
  await expect(page.locator("#drift-banner")).toBeVisible();
  await expect(page.locator("#drift-skew")).toHaveText(/6\.0s/);

  // +3s: no banner.
  await page.unroute("**/*");
  await page.route("**/*", async (route) => {
    const request = route.request();
    if (request.method() !== "HEAD") return route.fallback();
    await route.fulfill({
      status: 200,
      headers: { date: new Date(FIXED_NOW + 3000).toUTCString() },
      body: "",
    });
  });
  await page.locator("#drift-dismiss").click();
  await page.getByRole("button", { name: "Check clock now" }).click();
  await expect(page.locator("#drift-banner")).toBeHidden();
});
