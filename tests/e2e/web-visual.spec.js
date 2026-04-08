import { expect, test } from "@playwright/test";

test.skip(process.platform !== "win32", "Visual snapshots are currently pinned for local Windows rendering.");

const FIXED_NOW = 1_700_000_000_000;

async function loadStableHome(page, viewport) {
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
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
}

test("web home empty state desktop visual regression", async ({ page }) => {
  await loadStableHome(page, { width: 1440, height: 1000 });
  await expect(page).toHaveScreenshot("web-home-empty-desktop.png", {
    fullPage: true,
    animations: "disabled",
    maxDiffPixelRatio: 0.02,
  });
});

test("web home empty state mobile visual regression", async ({ page }) => {
  await loadStableHome(page, { width: 390, height: 844 });
  await expect(page).toHaveScreenshot("web-home-empty-mobile.png", {
    fullPage: true,
    animations: "disabled",
    maxDiffPixelRatio: 0.02,
  });
});

test("web home locked state desktop visual regression", async ({ page }) => {
  const passphrase = "correct horse battery";

  await loadStableHome(page, { width: 1440, height: 1000 });
  await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
  await page.locator("#label").fill("Locked:user@example.com");
  await page.getByRole("button", { name: "Save Entry" }).click();

  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill(passphrase);
  await page.locator("#vault-passphrase-confirm").fill(passphrase);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();

  await expect(page).toHaveScreenshot("web-home-locked-desktop.png", {
    fullPage: true,
    animations: "disabled",
    maxDiffPixelRatio: 0.02,
  });
});

test("web home populated state desktop visual regression", async ({ page }) => {
  await loadStableHome(page, { width: 1440, height: 1000 });
  await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
  await page.locator("#label").fill("Alpha:user@example.com");
  await page.getByRole("button", { name: "Save Entry" }).click();

  await page.locator("#secret").fill("NB2W45DFOIZA====");
  await page.locator("#label").fill("Beta:user@example.com");
  await page.getByRole("button", { name: "Save Entry" }).click();

  await expect(page).toHaveScreenshot("web-home-populated-desktop.png", {
    fullPage: true,
    animations: "disabled",
    maxDiffPixelRatio: 0.02,
  });
});

test("web home search no-results desktop visual regression", async ({ page }) => {
  await loadStableHome(page, { width: 1440, height: 1000 });
  await page.locator("#secret").fill("JBSWY3DPEHPK3PXP");
  await page.locator("#label").fill("Alpha:user@example.com");
  await page.getByRole("button", { name: "Save Entry" }).click();

  await page.locator("#search").fill("missing-entry-term");

  await expect(page).toHaveScreenshot("web-home-search-no-results-desktop.png", {
    fullPage: true,
    animations: "disabled",
    maxDiffPixelRatio: 0.02,
  });
});
