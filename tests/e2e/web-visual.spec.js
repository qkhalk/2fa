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
