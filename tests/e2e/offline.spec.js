import { expect, test } from "@playwright/test";

test.use({ serviceWorkers: "allow" });

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";

async function loadWithStableClock(page) {
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
}

test("app shell and persisted entries remain usable offline after the first online load", async ({ context, page }) => {
  await loadWithStableClock(page);
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();

  await page.locator("#secret").fill(PRIMARY_SECRET);
  await page.locator("#label").fill("Offline:user@example.com");
  await page.getByRole("button", { name: "Save Entry" }).click();
  await page.locator("#persist-toggle").check();
  await page.locator("#save-settings").click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Device storage updated");

  await page.evaluate(async () => {
    const registration = await navigator.serviceWorker.ready;
    await registration.update();
  });

  await context.setOffline(true);

  const offlinePage = await context.newPage();
  await loadWithStableClock(offlinePage);
  await offlinePage.goto("http://127.0.0.1:4173/", { waitUntil: "domcontentloaded" });

  await expect(offlinePage.locator("#offline-chip")).toContainText("Offline Ready");
  await expect(offlinePage.locator(".entry")).toHaveCount(1);
  await expect(offlinePage.locator(".entry-label")).toHaveText("Offline");
  await expect(offlinePage.locator(".entry-code")).toHaveText(/\d{3} \d{3}/);
});
