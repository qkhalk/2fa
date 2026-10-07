import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";

async function loadApp(page) {
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
}

async function addEntry(page, label, secret) {
  await page.locator("#secret").fill(secret);
  await page.locator("#label").fill(label);
  await page.getByRole("button", { name: "Save Entry" }).click();
  await expect(page.locator("#import-status")).toContainText("Entry added");
}

test("theme select applies data-theme without reload and persists", async ({ page }) => {
  await loadApp(page);

  await page.locator("#theme-select").selectOption("light");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  // A fresh vault is session-only; the important part is that the theme
  // applied without a reload.
  await expect(page.locator("#settings-status")).toContainText("session-only");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");

  await page.locator("#theme-select").selectOption("dark");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  // System removes the attribute so prefers-color-scheme decides.
  await page.locator("#theme-select").selectOption("system");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);

  // Choice survives a reload.
  await page.locator("#theme-select").selectOption("light");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.locator("#theme-select")).toHaveValue("light");
});

test("system theme follows prefers-color-scheme emulation", async ({ page }) => {
  await loadApp(page);
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);

  await page.emulateMedia({ colorScheme: "light" });
  const bg = await page.evaluate(() => getComputedStyle(document.body).color);
  expect(bg).toBeTruthy();
  await page.emulateMedia({ colorScheme: "dark" });
});

test("drag and drop reorders entries and the order persists", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, "Alpha:user@example.com", PRIMARY_SECRET);
  await addEntry(page, "Beta:user@example.com", "NB2W45DFOIZA====");
  await addEntry(page, "Gamma:user@example.com", "MFRGGZDFMZTWQ2LK");

  // Persist the vault so the order survives the reload below.
  await page.locator("#persist-toggle").check();
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await expect(page.locator("#privacy-dialog")).toBeVisible();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Device storage updated");

  // A tall viewport keeps every card visible: manual mouse drags use
  // viewport coordinates, and clamped off-screen pointers land on nothing.
  await page.setViewportSize({ width: 1440, height: 1600 });
  await page.locator("#sort-select").selectOption("custom");
  await expect(page.locator(".entry-label")).toHaveText(["Alpha", "Beta", "Gamma"]);
  await expect(page.locator(".drag-handle").first()).toBeVisible();

  // Drag Beta's handle down past Gamma's midpoint (75% down the card) so the
  // pointer crosses it and Beta lands after Gamma.
  const secondHandle = page.locator(".drag-handle").nth(1);
  const thirdCard = page.locator(".entry").nth(2);
  const sourceBox = await secondHandle.boundingBox();
  const targetBox = await thirdCard.boundingBox();

  await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2);
  await page.mouse.down();
  await page.mouse.move(sourceBox.x + sourceBox.width / 2, targetBox.y + targetBox.height * 0.75, { steps: 8 });
  await page.mouse.up();

  await expect(page.locator("#import-status")).toContainText("Manual order updated");
  await expect(page.locator(".entry-label")).toHaveText(["Alpha", "Gamma", "Beta"]);

  await page.reload();
  await page.locator("#sort-select").selectOption("custom");
  await expect(page.locator(".entry-label")).toHaveText(["Alpha", "Gamma", "Beta"]);
});

test("move buttons remain the keyboard-accessible reorder fallback", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, "Alpha:user@example.com", PRIMARY_SECRET);
  await addEntry(page, "Beta:user@example.com", "NB2W45DFOIZA====");

  await page.locator("#sort-select").selectOption("custom");
  await page.locator(".entry").nth(1).getByRole("button", { name: "Up" }).click();

  await expect(page.locator(".entry-label")).toHaveText(["Beta", "Alpha"]);
});

test("per-entry countdown ring tracks the remaining period", async ({ page }) => {
  await loadApp(page);
  await addEntry(page, "Ring:user@example.com", PRIMARY_SECRET);

  const ring = page.locator(".entry .ring-progress").first();
  await expect(ring).toBeVisible();
  const first = await ring.evaluate((node) => Number(node.style.strokeDashoffset));

  await page.waitForTimeout(1100);
  const second = await ring.evaluate((node) => Number(node.style.strokeDashoffset));

  expect(Number.isFinite(first)).toBe(true);
  expect(second).not.toBe(first);
});

test("copying an entry announces and records the code", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await loadApp(page);
  await addEntry(page, "Copy:user@example.com", PRIMARY_SECRET);

  await page.locator(".entry").first().getByRole("button", { name: "Copy" }).click();
  await expect(page.locator(".entry").first().getByRole("button", { name: "Copied" })).toBeVisible();
  await expect(page.locator("#copy-history")).toContainText("Copy");
});

test("axe reports no critical violations on locked, unlocked, and settings views", async ({ page }) => {
  // Locked view: seed an encrypted vault by UI, then reload into locked state.
  await loadApp(page);
  await addEntry(page, "A11y:user@example.com", PRIMARY_SECRET);
  await page.locator("#persist-toggle").check();
  await page.locator("#encrypt-toggle").check();
  await page.locator("#vault-passphrase").fill("correct horse battery");
  await page.locator("#vault-passphrase-confirm").fill("correct horse battery");
  await page.getByRole("button", { name: "Save Privacy Settings" }).click();
  await page.getByRole("button", { name: "I Understand" }).click();
  await expect(page.locator("#settings-status")).toContainText("Encrypted vault saved");

  await page.reload();
  await expect(page.locator("#unlock-panel")).toBeVisible();
  const locked = await new AxeBuilder({ page }).analyze();
  expect(locked.violations.filter((v) => v.impact === "critical")).toEqual([]);

  await page.locator("#unlock-passphrase").fill("correct horse battery");
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.locator("#unlock-status")).toHaveText("Vault unlocked");
  const unlocked = await new AxeBuilder({ page }).analyze();
  expect(unlocked.violations.filter((v) => v.impact === "critical")).toEqual([]);
});
