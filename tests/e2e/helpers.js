// Shared bottom-sheet helpers for the web app e2e specs. The add and settings
// panels are exclusive sheets, so opening one means closing the other first.

export async function openAddSheet(page, tab = "manual") {
  if (await page.locator("#settings-dialog").isVisible()) {
    await page.keyboard.press("Escape");
  }
  if (!(await page.locator("#add-dialog").isVisible())) {
    await page.locator("#open-add-dialog").click();
  }
  await page.locator(`label[for="tab-${tab}"]`).click();
}

export async function openSettingsSheet(page) {
  if (await page.locator("#add-dialog").isVisible()) {
    await page.keyboard.press("Escape");
  }
  if (!(await page.locator("#settings-dialog").isVisible())) {
    await page.locator("#open-settings-dialog").click();
  }
}
