import { expect, test } from "@playwright/test";

const FIXED_NOW = 1_700_000_000_000;
const PRIMARY_SECRET = "JBSWY3DPEHPK3PXP";

// --- migration fixture encoders (mirrors tests/unit/migration.test.js) ---

function encodeVarint(value) {
  let current = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current > 0n) byte |= 0x80;
    bytes.push(byte);
  } while (current > 0n);
  return bytes;
}

function encodeTag(fieldNumber, wireType) {
  return encodeVarint((fieldNumber << 3) | wireType);
}

function encodeLenField(fieldNumber, payload) {
  return [...encodeTag(fieldNumber, 2), ...encodeVarint(payload.length), ...payload];
}

function encodeVarintField(fieldNumber, value) {
  return [...encodeTag(fieldNumber, 0), ...encodeVarint(value)];
}

function utf8Bytes(value) {
  return Array.from(new TextEncoder().encode(value));
}

function encodeOtpParameters(options) {
  const out = [];
  if (options.secret !== undefined) out.push(...encodeLenField(1, options.secret));
  if (options.name !== undefined) out.push(...encodeLenField(2, utf8Bytes(options.name)));
  if (options.issuer !== undefined) out.push(...encodeLenField(3, utf8Bytes(options.issuer)));
  if (options.algorithm !== undefined) out.push(...encodeVarintField(4, options.algorithm));
  if (options.digits !== undefined) out.push(...encodeVarintField(5, options.digits));
  if (options.type !== undefined) out.push(...encodeVarintField(6, options.type));
  if (options.counter !== undefined) out.push(...encodeVarintField(7, options.counter));
  return out;
}

function encodeMigrationPayload(options) {
  const out = [];
  for (const entry of options.entries || []) out.push(...encodeLenField(1, entry));
  if (options.version !== undefined) out.push(...encodeVarintField(2, options.version));
  if (options.batchSize !== undefined) out.push(...encodeVarintField(3, options.batchSize));
  if (options.batchIndex !== undefined) out.push(...encodeVarintField(4, options.batchIndex));
  if (options.batchId !== undefined) out.push(...encodeVarintField(5, options.batchId));
  return new Uint8Array(out);
}

function toMigrationUri(payloadBytes) {
  const base64 = Buffer.from(payloadBytes).toString("base64");
  return `otpauth-migration://offline?data=${encodeURIComponent(base64)}`;
}

function twoEntryFixtureUri() {
  const payload = encodeMigrationPayload({
    version: 1,
    batchSize: 1,
    batchIndex: 0,
    batchId: 7,
    entries: [
      // QR enum: type 2 = TOTP; algorithm 1 = SHA1
      encodeOtpParameters({
        secret: Buffer.from("jbswy3dpehpk3pxp", "ascii"),
        name: "Totped:one@example.com",
        issuer: "Totped",
        algorithm: 1,
        digits: 1,
        type: 2,
      }),
      // type 1 = HOTP, algorithm 2 = SHA256, counter = 5
      encodeOtpParameters({
        secret: Buffer.from("nb2w45dfoiza", "ascii"),
        name: "Hotped:two@example.com",
        issuer: "",
        algorithm: 2,
        digits: 2,
        type: 1,
        counter: 5,
      }),
    ],
  });
  return toMigrationUri(payload);
}

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

test("imports a Google Authenticator migration export through the preview", async ({ page }) => {
  await loadApp(page);

  await page.locator("#uri").fill(twoEntryFixtureUri());
  await page.getByRole("button", { name: "Import Google Authenticator" }).click();

  await expect(page.locator("#import-dialog")).toBeVisible();
  await expect(page.locator("#import-preview-title")).toContainText("Review 2 candidates");

  // HOTP row surfaces its type and counter in the summary.
  await expect(page.locator("#import-preview-list")).toContainText("HOTP #5");
  await expect(page.locator("#import-preview-list")).toContainText("SHA-256");

  await page.locator("#confirm-import").click();
  await expect(page.locator("#import-status")).toContainText("Google Authenticator: imported 2");
  await expect(page.locator(".entry")).toHaveCount(2);

  // Labels: issuer from the issuer field, and issuer-in-name split for the
  // HOTP entry that left issuer empty.
  await expect(page.locator(".entry-label")).toHaveText(["Hotped", "Totped"]);

  // The HOTP card shows its counter badge and does not roll like a timer.
  await expect(page.locator(".entry-counter").first()).toContainText("#5");
});
