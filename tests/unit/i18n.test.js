import { beforeEach, describe, expect, it } from "vitest";

import { getLocale, registerStrings, setLocale, t } from "../../lib/i18n.js";

describe("i18n", () => {
  beforeEach(() => {
    setLocale("en");
  });

  it("defaults the active locale to en without auto detection", () => {
    expect(getLocale()).toBe("en");
  });

  it("resolves seeded unlock and settings keys from the en catalog", () => {
    expect(t("unlock.title")).toBe("Vault locked on this device");
    expect(t("unlock.helper")).toBe("Unlock with your passphrase to read encrypted entries stored locally.");
    expect(t("unlock.passphrasePlaceholder")).toBe("Enter vault passphrase");
    expect(t("unlock.statusFailed")).toBe("Incorrect passphrase or unreadable encrypted vault");
    expect(t("settings.heading")).toBe("Device & Backup Controls");
    expect(t("settings.persistToggle")).toBe("Remember entries on this device");
    expect(t("settings.screenshotSafeToggle")).toBe("Screenshot-safe mode hides codes until revealed");
    expect(t("settings.exportBackup")).toBe("Export Backup");
  });

  it("interpolates named params into placeholders", () => {
    expect(t("settings.autoLock", { minutes: 15 })).toBe("Lock vault automatically after 15 minutes");
    expect(t("settings.autoLock", { minutes: "30", unused: true })).toBe("Lock vault automatically after 30 minutes");
  });

  it("leaves placeholders literal when a param is missing", () => {
    expect(t("settings.autoLock")).toBe("Lock vault automatically after {minutes} minutes");
    expect(t("settings.autoLock", { other: 1 })).toBe("Lock vault automatically after {minutes} minutes");
  });

  it("falls back to the key name for unknown keys", () => {
    expect(t("settings.doesNotExist")).toBe("settings.doesNotExist");
    expect(t("totally.unknown")).toBe("totally.unknown");
  });

  it("registers a second locale and t() follows the active locale", () => {
    registerStrings("de", {
      "unlock.title": "Tresor auf diesem Gerät gesperrt",
      "settings.autoLock": "Sperre den Tresor nach {minutes} Minuten",
    });

    setLocale("de");
    expect(getLocale()).toBe("de");
    expect(t("unlock.title")).toBe("Tresor auf diesem Gerät gesperrt");
    expect(t("settings.autoLock", { minutes: 5 })).toBe("Sperre den Tresor nach 5 Minuten");
    // Keys missing from a partial catalog fall back to the en strings
    expect(t("unlock.button")).toBe("Unlock Vault");

    setLocale("en");
    expect(t("unlock.title")).toBe("Vault locked on this device");
  });

  it("shallow-merges repeated registerStrings calls for the same locale", () => {
    registerStrings("de", { "settings.save": "Speichern" });
    registerStrings("de", { "unlock.button": "Entsperren" });

    setLocale("de");
    expect(t("settings.save")).toBe("Speichern");
    expect(t("unlock.button")).toBe("Entsperren");
  });

  it("rejects locales that have not been registered", () => {
    expect(() => setLocale("zz")).toThrow("Unknown locale: zz");
    expect(getLocale()).toBe("en");
  });

  it("rejects invalid registerStrings input", () => {
    expect(() => registerStrings("", { "a.b": "c" })).toThrow("Locale name is required");
    expect(() => registerStrings("  ", { "a.b": "c" })).toThrow("Locale name is required");
    expect(() => registerStrings("de", null)).toThrow("Strings must be a plain object");
    expect(() => registerStrings("de", ["a.b"])).toThrow("Strings must be a plain object");
  });

  it("keeps reserved toast and import keys resolvable without migrating them", () => {
    expect(t("toast.vaultTitle")).toBe("Vault");
    expect(t("toast.copyFailed")).toBe("Could not copy OTP to clipboard");
    expect(t("import.entryAdded")).toBe("Entry added");
    expect(t("import.invalidUri")).toBe("Invalid URI");
  });
});
