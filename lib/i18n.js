import { OtpVaultError } from "./otp.js";

// i18n framework (phase 7 FR7): plain-object catalogs with {name}
// interpolation. No locale detection this release — both apps start on the
// seeded English catalog and later translations land via registerStrings().

const DEFAULT_LOCALE = "en";
const PLACEHOLDER_PATTERN = /\{([a-zA-Z0-9_]+)\}/g;

const en = {
  // Unlock panel — web app (index.html #unlock-panel)
  "unlock.eyebrow": "vault state",
  "unlock.title": "Vault locked on this device",
  "unlock.helper": "Unlock with your passphrase to read encrypted entries stored locally.",
  "unlock.passphrasePlaceholder": "Enter vault passphrase",
  "unlock.button": "Unlock Vault",
  "unlock.statusSuccess": "Vault unlocked",
  "unlock.statusFailed": "Incorrect passphrase or unreadable encrypted vault",

  // Unlock panel — extension popup (popup.html #unlock-panel)
  "unlock.extensionTitle": "Extension Vault",
  "unlock.extensionPassphrasePlaceholder": "Passphrase to unlock encrypted storage",
  "unlock.extensionButton": "Unlock",

  // Settings panel — web app (index.html settings-panel)
  "settings.eyebrow": "privacy",
  "settings.heading": "Device & Backup Controls",
  "settings.persistToggle": "Remember entries on this device",
  "settings.encryptToggle": "Encrypt stored entries with a passphrase",
  "settings.unlockOnLoadToggle": "Require unlock when opening this app",
  "settings.blurCodesToggle": "Blur OTP codes until hovered or focused",
  "settings.screenshotSafeToggle": "Screenshot-safe mode hides codes until revealed",
  "settings.clearClipboardToggle": "Clear clipboard 30 seconds after copy",
  "settings.passphraseLabel": "Vault passphrase",
  "settings.passphrasePlaceholder": "Use a strong passphrase",
  "settings.passphraseConfirmLabel": "Confirm passphrase",
  "settings.passphraseConfirmPlaceholder": "Repeat passphrase",
  "settings.passphraseGuidance": "This vault is already encrypted. Use Change Passphrase to rotate your vault secret.",
  "settings.exportBackup": "Export Backup",
  "settings.importBackup": "Import Backup",
  "settings.changePassphrase": "Change Passphrase",
  "settings.save": "Save Privacy Settings",
  // Seeded ahead of the planned auto-lock setting
  "settings.autoLock": "Lock vault automatically after {minutes} minutes",
  "settings.autoLockOff": "Auto-lock is off",
  "settings.statusEncryptedVaultSaved": "Encrypted vault saved. Use Change Passphrase to rotate your vault secret.",
  "settings.statusEncryptedSaved": "Encrypted vault saved",
  "settings.statusDeviceStorageUpdated": "Device storage updated",
  "settings.statusSessionOnly": "Entries are now session-only",
  "settings.statusImportFailed": "Could not import backup",
  "settings.statusPassphraseUpdated": "Vault passphrase updated",
  "settings.statusLockRequiresEncryption": "Enable encrypted storage to use lock/unlock",
  "settings.statusSaveFailed": "Could not save settings",
  "settings.statusInstallUnavailable": "Install prompt is not available yet on this browser",

  // Settings panel — extension popup (popup.html settings-panel)
  "settings.extensionHeading": "Security",
  "settings.extensionEncryptToggle": "Encrypt entries in extension storage",
  "settings.extensionPassphrasePlaceholder": "New passphrase",
  "settings.extensionPassphraseConfirmPlaceholder": "Confirm passphrase",
  "settings.extensionPassphraseGuidance": "This vault is already encrypted. Use Change Passphrase to rotate your extension secret.",
  "settings.extensionSave": "Save Security Settings",

  // Change passphrase flow — shared by both platforms
  "settings.changePassphraseTitle": "Change passphrase",
  "settings.currentPassphraseLabel": "Current passphrase",
  "settings.currentPassphrasePlaceholder": "Enter current passphrase",
  "settings.newPassphraseLabel": "New passphrase",
  "settings.newPassphrasePlaceholder": "Use a new strong passphrase",
  "settings.confirmNewPassphraseLabel": "Confirm new passphrase",
  "settings.confirmNewPassphrasePlaceholder": "Repeat new passphrase",
  "settings.updatePassphrase": "Update Passphrase",
};

// Reserved keys (phase 7 locked scope): toast and import strings stay
// hardcoded in app.js / popup.js this release. They are seeded with the
// current English strings so a later migration only swaps call sites.
const reserved = {
  "toast.vaultTitle": "Vault",
  "toast.importTitle": "Import",
  "toast.settingsTitle": "Settings",
  "toast.copyFailed": "Could not copy OTP to clipboard",
  "import.entryAdded": "Entry added",
  "import.invalidUri": "Invalid URI",
  "import.qrUrlRequired": "Please enter a QR image URL",
  "import.readingQrFile": "Reading QR file...",
  "import.fetchingQrUrl": "Fetching QR image URL...",
};

const catalogs = new Map([[DEFAULT_LOCALE, { ...en, ...reserved }]]);

let activeLocale = DEFAULT_LOCALE;

export function registerStrings(locale, dict) {
  const localeName = typeof locale === "string" ? locale.trim() : "";
  if (!localeName) {
    throw new OtpVaultError("Locale name is required", { code: "LOCALE_INVALID" });
  }
  if (!dict || typeof dict !== "object" || Array.isArray(dict)) {
    throw new OtpVaultError("Strings must be a plain object keyed by translation keys", {
      code: "STRINGS_INVALID",
    });
  }
  const existing = catalogs.get(localeName) || {};
  const merged = { ...existing, ...dict };
  catalogs.set(localeName, merged);
  return merged;
}

export function getLocale() {
  return activeLocale;
}

export function setLocale(locale) {
  const localeName = typeof locale === "string" ? locale.trim() : "";
  if (!localeName || !catalogs.has(localeName)) {
    throw new OtpVaultError(`Unknown locale: ${localeName || String(locale)}`, { code: "LOCALE_UNKNOWN" });
  }
  activeLocale = localeName;
  return activeLocale;
}

export function t(key, params) {
  return interpolate(resolveTemplate(key), params);
}

// Missing keys resolve visibly to the key name itself (phase plan decision);
// keys missing from a partial locale catalog fall back to English first.
function resolveTemplate(key) {
  if (typeof key !== "string" || !key) return key;
  const value = catalogs.get(activeLocale)?.[key] ?? catalogs.get(DEFAULT_LOCALE)?.[key];
  return typeof value === "string" ? value : key;
}

// Only placeholders with a provided param are replaced; missing params keep
// the literal "{name}" text so gaps stay visible in the UI.
function interpolate(template, params) {
  if (typeof template !== "string") return template;
  if (!params || typeof params !== "object") return template;
  return template.replace(PLACEHOLDER_PATTERN, (match, name) => (
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match
  ));
}
