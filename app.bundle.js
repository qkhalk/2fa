// app.js
var BASE32_REGEX = /^[A-Z2-7]+$/;
var OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
var MIN_PERIOD = 15;
var MAX_PERIOD = 120;
var OtpVaultError = class extends Error {
  constructor(message, { code = "OTP_VAULT_ERROR", cause } = {}) {
    super(message, cause ? { cause } : void 0);
    this.name = "OtpVaultError";
    this.code = code;
  }
};
function reportError(context, error) {
  console.error(`[OTP Vault] ${context}`, error);
}
function toUserMessage(error, fallback = "Something went wrong") {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}
function sanitizeBase32(value) {
  return (value || "").toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}
function normalizeTags(value) {
  const raw = Array.isArray(value) ? value : String(value || "").split(",");
  return [...new Set(
    raw.map((tag) => String(tag).trim().replace(/\s+/g, " ")).filter(Boolean).map((tag) => tag.slice(0, 24))
  )];
}
function generateEntryId() {
  return `entry_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
function ensureBase32Secret(secret) {
  const clean = sanitizeBase32(secret);
  if (!clean) {
    throw new OtpVaultError("Secret is required", { code: "SECRET_REQUIRED" });
  }
  if (!BASE32_REGEX.test(clean)) {
    throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
  }
  if (base32ToBytes(clean).length === 0) {
    throw new OtpVaultError("Secret is too short to decode", { code: "SECRET_TOO_SHORT" });
  }
  return clean;
}
function ensureDigits(digits) {
  const value = Number(digits);
  if (value !== 6 && value !== 8) {
    throw new OtpVaultError("Only 6-digit and 8-digit OTP codes are supported", { code: "DIGITS_UNSUPPORTED" });
  }
  return value;
}
function ensurePeriod(period) {
  const value = Number(period);
  if (!Number.isInteger(value) || value < MIN_PERIOD || value > MAX_PERIOD) {
    throw new OtpVaultError(`Period must be an integer between ${MIN_PERIOD} and ${MAX_PERIOD} seconds`, {
      code: "PERIOD_INVALID"
    });
  }
  return value;
}
function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}
function normalizeLabel(label, secret) {
  const clean = (label || "").trim();
  return clean || createFallbackLabel(secret);
}
function normalizeEntry(entry) {
  const secret = ensureBase32Secret(entry.secret || "");
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now()
  };
}
function normalizeEntries(entries2) {
  if (!Array.isArray(entries2)) return [];
  return entries2.flatMap((entry) => {
    try {
      return [normalizeEntry(entry)];
    } catch {
      return [];
    }
  });
}
function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };
  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(":").trim() || "No account label"
    };
  }
  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(" - ").trim() || "No account label"
    };
  }
  return { issuer: clean, account: "No account label" };
}
function getIssuerInitials(label) {
  const issuer = parseLabelParts(label).issuer;
  const parts = issuer.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "OT";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}
function normalizeOtpUriCandidate(value) {
  return safeDecode((value || "").trim()).replace(/[)\],.;]+$/, "");
}
function parseOtpAuthUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch (error) {
    throw new OtpVaultError("OTP URI is not a valid URL", { code: "URI_INVALID", cause: error });
  }
  if (parsed.protocol !== "otpauth:") {
    throw new OtpVaultError("URI must start with otpauth://", { code: "URI_PROTOCOL" });
  }
  if (parsed.hostname.toLowerCase() !== "totp") {
    throw new OtpVaultError("Only TOTP URIs are supported", { code: "URI_TYPE" });
  }
  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (algorithm !== "SHA1") {
    throw new OtpVaultError("Only SHA1 TOTP URIs are supported", { code: "URI_ALGORITHM" });
  }
  const issuerParam = safeDecode(parsed.searchParams.get("issuer") || "").trim();
  const rawLabel = safeDecode(parsed.pathname.replace(/^\/+/, "")).trim();
  const labelParts = parseLabelParts(rawLabel);
  if (issuerParam && rawLabel && labelParts.issuer !== "Unknown" && labelParts.account !== "No account label") {
    if (labelParts.issuer.toLowerCase() !== issuerParam.toLowerCase()) {
      throw new OtpVaultError("OTP URI issuer does not match the label", { code: "URI_ISSUER_MISMATCH" });
    }
  }
  const label = rawLabel ? rawLabel.includes(":") || !issuerParam ? rawLabel : `${issuerParam}:${rawLabel}` : issuerParam ? `${issuerParam}:Imported Account` : "Imported Account";
  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30
  });
}
function extractOtpAuthUri(rawText) {
  return extractOtpAuthUris(rawText)[0] || "";
}
function extractOtpAuthUris(rawText) {
  const candidates = /* @__PURE__ */ new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  candidates.add(normalizeOtpUriCandidate(raw));
  for (const match of raw.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const decoded = safeDecode(raw);
  candidates.add(normalizeOtpUriCandidate(decoded));
  for (const match of decoded.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const valid = [];
  for (const candidate of candidates) {
    if (!candidate.startsWith("otpauth://")) continue;
    try {
      parseOtpAuthUri(candidate);
      valid.push(candidate);
    } catch {
      continue;
    }
  }
  return valid;
}
function hasDuplicateEntry(entries2, candidate) {
  return entries2.some((entry) => entry.secret === candidate.secret && entry.digits === candidate.digits && entry.period === candidate.period);
}
function entryMatchesQuery(entry, query) {
  const text = query.trim().toLowerCase();
  if (!text) return true;
  return [entry.label, ...entry.tags || []].join(" ").toLowerCase().includes(text);
}
function getEntryGroup(entry, groupBy) {
  if (groupBy === "issuer") return parseLabelParts(entry.label).issuer;
  if (groupBy === "tag") return entry.tags?.[0] || "Untagged";
  return "All Entries";
}
function compareEntries(a, b, sortBy = "pinned-alpha") {
  if (sortBy === "recent") return b.createdAt - a.createdAt;
  if (sortBy === "period") return a.period - b.period || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
  return a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
}
function base32ToBytes(base32) {
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();
  let bits = "";
  for (const char of clean) {
    const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    if (idx === -1) {
      throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}
function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}
async function hmacSha1(keyBytes, messageBytes, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}
async function generateTotp(secret, digits, period, now, cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmacSha1(base32ToBytes(normalizedSecret), toCounterBytes(counter), cryptoApi);
  const offset = digest[digest.length - 1] & 15;
  const binary = (digest[offset] & 127) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3];
  return (binary % 10 ** normalizedDigits).toString().padStart(normalizedDigits, "0");
}
function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var BACKUP_VERSION = 2;
function toBase64(uint8) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(uint8).toString("base64");
  }
  return btoa(String.fromCharCode(...uint8));
}
function fromBase64(base64) {
  try {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(base64, "base64"));
    }
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  } catch (error) {
    throw new OtpVaultError("Encrypted data is unreadable", { code: "VAULT_BASE64", cause: error });
  }
}
function requireCrypto(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}
async function sha256Hex(value, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const digest = await safeCrypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
}
function normalizePassphrase(passphrase) {
  const clean = (passphrase || "").trim();
  if (clean.length < 8) {
    throw new OtpVaultError("Use a passphrase with at least 8 characters", { code: "PASSPHRASE_TOO_SHORT" });
  }
  return clean;
}
async function deriveVaultKey(passphrase, salt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 15e4, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptEntries(entries2, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(16));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted))
  };
}
function validateEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Encrypted data is missing or invalid", { code: "VAULT_INVALID" });
  }
  if (typeof payload.salt !== "string" || typeof payload.iv !== "string" || typeof payload.data !== "string") {
    throw new OtpVaultError("Encrypted data is missing required fields", { code: "VAULT_FIELDS" });
  }
  return payload;
}
async function decryptVaultEntries(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    const key = await deriveVaultKey(normalizedPassphrase, fromBase64(normalizedPayload.salt), safeCrypto);
    const decrypted = await safeCrypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(normalizedPayload.iv) },
      key,
      fromBase64(normalizedPayload.data)
    );
    const parsed = JSON.parse(decoder.decode(decrypted));
    return normalizeEntries(parsed);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
async function buildBackupEnvelope(payload, encrypted, cryptoApi = globalThis.crypto) {
  return {
    version: BACKUP_VERSION,
    encrypted,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    itemCount: encrypted ? 0 : payload.entries.length,
    checksum: await sha256Hex(JSON.stringify(payload), cryptoApi),
    payload
  };
}
async function createPlainBackup(entries2, cryptoApi = globalThis.crypto) {
  const payload = {
    schemaVersion: 1,
    entries: entries2
  };
  return buildBackupEnvelope(payload, false, cryptoApi);
}
async function createEncryptedBackup(vaultPayload, cryptoApi = globalThis.crypto) {
  validateEncryptedPayload(vaultPayload);
  return buildBackupEnvelope({
    schemaVersion: 1,
    vault: vaultPayload
  }, true, cryptoApi);
}
async function migrateBackup(rawBackup) {
  if (rawBackup.version === 1) {
    if (rawBackup.encrypted === true) {
      validateEncryptedPayload(rawBackup.vault);
      return {
        version: 1,
        encrypted: true,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: 1,
          vault: rawBackup.vault
        }
      };
    }
    if (rawBackup.encrypted === false && Array.isArray(rawBackup.entries)) {
      return {
        version: 1,
        encrypted: false,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: 1,
          entries: normalizeEntries(rawBackup.entries)
        }
      };
    }
  }
  if (rawBackup.version === BACKUP_VERSION) {
    return rawBackup;
  }
  throw new OtpVaultError("Backup version is not supported", { code: "BACKUP_VERSION" });
}
async function parseBackupFile(rawBackup, cryptoApi = globalThis.crypto) {
  if (!rawBackup || typeof rawBackup !== "object") {
    throw new OtpVaultError("Backup file is invalid", { code: "BACKUP_INVALID" });
  }
  const migrated = await migrateBackup(rawBackup);
  const payload = migrated.payload;
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Backup payload is missing", { code: "BACKUP_PAYLOAD" });
  }
  let integrity = "legacy";
  if (migrated.version === BACKUP_VERSION) {
    if (typeof migrated.checksum !== "string") {
      throw new OtpVaultError("Backup checksum is missing", { code: "BACKUP_CHECKSUM_MISSING" });
    }
    const expected = await sha256Hex(JSON.stringify(payload), cryptoApi);
    if (expected !== migrated.checksum) {
      throw new OtpVaultError("Backup integrity check failed", { code: "BACKUP_CHECKSUM_INVALID" });
    }
    integrity = "verified";
  }
  if (migrated.encrypted === true) {
    validateEncryptedPayload(payload.vault);
    return {
      encrypted: true,
      integrity,
      createdAt: migrated.createdAt || null,
      itemCount: migrated.itemCount || 0,
      schemaVersion: payload.schemaVersion || 1,
      vault: payload.vault
    };
  }
  if (!Array.isArray(payload.entries)) {
    throw new OtpVaultError("Backup entries are missing or invalid", { code: "BACKUP_ENTRIES" });
  }
  const entries2 = normalizeEntries(payload.entries);
  return {
    encrypted: false,
    integrity,
    createdAt: migrated.createdAt || null,
    itemCount: entries2.length,
    schemaVersion: payload.schemaVersion || 1,
    entries: entries2
  };
}
var STORAGE_KEY = "personal_otp_vault_entries_v2";
var SETTINGS_KEY = "personal_otp_vault_settings_v3";
var WARNING_KEY = "personal_otp_vault_persist_warning_seen_v1";
var ENCRYPTED_VAULT_KEY = "personal_otp_vault_encrypted_v1";
var form = document.getElementById("otp-form");
var labelInput = document.getElementById("label");
var secretInput = document.getElementById("secret");
var tagsInput = document.getElementById("tags");
var digitsInput = document.getElementById("digits");
var periodInput = document.getElementById("period");
var uriInput = document.getElementById("uri");
var parseUriBtn = document.getElementById("parse-uri");
var importClipboardBtn = document.getElementById("import-clipboard");
var qrFileInput = document.getElementById("qr-file");
var qrUrlInput = document.getElementById("qr-url");
var importQrUrlBtn = document.getElementById("import-qr-url");
var startCameraBtn = document.getElementById("start-camera");
var stopCameraBtn = document.getElementById("stop-camera");
var cameraPreview = document.getElementById("camera-preview");
var clearAllBtn = document.getElementById("clear-all");
var importStatus = document.getElementById("import-status");
var searchInput = document.getElementById("search");
var sortSelect = document.getElementById("sort-select");
var groupSelect = document.getElementById("group-select");
var entriesRoot = document.getElementById("entries");
var template = document.getElementById("entry-template");
var timerValue = document.getElementById("timer-value");
var timerBar = document.getElementById("timer-bar");
var bulkBar = document.getElementById("bulk-bar");
var bulkSummary = document.getElementById("bulk-summary");
var bulkTagInput = document.getElementById("bulk-tag-input");
var bulkTagApplyBtn = document.getElementById("bulk-tag-apply");
var bulkRemoveBtn = document.getElementById("bulk-remove");
var onboardingPanel = document.getElementById("onboarding");
var copyHistoryRoot = document.getElementById("copy-history");
var toastRegion = document.getElementById("toast-region");
var persistToggle = document.getElementById("persist-toggle");
var encryptToggle = document.getElementById("encrypt-toggle");
var unlockOnLoadToggle = document.getElementById("unlock-on-load");
var blurCodesToggle = document.getElementById("blur-codes-toggle");
var screenshotSafeToggle = document.getElementById("screenshot-safe-toggle");
var clearClipboardToggle = document.getElementById("clear-clipboard-toggle");
var encryptionFields = document.getElementById("encryption-fields");
var vaultPassphraseInput = document.getElementById("vault-passphrase");
var vaultPassphraseConfirmInput = document.getElementById("vault-passphrase-confirm");
var saveSettingsBtn = document.getElementById("save-settings");
var settingsStatus = document.getElementById("settings-status");
var exportBackupBtn = document.getElementById("export-backup");
var importBackupInput = document.getElementById("import-backup");
var installAppBtn = document.getElementById("install-app");
var lockAppBtn = document.getElementById("lock-app");
var unlockPanel = document.getElementById("unlock-panel");
var unlockPassphraseInput = document.getElementById("unlock-passphrase");
var unlockBtn = document.getElementById("unlock-btn");
var unlockStatus = document.getElementById("unlock-status");
var privacyDialog = document.getElementById("privacy-dialog");
var importDialog = document.getElementById("import-dialog");
var importPreviewTitle = document.getElementById("import-preview-title");
var importPreviewStatus = document.getElementById("import-preview-status");
var importPreviewTagsInput = document.getElementById("import-preview-tags");
var importPreviewList = document.getElementById("import-preview-list");
var backupReviewDialog = document.getElementById("backup-review-dialog");
var backupReviewSummary = document.getElementById("backup-review-summary");
var backupImportMode = document.getElementById("backup-import-mode");
var backupPassphraseRow = document.getElementById("backup-passphrase-row");
var backupImportPassphraseInput = document.getElementById("backup-import-passphrase");
var backupReviewStatus = document.getElementById("backup-review-status");
var debugToggleBtn = document.getElementById("debug-toggle");
var debugPanel = document.getElementById("debug-panel");
var debugList = document.getElementById("debug-list");
var defaultSettings = {
  persist: false,
  encrypt: false,
  unlockOnLoad: false,
  blurCodes: false,
  screenshotSafe: false,
  clearClipboard: false,
  sortBy: "pinned-alpha",
  groupBy: "none"
};
var settings = loadSettings();
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var currentPassphrase = "";
var cameraStream = null;
var cameraScanTimer = null;
var deferredInstallPrompt = null;
var cameraDetection = { uri: "", hits: 0 };
var selectedEntryIds = /* @__PURE__ */ new Set();
var copyHistory = [];
var debugEvents = [];
var importPreviewState = null;
var backupImportState = null;
initialize();
function initialize() {
  syncSettingsUI();
  applyVisualSettings();
  loadVaultOnStartup();
  renderEntries();
  renderCopyHistory();
  renderDebugFeed();
  renderBulkBar();
  tick();
  bindEvents();
  setInterval(tick, 1e3);
  registerPwaSupport();
  logDebug("info", "Vault initialized");
}
function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...defaultSettings };
    return { ...defaultSettings, ...JSON.parse(raw) };
  } catch (error) {
    reportError("Failed to load settings", error);
    return { ...defaultSettings };
  }
}
function saveSettings() {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}
function syncSettingsUI() {
  persistToggle.checked = settings.persist;
  encryptToggle.checked = settings.encrypt;
  unlockOnLoadToggle.checked = settings.unlockOnLoad;
  blurCodesToggle.checked = settings.blurCodes;
  screenshotSafeToggle.checked = settings.screenshotSafe;
  clearClipboardToggle.checked = settings.clearClipboard;
  sortSelect.value = settings.sortBy;
  groupSelect.value = settings.groupBy;
  encryptionFields.classList.toggle("hidden", !settings.encrypt);
}
function applyVisualSettings() {
  document.body.classList.toggle("blur-codes", settings.blurCodes);
  document.body.classList.toggle("screenshot-safe", settings.screenshotSafe);
}
function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success", "warning");
  if (tone) node.classList.add(tone);
}
function showToast(title, message = "", tone = "success") {
  if (!toastRegion) return;
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.innerHTML = `<strong>${title}</strong>${message ? `<p>${message}</p>` : ""}`;
  toastRegion.appendChild(toast);
  window.setTimeout(() => toast.remove(), 4200);
}
function setImportStatus(message, tone = "") {
  setStatus(importStatus, message, tone);
  if (message) showToast(tone === "error" ? "Import" : "Vault", message, tone || "success");
}
function setSettingsStatus(message, tone = "") {
  setStatus(settingsStatus, message, tone);
  if (message) showToast(tone === "error" ? "Settings" : "Vault", message, tone || "success");
}
function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}
function logDebug(level, message, detail = "") {
  debugEvents = [{
    level,
    message,
    detail: detail ? String(detail) : "",
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  }, ...debugEvents].slice(0, 18);
  renderDebugFeed();
}
function hasSeenPersistWarning() {
  return localStorage.getItem(WARNING_KEY) === "true";
}
function markPersistWarningSeen() {
  localStorage.setItem(WARNING_KEY, "true");
}
function loadVaultOnStartup() {
  if (!settings.persist) {
    entries = [];
    setLocked(false);
    return;
  }
  if (settings.encrypt) {
    entries = [];
    setLocked(true);
    if (!settings.unlockOnLoad && !localStorage.getItem(ENCRYPTED_VAULT_KEY)) {
      setLocked(false);
    }
    return;
  }
  entries = loadPlainEntries();
  setLocked(false);
}
function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  lockAppBtn.disabled = locked;
  form.querySelectorAll("input, button, select, textarea").forEach((el) => {
    el.disabled = locked;
  });
  searchInput.disabled = locked;
  sortSelect.disabled = locked;
  groupSelect.disabled = locked;
}
function loadPlainEntries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return normalizeEntries(JSON.parse(raw));
  } catch (error) {
    reportError("Failed to load plain entries", error);
    return [];
  }
}
function savePlainEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}
function clearPersistedEntries() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
}
function entryKey(entry) {
  return `${entry.secret}::${entry.digits}::${entry.period}`;
}
function getVisibleEntries() {
  return [...entries].filter((entry) => entryMatchesQuery(entry, searchInput.value || "")).sort((a, b) => compareEntries(a, b, settings.sortBy));
}
function getEntryGroups() {
  const visibleEntries = getVisibleEntries();
  const groups = /* @__PURE__ */ new Map();
  for (const entry of visibleEntries) {
    const name = getEntryGroup(entry, settings.groupBy);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(entry);
  }
  if (settings.groupBy === "none") return [["All Entries", visibleEntries]];
  return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right, void 0, { sensitivity: "base" }));
}
function setOnboardingVisibility() {
  onboardingPanel?.classList.toggle("hidden", entries.length > 0);
}
function renderTagRow(node, entry) {
  const tagRow = node.querySelector(".entry-tag-row");
  if (!tagRow) return;
  tagRow.innerHTML = "";
  for (const tag of entry.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag-chip";
    chip.textContent = tag;
    tagRow.appendChild(chip);
  }
}
function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  copyHistoryRoot.innerHTML = "";
  if (copyHistory.length === 0) {
    copyHistoryRoot.innerHTML = '<li class="history-empty">No copied codes yet. The last few copied OTPs appear here for quick recall.</li>';
    return;
  }
  for (const item of copyHistory) {
    const row = document.createElement("li");
    row.innerHTML = `<strong>${item.label}</strong><span>${item.code} \u2022 ${item.at}</span>`;
    copyHistoryRoot.appendChild(row);
  }
}
function renderDebugFeed() {
  if (!debugList) return;
  debugList.innerHTML = "";
  if (debugEvents.length === 0) {
    debugList.innerHTML = "<li><strong>No debug events yet</strong><span>Import, backup, and vault operations will appear here.</span></li>";
    return;
  }
  for (const event of debugEvents) {
    const row = document.createElement("li");
    row.innerHTML = `<strong>[${event.level}] ${event.message}</strong><span>${event.at}${event.detail ? ` \u2022 ${event.detail}` : ""}</span>`;
    debugList.appendChild(row);
  }
}
function renderBulkBar() {
  if (!bulkBar || !bulkSummary) return;
  const selectedCount = selectedEntryIds.size;
  bulkBar.classList.toggle("hidden", selectedCount === 0);
  bulkSummary.textContent = `${selectedCount} selected`;
}
function addCopyHistory(label, code) {
  copyHistory = [{
    label,
    code: formatCode(code),
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }, ...copyHistory.filter((item) => item.label !== label)].slice(0, 6);
  renderCopyHistory();
}
function showEmptyState(message) {
  entriesRoot.innerHTML = "";
  entriesRoot.innerHTML = `<section class="entry-group"><p class="entry-group-title">workspace</p><div class="preview-item">${message}</div></section>`;
}
function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  const avatar = node.querySelector(".entry-avatar");
  const label = node.querySelector(".entry-label");
  const account = node.querySelector(".entry-account");
  const meta = node.querySelector(".entry-meta");
  const copyBtn = node.querySelector(".copy");
  const revealBtn = node.querySelector(".reveal");
  const pinBtn = node.querySelector(".pin");
  const removeBtn = node.querySelector(".remove");
  const selectBox = node.querySelector(".entry-select");
  avatar.textContent = getIssuerInitials(entry.label);
  refreshEntryMetadata(node, entry);
  renderTagRow(node, entry);
  copyBtn.onclick = async () => {
    try {
      const latestCode = node.dataset.otp;
      if (!latestCode) return;
      await navigator.clipboard.writeText(latestCode);
      addCopyHistory(entry.label, latestCode);
      copyBtn.textContent = "Copied";
      if (settings.clearClipboard) {
        setTimeout(() => {
          navigator.clipboard.writeText("").catch((error) => reportError("Clipboard clear failed", error));
        }, 3e4);
      }
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1e3);
    } catch (error) {
      reportError("Copy failed", error);
      setImportStatus(toUserMessage(error, "Could not copy OTP to clipboard"), "error");
    }
  };
  revealBtn.onclick = () => {
    node.classList.toggle("revealed");
    revealBtn.textContent = node.classList.contains("revealed") ? "Hide" : "Reveal";
  };
  pinBtn.onclick = async () => {
    try {
      await replaceEntries(entries.map((item) => item.id === entry.id ? { ...item, pinned: !item.pinned } : item));
      setImportStatus("Entry order updated", "success");
    } catch (error) {
      reportError("Pin toggle failed", error);
      setImportStatus(toUserMessage(error, "Could not update entry order"), "error");
    }
  };
  removeBtn.onclick = async () => {
    try {
      const nextEntries = entries.filter((item) => item.id !== entry.id);
      await replaceEntries(nextEntries);
      selectedEntryIds.delete(entry.id);
      renderBulkBar();
      setImportStatus("Entry removed", "success");
    } catch (error) {
      reportError("Entry removal failed", error);
      setImportStatus(toUserMessage(error, "Could not remove entry"), "error");
    }
  };
  if (selectBox) {
    selectBox.onchange = () => {
      if (selectBox.checked) selectedEntryIds.add(entry.id);
      else selectedEntryIds.delete(entry.id);
      renderBulkBar();
    };
  }
  return node;
}
function refreshEntryMetadata(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".entry-label").textContent = parts.issuer;
  node.querySelector(".entry-account").textContent = parts.account;
  node.querySelector(".entry-meta").textContent = `${entry.digits} digits \u2022 ${entry.period}s`;
  renderTagRow(node, entry);
}
function renderEntries() {
  setOnboardingVisibility();
  if (!unlockPanel.classList.contains("hidden") && settings.encrypt) {
    showEmptyState("Vault is locked. Unlock to view your codes.");
    return;
  }
  if (entries.length === 0) {
    entryNodes.clear();
    showEmptyState("No entries yet. Import a URI, scan a QR, or add one manually.");
    return;
  }
  const groups = getEntryGroups();
  if (groups.length === 0 || groups.every(([, groupEntries]) => groupEntries.length === 0)) {
    showEmptyState("No matching entries.");
    return;
  }
  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (const [groupName, groupEntries] of groups) {
    if (groupEntries.length === 0) continue;
    const wrapper = document.createElement("section");
    wrapper.className = "entry-group";
    if (settings.groupBy !== "none") {
      const title = document.createElement("p");
      title.className = "entry-group-title";
      title.textContent = groupName;
      wrapper.appendChild(title);
    }
    for (const entry of groupEntries) {
      let node = entryNodes.get(entry.id);
      if (!node) {
        node = createEntryNode(entry);
        entryNodes.set(entry.id, node);
      }
      refreshEntryMetadata(node, entry);
      node.classList.toggle("pinned", entry.pinned);
      node.querySelector(".pin").textContent = entry.pinned ? "Unpin" : "Pin";
      const selectBox = node.querySelector(".entry-select");
      if (selectBox) selectBox.checked = selectedEntryIds.has(entry.id);
      wrapper.appendChild(node);
    }
    fragment.appendChild(wrapper);
  }
  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }
  entriesRoot.appendChild(fragment);
}
async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  const code = node.querySelector(".entry-code");
  const seconds = node.querySelector(".entry-seconds");
  const bar = node.querySelector(".entry-bar");
  const copyBtn = node.querySelector(".copy");
  const remaining = entry.period - now % entry.period;
  seconds.textContent = `${remaining}s left`;
  bar.style.transform = `scaleX(${remaining / entry.period})`;
  node.classList.toggle("urgent", remaining <= 10);
  try {
    const otp = await generateTotp(entry.secret, entry.digits, entry.period, now);
    code.textContent = formatCode(otp);
    node.dataset.otp = otp;
    copyBtn.disabled = false;
  } catch (error) {
    reportError("OTP generation failed", error);
    code.textContent = "Invalid secret";
    node.dataset.otp = "";
    copyBtn.disabled = true;
  }
}
async function updateAllEntries(now) {
  await Promise.all(getVisibleEntries().map((entry) => updateEntryNode(entry, now)));
}
function updateTimer(now) {
  const visibleEntries = getVisibleEntries();
  const period = visibleEntries.length > 0 ? Math.min(...visibleEntries.map((entry) => entry.period)) : 30;
  const remaining = period - now % period;
  timerValue.textContent = `${remaining}s`;
  timerBar.style.transform = `scaleX(${remaining / period})`;
}
async function tick() {
  const now = Math.floor(Date.now() / 1e3);
  updateTimer(now);
  if (!unlockPanel.classList.contains("hidden") && settings.encrypt) return;
  await updateAllEntries(now);
}
async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(encryptedPayload));
  return encryptedPayload;
}
async function decryptStoredEntries(passphrase) {
  const raw = localStorage.getItem(ENCRYPTED_VAULT_KEY);
  if (!raw) return [];
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    throw new Error("Encrypted data is unreadable", { cause: error });
  }
  return decryptVaultEntries(payload, passphrase);
}
async function persistEntries() {
  if (!settings.persist) {
    clearPersistedEntries();
    return;
  }
  if (settings.encrypt) {
    if (!currentPassphrase) {
      throw new Error("Unlock or set a passphrase before saving encrypted entries");
    }
    await saveEncryptedEntries(entries, currentPassphrase);
    localStorage.removeItem(STORAGE_KEY);
    return;
  }
  savePlainEntries();
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
}
async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);
  selectedEntryIds = new Set([...selectedEntryIds].filter((id) => entries.some((entry) => entry.id === id)));
  try {
    await persistEntries();
  } catch (error) {
    entries = previousEntries;
    renderEntries();
    renderBulkBar();
    await tick();
    throw error;
  }
  renderEntries();
  renderBulkBar();
  await tick();
}
function buildManualEntry(input) {
  const entry = normalizeEntry({ ...input, pinned: false });
  if (hasDuplicateEntry(entries, entry)) {
    throw new Error("This account already exists");
  }
  return entry;
}
async function addEntry(input) {
  const entry = buildManualEntry(input);
  await replaceEntries([...entries, entry]);
  return entry;
}
function buildPreviewCandidatesFromUris(uris, sourceLabel) {
  const unique = [];
  const seen = /* @__PURE__ */ new Set();
  for (const uri of uris) {
    try {
      const entry = parseOtpAuthUri(uri);
      const key = entryKey(entry);
      if (seen.has(key) || hasDuplicateEntry(entries, entry)) continue;
      seen.add(key);
      unique.push(entry);
    } catch {
      continue;
    }
  }
  if (unique.length === 0) throw new Error(`No new entries found from ${sourceLabel}`);
  return unique;
}
function renderImportPreview() {
  if (!importPreviewState || !importPreviewList) return;
  importPreviewTitle.textContent = `Review ${importPreviewState.candidates.length} candidate${importPreviewState.candidates.length === 1 ? "" : "s"}`;
  importPreviewStatus.textContent = `${importPreviewState.sourceLabel}: only valid, non-duplicate entries are shown below.`;
  importPreviewList.innerHTML = "";
  importPreviewState.candidates.forEach((entry, index) => {
    const row = document.createElement("article");
    row.className = "preview-item";
    row.dataset.index = String(index);
    row.innerHTML = `
      <label class="toggle-row">
        <input type="checkbox" class="preview-include" checked>
        <span>Import this entry</span>
      </label>
      <label>
        <span>Label</span>
        <input type="text" class="preview-label" value="${entry.label.replace(/"/g, "&quot;")}">
      </label>
      <label>
        <span>Tags</span>
        <input type="text" class="preview-tags" value="${(entry.tags || []).join(", ")}" placeholder="project, hardware-key">
      </label>
      <p>${entry.digits} digits \u2022 ${entry.period}s</p>
    `;
    importPreviewList.appendChild(row);
  });
}
function openImportPreview(candidates, sourceLabel) {
  importPreviewState = { candidates, sourceLabel };
  if (importPreviewTagsInput) importPreviewTagsInput.value = "";
  renderImportPreview();
  importDialog?.showModal?.();
}
async function commitImportPreview() {
  if (!importPreviewState) return;
  const extraTags = normalizeTags(importPreviewTagsInput?.value);
  const rows = [...importPreviewList.querySelectorAll(".preview-item")];
  const enriched = rows.flatMap((row) => {
    const include = row.querySelector(".preview-include");
    if (!include?.checked) return [];
    const index = Number(row.dataset.index);
    const baseEntry = importPreviewState.candidates[index];
    return [{
      ...baseEntry,
      label: row.querySelector(".preview-label")?.value.trim() || baseEntry.label,
      tags: normalizeTags([
        ...baseEntry.tags || [],
        ...normalizeTags(row.querySelector(".preview-tags")?.value),
        ...extraTags
      ])
    }];
  });
  if (enriched.length === 0) throw new Error("Select at least one entry to import");
  await replaceEntries([...entries, ...enriched]);
  setImportStatus(`${importPreviewState.sourceLabel}: imported ${enriched.length} entr${enriched.length === 1 ? "y" : "ies"}`, "success");
}
async function decodeQrFromBlob(blob) {
  if (typeof window.jsQR !== "function") {
    throw new Error("QR scanner library failed to load");
  }
  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  if (!result?.data) {
    throw new Error("Could not detect a QR code in that image");
  }
  return result.data;
}
async function importFromQrBlob(blob, sourceLabel) {
  const qrText = await decodeQrFromBlob(blob);
  const uris = extractOtpAuthUris(qrText);
  if (uris.length === 0) throw new Error("QR code was detected but does not contain a valid OTP URI");
  const candidates = buildPreviewCandidatesFromUris(uris, sourceLabel);
  openImportPreview(candidates, sourceLabel);
}
async function unlockVault(passphrase) {
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const decrypted = await decryptStoredEntries(normalizedPassphrase);
  currentPassphrase = normalizedPassphrase;
  entries = decrypted;
  setLocked(false);
  renderEntries();
  await tick();
}
async function handleSaveSettings() {
  if (persistToggle.checked && !hasSeenPersistWarning()) {
    if (typeof privacyDialog.showModal === "function") {
      privacyDialog.showModal();
      return;
    }
  }
  const nextSettings = {
    persist: persistToggle.checked,
    encrypt: encryptToggle.checked,
    unlockOnLoad: unlockOnLoadToggle.checked,
    blurCodes: blurCodesToggle.checked,
    screenshotSafe: screenshotSafeToggle.checked,
    clearClipboard: clearClipboardToggle.checked,
    sortBy: sortSelect.value,
    groupBy: groupSelect.value
  };
  let nextPassphrase = currentPassphrase;
  if (nextSettings.encrypt) {
    const first = vaultPassphraseInput.value.trim();
    const second = vaultPassphraseConfirmInput.value.trim();
    if (!currentPassphrase && !first) {
      throw new Error("Enter a passphrase to enable encryption");
    }
    if (first || second) {
      if (first !== second) {
        throw new Error("Passphrase confirmation does not match");
      }
      nextPassphrase = normalizePassphrase(first);
    }
  } else {
    nextPassphrase = "";
  }
  settings = nextSettings;
  currentPassphrase = nextPassphrase;
  saveSettings();
  syncSettingsUI();
  applyVisualSettings();
  if (!settings.persist) {
    clearPersistedEntries();
    setLocked(false);
    setSettingsStatus("Entries are now session-only", "success");
    vaultPassphraseInput.value = "";
    vaultPassphraseConfirmInput.value = "";
    return;
  }
  await persistEntries();
  setLocked(false);
  setSettingsStatus(settings.encrypt ? "Encrypted vault saved" : "Device storage updated", "success");
  vaultPassphraseInput.value = "";
  vaultPassphraseConfirmInput.value = "";
}
function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
async function exportBackup() {
  if (settings.encrypt) {
    if (!currentPassphrase) {
      throw new Error("Unlock the vault before exporting encrypted backup");
    }
    const encryptedPayload = await encryptEntries(entries, currentPassphrase);
    downloadJson("otp-vault-backup.json", await createEncryptedBackup(encryptedPayload));
    return;
  }
  downloadJson("otp-vault-backup.json", await createPlainBackup(entries));
}
function renderBackupReview(backup) {
  if (!backupReviewSummary) return;
  backupReviewSummary.innerHTML = "";
  [
    `Integrity: ${backup.integrity === "verified" ? "verified checksum" : "legacy backup"}`,
    `Encrypted: ${backup.encrypted ? "yes" : "no"}`,
    `Schema: v${backup.schemaVersion}`,
    `Created: ${backup.createdAt || "unknown"}`,
    `Incoming items: ${backup.itemCount}`,
    `Current vault size: ${entries.length}`
  ].forEach((item) => {
    const row = document.createElement("div");
    row.className = "preview-item";
    row.textContent = item;
    backupReviewSummary.appendChild(row);
  });
  backupPassphraseRow?.classList.toggle("hidden", !backup.encrypted);
  setStatus(
    backupReviewStatus,
    backup.integrity === "verified" ? "Backup checksum verified. Choose merge to keep existing entries or replace to overwrite the vault." : "Legacy backup detected. Import is supported, but integrity could not be verified.",
    backup.integrity === "verified" ? "success" : "warning"
  );
}
async function importBackupFile(file, backup = null) {
  const resolvedBackup = backup || await (async () => {
    const text = await file.text();
    try {
      return await parseBackupFile(JSON.parse(text));
    } catch (error) {
      throw new Error(toUserMessage(error, "Backup file is invalid"));
    }
  })();
  if (resolvedBackup.integrity === "legacy") {
    setSettingsStatus("Legacy backup detected. Importing without checksum verification.", "warning");
  }
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");
  if (resolvedBackup.encrypted) {
    const passphrase = backupImportPassphraseInput?.value.trim() || window.prompt("Backup is encrypted. Enter the backup passphrase:");
    if (!passphrase) throw new Error("Backup import cancelled");
    const decrypted = await decryptVaultEntries(resolvedBackup.vault, passphrase);
    if (settings.encrypt) {
      currentPassphrase = normalizePassphrase(passphrase);
    }
    const nextEntries2 = mode === "replace" ? decrypted : [...entries, ...decrypted.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
    await replaceEntries(nextEntries2);
    return;
  }
  const nextEntries = mode === "replace" ? resolvedBackup.entries : [...entries, ...resolvedBackup.entries.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
  await replaceEntries(nextEntries);
}
async function stageBackupImport(file) {
  const text = await file.text();
  let backup;
  try {
    backup = await parseBackupFile(JSON.parse(text));
  } catch (error) {
    throw new Error(toUserMessage(error, "Backup file is invalid"));
  }
  backupImportState = { file, backup };
  if (backupImportMode) backupImportMode.value = entries.length > 0 ? "merge" : "replace";
  if (backupImportPassphraseInput) backupImportPassphraseInput.value = "";
  renderBackupReview(backup);
  if (backupReviewDialog?.showModal) {
    backupReviewDialog.showModal();
    return;
  }
  await importBackupFile(file, backup);
}
async function commitBackupImport() {
  if (!backupImportState) return;
  await importBackupFile(backupImportState.file, backupImportState.backup);
}
function registerCameraDetection(uri) {
  if (cameraDetection.uri === uri) {
    cameraDetection.hits += 1;
  } else {
    cameraDetection = { uri, hits: 1 };
  }
  return cameraDetection.hits >= 2;
}
async function startCameraScan() {
  if (cameraStream) return;
  cameraDetection = { uri: "", hits: 0 };
  cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  cameraPreview.srcObject = cameraStream;
  await cameraPreview.play();
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  cameraScanTimer = setInterval(async () => {
    if (!cameraPreview.videoWidth || !cameraPreview.videoHeight || typeof window.jsQR !== "function") return;
    canvas.width = cameraPreview.videoWidth;
    canvas.height = cameraPreview.videoHeight;
    ctx.drawImage(cameraPreview, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const result = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
    const otpUri = extractOtpAuthUri(result?.data || "");
    if (!otpUri) {
      cameraDetection = { uri: "", hits: 0 };
      return;
    }
    if (!registerCameraDetection(otpUri)) {
      setImportStatus("Potential OTP QR detected. Confirming with another frame...", "success");
      return;
    }
    try {
      openImportPreview(buildPreviewCandidatesFromUris([otpUri], "Camera"), "Camera");
      stopCameraScan();
    } catch (error) {
      reportError("Camera import failed", error);
      setImportStatus(toUserMessage(error, "Could not import camera scan"), "error");
      cameraDetection = { uri: "", hits: 0 };
    }
  }, 900);
}
function stopCameraScan() {
  if (cameraScanTimer) clearInterval(cameraScanTimer);
  cameraScanTimer = null;
  cameraDetection = { uri: "", hits: 0 };
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
  }
  cameraStream = null;
  cameraPreview.srcObject = null;
}
function registerPwaSupport() {
  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    deferredInstallPrompt = event;
    installAppBtn.disabled = false;
  });
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch((error) => reportError("Service worker registration failed", error));
  }
}
function bindEvents() {
  document.addEventListener("keydown", (event) => {
    if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return;
    if (event.key === "/") {
      event.preventDefault();
      searchInput.focus();
    }
    if (event.key.toLowerCase() === "n") {
      event.preventDefault();
      secretInput.focus();
    }
  });
  encryptToggle.addEventListener("change", () => {
    encryptionFields.classList.toggle("hidden", !encryptToggle.checked);
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
        tags: normalizeTags(tagsInput?.value)
      });
      form.reset();
      digitsInput.value = "6";
      periodInput.value = "30";
      syncSettingsUI();
      setImportStatus("Entry added", "success");
    } catch (error) {
      reportError("Manual entry failed", error);
      setImportStatus(toUserMessage(error, "Could not add entry"), "error");
    }
  });
  parseUriBtn.addEventListener("click", async () => {
    try {
      const uris = extractOtpAuthUris(uriInput.value);
      if (uris.length === 0) throw new Error("No valid otpauth:// URI found");
      openImportPreview(buildPreviewCandidatesFromUris(uris, "URI"), "URI");
      uriInput.value = "";
    } catch (error) {
      reportError("URI import failed", error);
      setImportStatus(toUserMessage(error, "Invalid URI"), "error");
    }
  });
  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    setImportStatus("Reading QR file...");
    try {
      await importFromQrBlob(file, "QR file");
    } catch (error) {
      reportError("QR file import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import QR file"), "error");
    } finally {
      qrFileInput.value = "";
    }
  });
  importQrUrlBtn.addEventListener("click", async () => {
    const url = (qrUrlInput.value || "").trim();
    if (!url) {
      setImportStatus("Please enter a QR image URL", "error");
      return;
    }
    setImportStatus("Fetching QR image URL...");
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error("Could not download QR image URL");
      await importFromQrBlob(await response.blob(), "QR URL");
    } catch (error) {
      reportError("QR URL import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from URL"), "error");
    }
  });
  importClipboardBtn.addEventListener("click", async () => {
    setImportStatus("Reading clipboard...");
    try {
      if (navigator.clipboard && typeof navigator.clipboard.read === "function") {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imageType = item.types.find((type) => type.startsWith("image/"));
          if (!imageType) continue;
          await importFromQrBlob(await item.getType(imageType), "Clipboard image");
          return;
        }
      }
      const text = await navigator.clipboard.readText();
      const uris = extractOtpAuthUris(text);
      if (uris.length === 0) throw new Error("Clipboard does not contain a valid OTP URI or QR image");
      openImportPreview(buildPreviewCandidatesFromUris(uris, "Clipboard"), "Clipboard");
    } catch (error) {
      reportError("Clipboard import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from clipboard"), "error");
    }
  });
  startCameraBtn.addEventListener("click", async () => {
    try {
      setImportStatus("Starting camera...");
      await startCameraScan();
      setImportStatus("Camera ready. Hold a QR code in front of it.", "success");
    } catch (error) {
      reportError("Camera start failed", error);
      setImportStatus(toUserMessage(error, "Could not start camera"), "error");
    }
  });
  stopCameraBtn.addEventListener("click", () => {
    stopCameraScan();
    setImportStatus("Camera stopped");
  });
  clearAllBtn.addEventListener("click", async () => {
    try {
      await replaceEntries([]);
      setImportStatus("All entries cleared", "success");
    } catch (error) {
      reportError("Clear all failed", error);
      setImportStatus(toUserMessage(error, "Could not clear entries"), "error");
    }
  });
  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });
  sortSelect?.addEventListener("change", () => {
    settings.sortBy = sortSelect.value;
    saveSettings();
    renderEntries();
    tick();
  });
  groupSelect?.addEventListener("change", () => {
    settings.groupBy = groupSelect.value;
    saveSettings();
    renderEntries();
  });
  bulkTagApplyBtn?.addEventListener("click", async () => {
    const extraTags = normalizeTags(bulkTagInput.value);
    if (extraTags.length === 0) {
      setImportStatus("Enter at least one tag for the selected entries", "warning");
      return;
    }
    try {
      await replaceEntries(entries.map((entry) => selectedEntryIds.has(entry.id) ? { ...entry, tags: normalizeTags([...entry.tags || [], ...extraTags]) } : entry));
      bulkTagInput.value = "";
      setImportStatus("Tags applied to selected entries", "success");
    } catch (error) {
      reportError("Bulk tag update failed", error);
      setImportStatus(toUserMessage(error, "Could not update selected entries"), "error");
    }
  });
  bulkRemoveBtn?.addEventListener("click", async () => {
    try {
      await replaceEntries(entries.filter((entry) => !selectedEntryIds.has(entry.id)));
      selectedEntryIds.clear();
      renderBulkBar();
      setImportStatus("Selected entries removed", "success");
    } catch (error) {
      reportError("Bulk remove failed", error);
      setImportStatus(toUserMessage(error, "Could not remove selected entries"), "error");
    }
  });
  saveSettingsBtn.addEventListener("click", async () => {
    try {
      await handleSaveSettings();
    } catch (error) {
      reportError("Save settings failed", error);
      setSettingsStatus(toUserMessage(error, "Could not save settings"), "error");
    }
  });
  exportBackupBtn.addEventListener("click", async () => {
    try {
      await exportBackup();
      setSettingsStatus("Backup exported", "success");
    } catch (error) {
      reportError("Backup export failed", error);
      setSettingsStatus(toUserMessage(error, "Could not export backup"), "error");
    }
  });
  importBackupInput.addEventListener("change", async () => {
    const [file] = importBackupInput.files || [];
    if (!file) return;
    try {
      await stageBackupImport(file);
    } catch (error) {
      reportError("Backup import failed", error);
      setSettingsStatus(toUserMessage(error, "Could not import backup"), "error");
    } finally {
      importBackupInput.value = "";
    }
  });
  lockAppBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setSettingsStatus("Enable encrypted storage to use lock/unlock", "error");
      return;
    }
    entries = [];
    setLocked(true);
    renderEntries();
  });
  unlockBtn.addEventListener("click", async () => {
    try {
      await unlockVault(unlockPassphraseInput.value);
      unlockPassphraseInput.value = "";
      setUnlockStatus("Vault unlocked", "success");
    } catch (error) {
      reportError("Vault unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted vault"), "error");
    }
  });
  installAppBtn.addEventListener("click", async () => {
    if (!deferredInstallPrompt) {
      setSettingsStatus("Install prompt is not available yet on this browser", "error");
      return;
    }
    await deferredInstallPrompt.prompt();
    deferredInstallPrompt = null;
  });
  debugToggleBtn?.addEventListener("click", () => {
    const willShow = debugPanel.classList.contains("hidden");
    debugPanel.classList.toggle("hidden", !willShow);
    debugToggleBtn.setAttribute("aria-expanded", String(willShow));
  });
  privacyDialog.addEventListener("close", () => {
    if (privacyDialog.returnValue === "accept") {
      markPersistWarningSeen();
      handleSaveSettings().catch((error) => {
        reportError("Save settings after privacy dialog failed", error);
        setSettingsStatus(toUserMessage(error, "Could not save settings"), "error");
      });
    } else {
      persistToggle.checked = settings.persist;
    }
  });
  importDialog?.addEventListener("close", () => {
    if (importDialog.returnValue === "accept") {
      commitImportPreview().catch((error) => {
        reportError("Import preview commit failed", error);
        setImportStatus(toUserMessage(error, "Could not import entries"), "error");
      });
    }
    importPreviewState = null;
  });
  backupReviewDialog?.addEventListener("close", () => {
    if (backupReviewDialog.returnValue === "accept") {
      commitBackupImport().then(() => setSettingsStatus("Backup imported", "success")).catch((error) => setSettingsStatus(toUserMessage(error, "Could not import backup"), "error"));
    }
    backupImportState = null;
  });
}
window.otpVaultDebug = {
  extractOtpAuthUri,
  parseLabelParts,
  parseOtpAuthUri
};
