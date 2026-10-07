// lib/otp.js
var BASE32_REGEX = /^[A-Z2-7]+$/;
var OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
var MIN_PERIOD = 15;
var MAX_PERIOD = 120;
var OTP_TYPES = ["totp", "hotp"];
var OTP_ALGORITHMS = ["SHA1", "SHA256", "SHA512"];
var HMAC_HASH_NAMES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
var MAX_SAFE_COUNTER = Number.MAX_SAFE_INTEGER;
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
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(6));
  const random = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `entry_${Date.now().toString(36)}_${random}`;
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
function ensureType(type) {
  const value = String(type || "totp").toLowerCase();
  if (!OTP_TYPES.includes(value)) {
    throw new OtpVaultError("OTP type must be totp or hotp", { code: "OTP_TYPE_INVALID" });
  }
  return value;
}
function ensureAlgorithm(algorithm) {
  const value = String(algorithm || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(value)) {
    throw new OtpVaultError("OTP algorithm must be SHA1, SHA256, or SHA512", { code: "ALGORITHM_UNSUPPORTED" });
  }
  return value;
}
function ensureCounter(counter) {
  if (counter === void 0 || counter === null || counter === "") return 0;
  const value = Number(counter);
  if (!Number.isInteger(value) || value < 0 || value > MAX_SAFE_COUNTER) {
    throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "COUNTER_INVALID" });
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
  const type = ensureType(entry.type);
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    type,
    counter: type === "hotp" ? ensureCounter(entry.counter) : 0,
    algorithm: ensureAlgorithm(entry.algorithm),
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now(),
    order: Number.isFinite(Number(entry.order)) ? Number(entry.order) : 0
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
      issuer: issuer.trim() || "Unknown",
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
  const type = parsed.hostname.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    throw new OtpVaultError("Only TOTP and HOTP URIs are supported", { code: "URI_TYPE" });
  }
  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(algorithm)) {
    throw new OtpVaultError("Only SHA1, SHA256, and SHA512 OTP URIs are supported", { code: "URI_ALGORITHM" });
  }
  let counter;
  if (type === "hotp") {
    const counterParam = parsed.searchParams.get("counter");
    counter = counterParam === null ? 0 : Number(counterParam);
    if (!Number.isInteger(counter) || counter < 0 || counter > MAX_SAFE_COUNTER) {
      throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "URI_COUNTER" });
    }
  }
  const issuerParam = safeDecode(parsed.searchParams.get("issuer") || "").trim();
  const rawLabel = safeDecode(parsed.pathname.replace(/^\/+/, "")).trim();
  const labelParts = parseLabelParts(rawLabel);
  if (issuerParam && rawLabel && labelParts.issuer !== "Unknown" && labelParts.account !== "No account label") {
    if (labelParts.issuer.toLowerCase() !== issuerParam.toLowerCase()) {
      throw new OtpVaultError("OTP URI issuer does not match the label", { code: "URI_ISSUER_MISMATCH" });
    }
  }
  const label = rawLabel ? issuerParam && rawLabel.includes(":") ? labelParts.account === "No account label" ? `${labelParts.issuer === "Unknown" ? issuerParam : labelParts.issuer}:${labelParts.account}` : labelParts.issuer === "Unknown" ? `${issuerParam}:${labelParts.account}` : rawLabel : !issuerParam ? rawLabel : `${issuerParam}:${rawLabel}` : issuerParam ? `${issuerParam}:Imported Account` : "Imported Account";
  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    type,
    counter,
    algorithm,
    // Period is meaningless for HOTP but stored so the entry shape stays valid.
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: type === "hotp" ? 30 : parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30
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
function compareEntries(a, b, sortBy = "pinned-alpha") {
  if (sortBy === "recent") return b.createdAt - a.createdAt;
  if (sortBy === "period") return a.period - b.period || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  if (sortBy === "custom") return a.order - b.order || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
  return a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
}
function computeDropIndex(midpoints, fromIndex, y) {
  if (!Array.isArray(midpoints) || midpoints.length === 0) return 0;
  const others = midpoints.filter((_, index) => index !== fromIndex);
  if (!Number.isFinite(y) || others.length === 0) return others.length;
  for (let index = 0; index < others.length; index += 1) {
    if (y <= others[index]) return index;
  }
  return others.length;
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
var MIGRATION_URI_REGEX = /otpauth-migration:\/\/[^\s"'<>]+/gi;
function extractMigrationUris(rawText) {
  const found = /* @__PURE__ */ new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  for (const match of raw.matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  for (const match of safeDecode(raw).matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  return [...found];
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
async function hmac(keyBytes, messageBytes, hash, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  const algorithmName = HMAC_HASH_NAMES[hash] || hash;
  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algorithmName }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}
function truncateDigest(digest, digits) {
  const offset = digest[digest.length - 1] & 15;
  const binary = (digest[offset] & 127) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3];
  return (binary % 10 ** digits).toString().padStart(digits, "0");
}
async function generateHotp(secret, counter, digits, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedCounter = ensureCounter(counter);
  const normalizedDigits = ensureDigits(digits);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(normalizedCounter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}
async function generateTotp(secret, digits, period, now, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(counter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}
function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

// lib/i18n.js
var DEFAULT_LOCALE = "en";
var PLACEHOLDER_PATTERN = /\{([a-zA-Z0-9_]+)\}/g;
var en = {
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
  "settings.updatePassphrase": "Update Passphrase"
};
var reserved = {
  "toast.vaultTitle": "Vault",
  "toast.importTitle": "Import",
  "toast.settingsTitle": "Settings",
  "toast.copyFailed": "Could not copy OTP to clipboard",
  "import.entryAdded": "Entry added",
  "import.invalidUri": "Invalid URI",
  "import.qrUrlRequired": "Please enter a QR image URL",
  "import.readingQrFile": "Reading QR file...",
  "import.fetchingQrUrl": "Fetching QR image URL..."
};
var catalogs = /* @__PURE__ */ new Map([[DEFAULT_LOCALE, { ...en, ...reserved }]]);
var activeLocale = DEFAULT_LOCALE;
function t(key, params) {
  return interpolate(resolveTemplate(key), params);
}
function resolveTemplate(key) {
  if (typeof key !== "string" || !key) return key;
  const value = catalogs.get(activeLocale)?.[key] ?? catalogs.get(DEFAULT_LOCALE)?.[key];
  return typeof value === "string" ? value : key;
}
function interpolate(template2, params) {
  if (typeof template2 !== "string") return template2;
  if (!params || typeof params !== "object") return template2;
  return template2.replace(PLACEHOLDER_PATTERN, (match, name) => Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match);
}

// lib/migration.js
var MAX_BATCH_SIZE = 10;
var MAX_STITCHED_ENTRIES = 500;
var MAX_PAYLOAD_BYTES = 64 * 1024;
var MAX_SAFE_COUNTER2 = BigInt(Number.MAX_SAFE_INTEGER);
var ALGORITHM_NAMES = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
var BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
var BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var BASE64_LOOKUP = new Int8Array(256).fill(-1);
for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
  BASE64_LOOKUP[BASE64_ALPHABET.charCodeAt(index)] = index;
}
var TEXT_DECODER = new TextDecoder("utf-8");
function malformed(message) {
  return new OtpVaultError(message, { code: "MIGRATION_DATA_MALFORMED" });
}
function toInt32(value) {
  return Number(BigInt.asIntN(32, value));
}
function varint(bytes, pos) {
  let value = 0n;
  let shift = 0n;
  for (; ; ) {
    if (pos >= bytes.length) {
      throw malformed("Migration payload ends inside a varint");
    }
    const byte = bytes[pos];
    pos += 1;
    value |= BigInt(byte & 127) << shift;
    if ((byte & 128) === 0) return [value, pos];
    shift += 7n;
    if (shift >= 70n) {
      throw malformed("Migration payload contains an overlong varint");
    }
  }
}
function skipField(bytes, pos, wireType) {
  if (wireType === 0) return varint(bytes, pos)[1];
  if (wireType === 1) {
    if (pos + 8 > bytes.length) throw malformed("Migration payload has a truncated fixed64 field");
    return pos + 8;
  }
  if (wireType === 2) return lenBytes(bytes, pos)[1];
  if (wireType === 5) {
    if (pos + 4 > bytes.length) throw malformed("Migration payload has a truncated fixed32 field");
    return pos + 4;
  }
  throw malformed(`Migration payload uses unsupported wire type ${wireType}`);
}
function lenBytes(bytes, pos) {
  const [length, start] = varint(bytes, pos);
  const end = start + Number(length);
  if (end > bytes.length) {
    throw malformed("Migration payload has a truncated length-delimited field");
  }
  return [bytes.subarray(start, end), end];
}
function decodeOtpParameters(bytes) {
  const params = { secret: new Uint8Array(0), name: "", issuer: "", algorithm: 0, digits: 0, type: 0, counter: 0n };
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      [params.secret, pos] = lenBytes(bytes, pos);
    } else if ((field === 2 || field === 3) && wireType === 2) {
      const [value, after] = lenBytes(bytes, pos);
      pos = after;
      const text = TEXT_DECODER.decode(value);
      if (field === 2) params.name = text;
      else params.issuer = text;
    } else if (field >= 4 && field <= 6 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      if (field === 4) params.algorithm = Number(value);
      else if (field === 5) params.digits = Number(value);
      else params.type = Number(value);
    } else if (field === 7 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      params.counter = BigInt.asIntN(64, value);
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return params;
}
function scanPayload(bytes) {
  const entryRanges = [];
  let version;
  let batchSize;
  let batchIndex;
  let batchId;
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      const [length, start] = varint(bytes, pos);
      const end = start + Number(length);
      if (end > bytes.length) throw malformed("Migration payload has a truncated entry");
      entryRanges.push([start, end]);
      pos = end;
    } else if (field >= 2 && field <= 5 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      if (field === 2) version = value;
      else if (field === 3) batchSize = value;
      else if (field === 4) batchIndex = value;
      else batchId = value;
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return { entryRanges, version, batchSize, batchIndex, batchId };
}
function decodeMigrationPayload(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw malformed("Migration payload must be raw bytes");
  }
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw malformed(`Migration payload exceeds the ${MAX_PAYLOAD_BYTES} byte limit`);
  }
  const scanned = scanPayload(bytes);
  const batchSize = scanned.batchSize === void 0 ? 1 : toInt32(scanned.batchSize);
  const batchIndex = scanned.batchIndex === void 0 ? 0 : toInt32(scanned.batchIndex);
  if (batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
    throw malformed(`Migration batch size ${batchSize} is outside the allowed range 1-${MAX_BATCH_SIZE}`);
  }
  if (batchIndex < 0 || batchIndex >= batchSize) {
    throw malformed(`Migration batch index ${batchIndex} is outside the batch size ${batchSize}`);
  }
  const entries2 = scanned.entryRanges.map(([start, end]) => decodeOtpParameters(bytes.subarray(start, end)));
  return {
    entries: entries2,
    version: scanned.version === void 0 ? 0 : toInt32(scanned.version),
    batchSize,
    batchIndex,
    batchId: scanned.batchId === void 0 ? 0 : toInt32(scanned.batchId)
  };
}
function b64DecodeBytes(value) {
  if (typeof value !== "string") {
    throw malformed("Migration data must be a base64 string");
  }
  const normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (normalized.length % 4 === 1) {
    throw malformed("Migration data is not valid base64");
  }
  if (normalized.length > Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4) {
    throw malformed(`Migration data exceeds the ${MAX_PAYLOAD_BYTES} byte payload limit`);
  }
  const out = new Uint8Array(Math.ceil(normalized.length * 3 / 4));
  let outLength = 0;
  let acc = 0;
  let bits = 0;
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index);
    const decoded = code < 256 ? BASE64_LOOKUP[code] : -1;
    if (decoded === -1) {
      throw malformed("Migration data is not valid base64");
    }
    acc = acc << 6 | decoded;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outLength] = acc >>> bits & 255;
      outLength += 1;
    }
  }
  return out.subarray(0, outLength);
}
function parseMigrationUri(uri) {
  const raw = typeof uri === "string" ? uri.trim() : "";
  if (!raw.toLowerCase().startsWith("otpauth-migration://")) {
    throw new OtpVaultError("URI must be an otpauth-migration:// export URI", { code: "MIGRATION_URI_INVALID" });
  }
  const queryIndex = raw.indexOf("?");
  if (queryIndex === -1) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }
  let dataParam;
  for (const pair of raw.slice(queryIndex + 1).split("&")) {
    const equals = pair.indexOf("=");
    const key = equals === -1 ? pair : pair.slice(0, equals);
    if (key.toLowerCase() === "data") {
      dataParam = equals === -1 ? "" : pair.slice(equals + 1);
      break;
    }
  }
  if (!dataParam) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }
  let data = dataParam;
  try {
    data = decodeURIComponent(dataParam);
  } catch {
  }
  data = data.replace(/ /g, "+");
  const payloadBytes = b64DecodeBytes(data);
  const payload = decodeMigrationPayload(payloadBytes);
  const { entries: entries2, warnings } = filterMigrationEntries(payload.entries);
  return {
    entries: entries2,
    warnings,
    batch: { size: payload.batchSize, index: payload.batchIndex, id: payload.batchId },
    // Raw decoded payload bytes so multi-QR camera flows can accumulate and
    // stitch via stitchMigrationBatches without re-parsing the URI.
    payloadBytes
  };
}
function entryDisplayName(params) {
  const name = (params.name || "").trim();
  if (name) return name;
  const issuer = (params.issuer || "").trim();
  return issuer || "unnamed entry";
}
function filterMigrationEntries(rawEntries) {
  const entries2 = [];
  const warnings = [];
  for (const params of rawEntries) {
    const label = entryDisplayName(params);
    if (!params.secret.length) {
      warnings.push(`Skipped "${label}": entry has no secret`);
      continue;
    }
    if (params.algorithm === 4) {
      warnings.push(`Skipped "${label}": unsupported algorithm (MD5)`);
      continue;
    }
    if (params.algorithm > 3) {
      warnings.push(`Skipped "${label}": unsupported algorithm (code ${params.algorithm})`);
      continue;
    }
    if (params.digits > 2) {
      warnings.push(`Skipped "${label}": unsupported digits code ${params.digits}`);
      continue;
    }
    if (params.type > 2) {
      warnings.push(`Skipped "${label}": unsupported OTP type code ${params.type}`);
      continue;
    }
    if (params.counter < 0n) {
      warnings.push(`Skipped "${label}": invalid negative HOTP counter`);
      continue;
    }
    if (params.counter > MAX_SAFE_COUNTER2) {
      warnings.push(`Skipped "${label}": HOTP counter exceeds the supported range`);
      continue;
    }
    entries2.push(params);
  }
  return { entries: entries2, warnings };
}
function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function bytesToBase32(bytes) {
  let output = "";
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = acc << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[acc >>> bits - 5 & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[acc << 5 - bits & 31];
  return output;
}
function buildMigrationLabel(params) {
  const issuer = (params.issuer || "").trim();
  const name = (params.name || "").trim();
  if (!issuer) {
    const colon = name.indexOf(":");
    if (colon === -1) return name;
    const nameIssuer = name.slice(0, colon).trim();
    const account = name.slice(colon + 1).trim();
    if (!account) return nameIssuer;
    if (!nameIssuer) return account;
    return `${nameIssuer}:${account}`;
  }
  if (!name) return issuer;
  if (name.toLowerCase().startsWith(`${issuer.toLowerCase()}:`)) return name;
  return `${issuer}:${name}`;
}
function migrationToEntryCandidates(entries2) {
  const source = Array.isArray(entries2) ? entries2 : [];
  return source.map((params) => {
    const algorithm = ALGORITHM_NAMES[params.algorithm];
    if (!algorithm) {
      throw malformed(`Unsupported migration algorithm code ${params.algorithm}`);
    }
    if (params.digits !== 0 && params.digits !== 1 && params.digits !== 2) {
      throw malformed(`Unsupported migration digits code ${params.digits}`);
    }
    if (params.type !== 0 && params.type !== 1 && params.type !== 2) {
      throw malformed(`Unsupported migration OTP type code ${params.type}`);
    }
    const counter = BigInt(params.counter ?? 0n);
    if (counter < 0n || counter > MAX_SAFE_COUNTER2) {
      throw malformed("Migration HOTP counter is outside the supported range");
    }
    return {
      label: buildMigrationLabel(params),
      secret: bytesToBase32(params.secret),
      digits: params.digits === 2 ? 8 : 6,
      // QR enum: 0 unspecified, 1 = SIX, 2 = EIGHT
      period: 30,
      // the payload has no period field; GA assumes 30s
      // CRITICAL: the migration QR enum order (1 = HOTP, 2 = TOTP) is the
      // OPPOSITE of Google Authenticator's internal SQLite DB order
      // (TOTP = 0, HOTP = 1 — see Aegis GoogleAuthImporter). Never share one
      // mapping between the two formats.
      type: params.type === 1 ? "hotp" : "totp",
      counter: Number(counter),
      algorithm
    };
  });
}
function stitchMigrationBatches(payloads) {
  if (!Array.isArray(payloads)) {
    throw malformed("Migration payloads must be an array of byte arrays");
  }
  const warnings = [];
  const groups = /* @__PURE__ */ new Map();
  for (const bytes of payloads) {
    const payload = decodeMigrationPayload(bytes);
    const { entries: entries3, warnings: entryWarnings } = filterMigrationEntries(payload.entries);
    warnings.push(...entryWarnings);
    let group = groups.get(payload.batchId);
    if (!group) {
      group = { id: payload.batchId, size: payload.batchSize, scanned: /* @__PURE__ */ new Set(), buckets: /* @__PURE__ */ new Map() };
      groups.set(payload.batchId, group);
    }
    if (group.size !== payload.batchSize) {
      throw malformed("Migration payloads disagree on the batch size");
    }
    group.scanned.add(payload.batchIndex);
    if (!group.buckets.has(payload.batchIndex)) {
      group.buckets.set(payload.batchIndex, []);
    }
    group.buckets.get(payload.batchIndex).push(...entries3);
  }
  const entries2 = [];
  const batches = [];
  const seen = /* @__PURE__ */ new Set();
  let capped = false;
  outer: for (const group of groups.values()) {
    batches.push({
      id: group.id,
      size: group.size,
      scannedIndexes: [...group.scanned].sort((a, b) => a - b)
    });
    for (let index = 0; index < group.size; index += 1) {
      for (const params of group.buckets.get(index) || []) {
        if (entries2.length >= MAX_STITCHED_ENTRIES) {
          capped = true;
          break outer;
        }
        const key = `${bytesToHex(params.secret)}|${params.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries2.push(params);
      }
    }
  }
  if (capped) {
    warnings.push(`Stopped at the ${MAX_STITCHED_ENTRIES} entry limit; remaining entries were not imported`);
  }
  return { entries: entries2, warnings, batches };
}

// lib/vault.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var BACKUP_VERSION = 2;
var KDF_PARAMS_DEFAULT = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 6e5,
  hash: "SHA-256",
  saltBytes: 16
});
var KDF_PARAMS_LEGACY = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 15e4,
  hash: "SHA-256",
  saltBytes: 16
});
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
async function deriveVaultKey(passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: params.hash },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}
async function deriveVaultKeyFromPayload(payload, passphrase, cryptoApi = globalThis.crypto) {
  const normalizedPayload = validateEncryptedPayload(payload);
  return deriveVaultKey(
    normalizePassphrase(passphrase),
    fromBase64(normalizedPayload.salt),
    resolveKdfParams(normalizedPayload.kdf),
    requireCrypto(cryptoApi)
  );
}
async function decryptAndNormalize(key, normalizedPayload, safeCrypto) {
  const decrypted = await safeCrypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(normalizedPayload.iv) },
    key,
    fromBase64(normalizedPayload.data)
  );
  const parsed = JSON.parse(decoder.decode(decrypted));
  return normalizeBackupEntriesStrict(parsed, {
    message: "Decrypted vault entries are invalid",
    code: "VAULT_ENTRIES_INVALID"
  });
}
async function decryptVaultEntriesWithKey(key, payload, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    return await decryptAndNormalize(key, normalizedPayload, safeCrypto);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
function validateKdfParams(kdf) {
  if (!kdf || typeof kdf !== "object" || Array.isArray(kdf)) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  if (kdf.algorithm !== "PBKDF2" || kdf.hash !== "SHA-256") {
    throw new OtpVaultError("Encrypted data uses an unsupported KDF", { code: "VAULT_FIELDS" });
  }
  if (!Number.isInteger(kdf.iterations) || kdf.iterations <= 0) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  if (kdf.saltBytes !== void 0 && (!Number.isInteger(kdf.saltBytes) || kdf.saltBytes <= 0)) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  return kdf;
}
function resolveKdfParams(kdf) {
  if (!kdf) return KDF_PARAMS_LEGACY;
  validateKdfParams(kdf);
  if (kdf.iterations < KDF_PARAMS_LEGACY.iterations) return KDF_PARAMS_LEGACY;
  return kdf;
}
function isLegacyEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (!payload.kdf) return true;
  if (typeof payload.kdf !== "object") return true;
  return typeof payload.kdf.iterations !== "number" || payload.kdf.iterations < KDF_PARAMS_LEGACY.iterations;
}
var COMMON_PASSPHRASE_PATTERNS = [
  "password",
  "passwort",
  "passphrase",
  "123456",
  "qwerty",
  "letmein",
  "welcome",
  "iloveyou",
  "admin",
  "dragon",
  "monkey",
  "sunshine",
  "princess",
  "football",
  "master",
  "vault"
];
var STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];
var BACKUP_REMINDER_MS = 30 * 24 * 60 * 60 * 1e3;
function shouldWarnBackup(settings2, entryCount, now = Date.now()) {
  if (!Number.isInteger(entryCount) || entryCount < 1) return false;
  const lastBackupAt = Number(settings2?.lastBackupAt);
  if (!Number.isFinite(lastBackupAt) || lastBackupAt <= 0) return true;
  return now - lastBackupAt > BACKUP_REMINDER_MS;
}
function assessPassphraseStrength(passphrase) {
  const value = String(passphrase || "");
  if (value.length === 0) {
    return { score: 0, label: STRENGTH_LABELS[0], warnings: ["Enter a passphrase"] };
  }
  let score = 0;
  if (value.length >= 8) score = 1;
  if (value.length >= 12) score = 2;
  const characterClasses = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(value)).length;
  if (characterClasses >= 3) score += 1;
  if (characterClasses >= 4) score += 1;
  const warnings = [];
  if (COMMON_PASSPHRASE_PATTERNS.some((pattern) => value.toLowerCase().includes(pattern))) {
    score = Math.max(0, score - 2);
    warnings.push("Avoid common words and patterns");
  }
  if (value.length < 12) {
    warnings.push("Use at least 12 characters for a stronger passphrase");
  }
  score = Math.min(4, score);
  return { score, label: STRENGTH_LABELS[score], warnings };
}
async function encryptEntries(entries2, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, KDF_PARAMS_DEFAULT, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...KDF_PARAMS_DEFAULT }
  };
}
function validateEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Encrypted data is missing or invalid", { code: "VAULT_INVALID" });
  }
  if (typeof payload.salt !== "string" || typeof payload.iv !== "string" || typeof payload.data !== "string") {
    throw new OtpVaultError("Encrypted data is missing required fields", { code: "VAULT_FIELDS" });
  }
  if (payload.kdf !== void 0) {
    validateKdfParams(payload.kdf);
  }
  if (payload.dek !== void 0) {
    const dek = payload.dek;
    if (!dek || typeof dek !== "object" || typeof dek.wrapped !== "string" || typeof dek.iv !== "string") {
      throw new OtpVaultError("Encrypted data has an invalid dek block", { code: "VAULT_FIELDS" });
    }
  }
  return payload;
}
function isDekEncryptedPayload(payload) {
  return Boolean(payload && typeof payload === "object" && payload.kdf && typeof payload.kdf === "object" && payload.kdf.mode === "dek-v1" && payload.dek && typeof payload.dek === "object");
}
async function unwrapDekWithPassphrase(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPayload = validateEncryptedPayload(payload);
  if (!isDekEncryptedPayload(normalizedPayload)) {
    throw new OtpVaultError("Encrypted data does not contain a DEK envelope", { code: "VAULT_FIELDS" });
  }
  try {
    const wrapKey = await deriveVaultKey(
      normalizePassphrase(passphrase),
      fromBase64(normalizedPayload.salt),
      resolveKdfParams(normalizedPayload.kdf),
      safeCrypto
    );
    return await safeCrypto.subtle.unwrapKey(
      "raw",
      fromBase64(normalizedPayload.dek.wrapped),
      wrapKey,
      { name: "AES-GCM", iv: fromBase64(normalizedPayload.dek.iv) },
      { name: "AES-GCM", length: 256 },
      // extractable + wrapKey: passphrase change (FR11) and re-enrollment must
      // re-wrap this DEK after a reload; it is never exported to storage.
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
async function wrapDekWithPassphrase(dek, passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const wrapKey = await deriveVaultKey(normalizePassphrase(passphrase), salt, params, safeCrypto);
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const wrapped = await safeCrypto.subtle.wrapKey("raw", dek, wrapKey, { name: "AES-GCM", iv });
  return { wrapped: toBase64(new Uint8Array(wrapped)), iv: toBase64(iv) };
}
async function generateVaultDek(cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  return safeCrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
}
async function encryptEntriesWithDek(entries2, dek, envelopeMeta, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const { salt, kdf, dek: dekBlock } = envelopeMeta || {};
  if (typeof salt !== "string" || !kdf || !dekBlock) {
    throw new OtpVaultError("A DEK-mode envelope meta block is required", { code: "VAULT_FIELDS" });
  }
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, payload);
  return {
    salt,
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...kdf, mode: "dek-v1" },
    dek: { ...dekBlock }
  };
}
function hasRequiredBackupSecret(secret) {
  if (typeof secret !== "string") return false;
  const normalizedSecret = sanitizeBase32(secret);
  if (!normalizedSecret) return false;
  try {
    return base32ToBytes(normalizedSecret).length > 0;
  } catch {
    return false;
  }
}
function hasRequiredBackupEntryShape(entry) {
  return Boolean(entry) && typeof entry === "object" && typeof entry.id === "string" && entry.id.trim().length > 0 && typeof entry.label === "string" && entry.label.trim().length > 0 && hasRequiredBackupSecret(entry.secret) && Number.isInteger(entry.digits) && Number.isInteger(entry.period) && typeof entry.createdAt === "number" && Number.isFinite(entry.createdAt);
}
function normalizeBackupEntriesStrict(entries2, { message, code }) {
  if (!Array.isArray(entries2) || !entries2.every(hasRequiredBackupEntryShape)) {
    throw new OtpVaultError(message, { code });
  }
  const normalizedEntries = normalizeEntries(entries2);
  if (normalizedEntries.length !== entries2.length) {
    throw new OtpVaultError(message, { code });
  }
  return normalizedEntries;
}
async function decryptVaultEntries(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    if (isDekEncryptedPayload(normalizedPayload)) {
      const dek = await unwrapDekWithPassphrase(normalizedPayload, normalizedPassphrase, safeCrypto);
      return await decryptAndNormalize(dek, normalizedPayload, safeCrypto);
    }
    const key = await deriveVaultKey(
      normalizedPassphrase,
      fromBase64(normalizedPayload.salt),
      resolveKdfParams(normalizedPayload.kdf),
      safeCrypto
    );
    return await decryptAndNormalize(key, normalizedPayload, safeCrypto);
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

// lib/biometric.js
var encoder2 = new TextEncoder();
var RP_NAME = "Personal OTP Vault";
var USER_NAME = "otp-vault";
var KEK_INFO = encoder2.encode("2fa-vault-kek-v1");
var CEREMONY_TIMEOUT_MS = 6e4;
var CHALLENGE_BYTES = 32;
var USER_ID_BYTES = 16;
var PRF_SALT_BYTES = 32;
var DEK_BYTES = 32;
function defaultCredentialsApi() {
  return globalThis.navigator?.credentials;
}
function requireCrypto2(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}
function requireCredentials(credentialsApi, method) {
  if (!credentialsApi || typeof credentialsApi[method] !== "function") {
    throw new OtpVaultError("WebAuthn is unavailable in this context", { code: "BIOMETRIC_UNSUPPORTED" });
  }
  return credentialsApi;
}
function randomBytes(length, cryptoApi) {
  return requireCrypto2(cryptoApi).getRandomValues(new Uint8Array(length));
}
function toRawBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}
function toB64u(bytes) {
  if (!ArrayBuffer.isView(bytes)) {
    throw new OtpVaultError("Base64url encoding expects bytes", { code: "BIOMETRIC_INVALID_STATE" });
  }
  return toRawBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64u(value) {
  try {
    if (typeof value !== "string") {
      throw new TypeError("base64url input must be a string");
    }
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const bytes = typeof Buffer !== "undefined" ? new Uint8Array(Buffer.from(padded, "base64")) : Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    if (toB64u(bytes) !== value) {
      throw new Error("value is not canonical base64url");
    }
    return bytes;
  } catch (error) {
    throw new OtpVaultError("Value is not valid base64url", { code: "BIOMETRIC_INVALID_STATE", cause: error });
  }
}
async function prfCapable({
  credentialsApi = defaultCredentialsApi(),
  publicKeyCredential = globalThis.PublicKeyCredential
} = {}) {
  if (!credentialsApi || typeof publicKeyCredential !== "function") {
    return false;
  }
  let platformAuthenticatorAvailable = false;
  try {
    platformAuthenticatorAvailable = await publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    platformAuthenticatorAvailable = false;
  }
  if (!platformAuthenticatorAvailable) {
    return false;
  }
  try {
    if (typeof publicKeyCredential.getClientCapabilities !== "function") {
      return true;
    }
    const capabilities = await publicKeyCredential.getClientCapabilities();
    return capabilities?.prf === true;
  } catch {
    return true;
  }
}
function mapCeremonyError(error) {
  if (error instanceof OtpVaultError) return error;
  if (error?.name === "NotAllowedError") {
    return new OtpVaultError("Biometric verification was cancelled or blocked \u2014 use the passphrase to unlock", {
      code: "BIOMETRIC_NOT_ALLOWED",
      cause: error
    });
  }
  if (error?.name === "InvalidStateError") {
    return new OtpVaultError("The authenticator is in an invalid state \u2014 use the passphrase to unlock", {
      code: "BIOMETRIC_INVALID_STATE",
      cause: error
    });
  }
  if (error?.name === "NotSupportedError") {
    return new OtpVaultError("This authenticator does not support PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED",
      cause: error
    });
  }
  return new OtpVaultError("WebAuthn ceremony failed", { code: "BIOMETRIC_CEREMONY_FAILED", cause: error });
}
async function runCreateCeremony({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "create");
  const safeCrypto = requireCrypto2(cryptoApi);
  const publicKey = {
    challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
    rp: { name: RP_NAME, id: rpId },
    user: {
      id: randomBytes(USER_ID_BYTES, safeCrypto),
      name: USER_NAME
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 }
    ],
    authenticatorSelection: {
      userVerification: "required",
      residentKey: "preferred"
    },
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: "none",
    extensions: { prf: {} }
  };
  let credential;
  try {
    credential = await safeCredentials.create({ publicKey });
  } catch (error) {
    throw mapCeremonyError(error);
  }
  const extensionResults = credential?.getClientExtensionResults?.() ?? {};
  if (extensionResults.prf?.enabled !== true) {
    throw new OtpVaultError("This authenticator cannot provide PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED"
    });
  }
  if (!credential.rawId) {
    throw new OtpVaultError("The authenticator did not return a credential", {
      code: "BIOMETRIC_CEREMONY_FAILED"
    });
  }
  return { credentialId: toB64u(new Uint8Array(credential.rawId)) };
}
async function runAssertCeremony({
  credentialId,
  prfSalt,
  credentialsApi = defaultCredentialsApi(),
  allowEvalFallback = true,
  rpId,
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "get");
  const safeCrypto = requireCrypto2(cryptoApi);
  if (!credentialId || typeof credentialId !== "string") {
    throw new OtpVaultError("No biometric credential is enrolled", { code: "BIOMETRIC_INVALID_STATE" });
  }
  if (!ArrayBuffer.isView(prfSalt) || prfSalt.byteLength === 0) {
    throw new OtpVaultError("The stored PRF salt is missing", { code: "BIOMETRIC_INVALID_STATE" });
  }
  const idBytes = fromB64u(credentialId);
  const salts = { first: prfSalt };
  const buildOptions = (extensions) => {
    const publicKey = {
      challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
      allowCredentials: [{ id: idBytes, type: "public-key" }],
      userVerification: "required",
      timeout: CEREMONY_TIMEOUT_MS,
      extensions
    };
    if (rpId !== void 0) {
      publicKey.rpId = rpId;
    }
    return { publicKey };
  };
  let assertion;
  try {
    assertion = await safeCredentials.get(buildOptions({
      prf: { evalByCredential: { [credentialId]: salts } }
    }));
  } catch (error) {
    if (!allowEvalFallback || error?.name !== "NotSupportedError") {
      throw mapCeremonyError(error);
    }
    try {
      assertion = await safeCredentials.get(buildOptions({ prf: { eval: salts } }));
    } catch (retryError) {
      throw mapCeremonyError(retryError);
    }
  }
  const extensionResults = assertion?.getClientExtensionResults?.() ?? {};
  const first = extensionResults.prf?.results?.first;
  if (!first) {
    throw new OtpVaultError("The authenticator did not return PRF output", {
      code: "BIOMETRIC_UNSUPPORTED"
    });
  }
  return { credentialId, prfOutput: new Uint8Array(first) };
}
async function deriveKek(prfOutput, prfSalt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    if (!ArrayBuffer.isView(prfOutput) || prfOutput.byteLength < 16) {
      throw new Error("PRF output must be at least 16 bytes");
    }
    const ikm = await safeCrypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
    return await safeCrypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: prfSalt, info: KEK_INFO },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not derive the biometric unlock key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function wrapDek(dek, kek, iv, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    if (!ArrayBuffer.isView(dek) || dek.byteLength !== DEK_BYTES) {
      throw new Error("The vault key must be 256 bits");
    }
    const dekKey = await safeCrypto.subtle.importKey("raw", dek, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    const wrapped = await safeCrypto.subtle.wrapKey("raw", dekKey, kek, { name: "AES-GCM", iv });
    return new Uint8Array(wrapped);
  } catch (error) {
    throw new OtpVaultError("Could not wrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function unwrapDek(wrapped, iv, kek, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto2(cryptoApi);
  try {
    return await safeCrypto.subtle.unwrapKey(
      "raw",
      wrapped,
      kek,
      { name: "AES-GCM", iv },
      { name: "AES-GCM", length: 256 },
      // extractable + wrapKey so re-enrollment can re-wrap the held DEK under
      // a new KEK; raw bytes never leave memory and are never persisted.
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not unwrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error
    });
  }
}
async function enrollBiometricUnlock({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto
} = {}) {
  const safeCrypto = requireCrypto2(cryptoApi);
  const { credentialId } = await runCreateCeremony({ rpId, credentialsApi, cryptoApi: safeCrypto });
  const prfSalt = randomBytes(PRF_SALT_BYTES, safeCrypto);
  const { prfOutput } = await runAssertCeremony({
    credentialId,
    prfSalt,
    credentialsApi,
    rpId,
    cryptoApi: safeCrypto
  });
  return { credentialId, prfSalt, firstPrfOutput: prfOutput };
}

// extension/popup.js
var STORAGE_KEY = "otp_extension_entries_v3";
var LEGACY_STORAGE_KEY = "otp_extension_entries_v2";
var ENCRYPTED_KEY = "otp_extension_encrypted_v1";
var BIOMETRIC_KEY = "otp_extension_biometric_v1";
var SETTINGS_KEY = "otp_extension_settings_v1";
var UI_KEY = "otp_extension_ui_v1";
var SESSION_UNLOCK_KEY = "otp_extension_session_unlock_v1";
var UNLOCK_GUARD_KEY = "otp_extension_unlock_guard_v1";
var UNDO_TOMBSTONE_KEY = "otp_extension_undo_tombstone_v1";
var UNDO_TOMBSTONE_TTL_MS = 10 * 60 * 1e3;
var UNDO_TOAST_MS = 1e4;
var form = document.getElementById("entry-form");
var labelInput = document.getElementById("label");
var secretInput = document.getElementById("secret");
var tagsInput = document.getElementById("tags");
var digitsInput = document.getElementById("digits");
var periodInput = document.getElementById("period");
var entryTypeSelect = document.getElementById("entry-type");
var counterInput = document.getElementById("counter");
var algorithmSelect = document.getElementById("algorithm");
var qrFileInput = document.getElementById("qr-file");
var searchInput = document.getElementById("search");
var sortSelect = document.getElementById("sort-select");
var pasteUriBtn = document.getElementById("paste-uri");
var toggleFormBtn = document.getElementById("toggle-form");
var lockBtn = document.getElementById("lock-btn");
var statusNode = document.getElementById("status");
var entriesRoot = document.getElementById("entries");
var globalSeconds = document.getElementById("global-seconds");
var globalBar = document.getElementById("global-bar");
var template = document.getElementById("entry-template");
var unlockPanel = document.getElementById("unlock-panel");
var unlockPassphraseInput = document.getElementById("unlock-passphrase");
var unlockBtn = document.getElementById("unlock-btn");
var unlockStatus = document.getElementById("unlock-status");
var encryptToggle = document.getElementById("encrypt-toggle");
var passphraseFields = document.getElementById("passphrase-fields");
var passphraseGuidance = document.getElementById("passphrase-guidance");
var passphraseInput = document.getElementById("passphrase");
var passphraseConfirmInput = document.getElementById("passphrase-confirm");
var changePassphraseBtn = document.getElementById("change-passphrase-btn");
var changePassphraseForm = document.getElementById("change-passphrase-form");
var currentPassphraseInput = document.getElementById("current-passphrase");
var newPassphraseInput = document.getElementById("new-passphrase");
var newPassphraseConfirmInput = document.getElementById("new-passphrase-confirm");
var saveSecurityBtn = document.getElementById("save-security");
var copyHistoryRoot = document.getElementById("copy-history");
var unlockForm = document.getElementById("unlock-form");
var securityForm = document.getElementById("security-form");
var editEntryForm = document.getElementById("edit-entry-form");
var editEntryDialog = document.getElementById("edit-entry-dialog");
var editEntryIdInput = document.getElementById("edit-entry-id");
var editLabelInput = document.getElementById("edit-label");
var editSecretInput = document.getElementById("edit-secret");
var editTagsInput = document.getElementById("edit-tags");
var editDigitsInput = document.getElementById("edit-digits");
var editPeriodInput = document.getElementById("edit-period");
var editCounterInput = document.getElementById("edit-counter");
var editAlgorithmSelect = document.getElementById("edit-algorithm");
var editStatus = document.getElementById("edit-status");
var cancelEditBtn = document.getElementById("cancel-edit");
var saveEditBtn = document.getElementById("save-edit");
var confirmRemoveDialog = document.getElementById("confirm-remove-dialog");
var confirmRemoveMessage = document.getElementById("confirm-remove-message");
var pasteGaBtn = document.getElementById("paste-ga");
var exportBackupBtn = document.getElementById("export-backup");
var migrationPreviewDialog = document.getElementById("migration-preview-dialog");
var migrationPreviewForm = document.getElementById("migration-preview-form");
var migrationPreviewStatus = document.getElementById("migration-preview-status");
var migrationPreviewList = document.getElementById("migration-preview-list");
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var collapsed = false;
var settings = { encrypt: false, sortBy: "alpha", theme: "system" };
var currentPassphrase = "";
var heldDek = null;
var dekEnvelopeMeta = null;
var biometricCapable = false;
var copyHistory = [];
var confirmRemoveCallback = null;
var lastActivity = Date.now();
var migrationPreviewState = null;
var undoTombstone = null;
function applyTheme() {
  const theme = settings.theme || "system";
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}
function applyStaticStrings() {
  const set = (id, key) => {
    const node = document.getElementById(id);
    if (node) node.textContent = t(key);
  };
  const setPlaceholder = (id, key) => {
    const node = document.getElementById(id);
    if (node) node.setAttribute("placeholder", t(key));
  };
  set("unlock-btn", "unlock.extensionButton");
  set("export-backup", "settings.exportBackup");
  set("change-passphrase-btn", "settings.changePassphrase");
  set("save-security", "settings.extensionSave");
  setPlaceholder("unlock-passphrase", "unlock.extensionPassphrasePlaceholder");
  setPlaceholder("passphrase", "settings.extensionPassphrasePlaceholder");
  setPlaceholder("passphrase-confirm", "settings.extensionPassphraseConfirmPlaceholder");
  const guidance = document.getElementById("passphrase-guidance");
  if (guidance) guidance.textContent = t("settings.extensionPassphraseGuidance");
}
initialize();
async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, sortBy: "alpha", autoLockMinutes: 15, timeDriftCheck: false, ...stored[SETTINGS_KEY] || {} };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
  const autoLockSelect = document.getElementById("auto-lock-select");
  if (autoLockSelect) autoLockSelect.value = String(settings.autoLockMinutes ?? 15);
  const timeDriftToggle = document.getElementById("time-drift-toggle");
  if (timeDriftToggle) timeDriftToggle.checked = Boolean(settings.timeDriftCheck);
  const themeSelect = document.getElementById("theme-select");
  if (themeSelect) themeSelect.value = settings.theme || "system";
  applyTheme();
  const hasExistingEncryptedVault = Boolean(settings.encrypt && stored[ENCRYPTED_KEY]);
  passphraseFields.classList.toggle("hidden", !settings.encrypt || hasExistingEncryptedVault);
  passphraseGuidance?.classList.toggle("hidden", !hasExistingEncryptedVault);
  applyUiState();
  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    const cached = await readSessionUnlock(stored[ENCRYPTED_KEY]);
    if (cached) {
      entries = cached.entries;
      currentPassphrase = cached.passphrase;
      if (isDekEncryptedPayload(stored[ENCRYPTED_KEY])) {
        heldDek = cached.keyHandle;
        dekEnvelopeMeta = extractDekEnvelopeMeta(stored[ENCRYPTED_KEY]);
      }
      if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
      setLocked(false);
      await offerUndoFromTombstone();
    } else {
      setLocked(true);
    }
  } else {
    const rawEntries = stored[STORAGE_KEY] ?? stored[LEGACY_STORAGE_KEY];
    entries = normalizeEntries(rawEntries);
    if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
    setLocked(false);
    await offerUndoFromTombstone();
  }
  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    await reconcileOrphanedBiometricRecord();
  }
  applyStaticStrings();
  bindEvents();
  bindPassphraseStrengthMeters();
  bindAutoLockActivity();
  renderEntries();
  renderCopyHistory();
  renderBackupReminder();
  renderBiometricControls();
  tick();
  setInterval(tick, 1e3);
  prfCapable().then((capable) => {
    biometricCapable = capable;
    renderBiometricControls();
  }).catch(() => {
    biometricCapable = false;
    renderBiometricControls();
  });
}
async function readSessionUnlock(encryptedPayload) {
  try {
    const cached = (await chrome.storage.session.get(SESSION_UNLOCK_KEY))[SESSION_UNLOCK_KEY];
    if (!cached || !cached.keyHandle || typeof cached.passphrase !== "string") return null;
    const entriesDecrypted = await decryptVaultEntriesWithKey(cached.keyHandle, encryptedPayload);
    return { entries: entriesDecrypted, passphrase: cached.passphrase, keyHandle: cached.keyHandle };
  } catch (error) {
    reportError("Session unlock cache miss or invalid", error);
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
    return null;
  }
}
async function writeSessionUnlock(encryptedPayload, passphrase, keyHandle) {
  try {
    await chrome.storage.session.set({ [SESSION_UNLOCK_KEY]: { passphrase, keyHandle } });
  } catch (error) {
    reportError("Session unlock cache write failed", error);
  }
}
async function clearSessionUnlock() {
  try {
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
  } catch (error) {
    reportError("Session unlock cache clear failed", error);
  }
}
function bytesToBase64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function base64ToBytes(value) {
  const text = atob(value);
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i);
  return bytes;
}
async function readBiometricRecord() {
  try {
    const stored = await chrome.storage.local.get(BIOMETRIC_KEY);
    const record = stored[BIOMETRIC_KEY];
    if (!record || typeof record.credentialId !== "string" || typeof record.prfSalt !== "string" || typeof record.wrappedDek !== "string" || typeof record.wrappedIv !== "string") {
      return null;
    }
    return record;
  } catch (error) {
    reportError("Failed to read biometric record", error);
    return null;
  }
}
async function writeBiometricRecord(record) {
  await chrome.storage.local.set({ [BIOMETRIC_KEY]: record });
}
async function removeBiometricRecord() {
  await chrome.storage.local.remove(BIOMETRIC_KEY);
}
function extractDekEnvelopeMeta(payload) {
  if (!isDekEncryptedPayload(payload)) return null;
  return { salt: payload.salt, kdf: { ...payload.kdf }, dek: { ...payload.dek } };
}
async function exportDekRawBytes(dek) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", dek));
}
async function reconcileOrphanedBiometricRecord() {
  const record = await readBiometricRecord();
  if (!record) return;
  let payload = null;
  try {
    const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
    payload = stored[ENCRYPTED_KEY] ?? null;
  } catch {
    payload = null;
  }
  if (isDekEncryptedPayload(payload)) return;
  await removeBiometricRecord();
  renderBiometricControls();
}
async function requirePassphrase(actionLabel) {
  if (currentPassphrase) return currentPassphrase;
  if (!heldDek) return "";
  const candidate = window.prompt(`Enter your vault passphrase to ${actionLabel}:`);
  if (!candidate) throw new Error("Vault passphrase required for this action");
  const normalized = normalizePassphrase(candidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    throw new Error("Vault passphrase required for this action");
  }
  heldDek = await unwrapDekWithPassphrase(payload, normalized);
  dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  currentPassphrase = normalized;
  await writeSessionUnlock(payload, normalized, heldDek);
  return currentPassphrase;
}
function releasePassphrase(previousPassphrase) {
  if (!previousPassphrase) currentPassphrase = "";
}
async function refreshSessionCacheForDek(payload) {
  if (!heldDek) return;
  await writeSessionUnlock(payload, currentPassphrase, heldDek);
}
function applyUiState() {
  document.body.classList.toggle("collapsed", collapsed);
  toggleFormBtn.textContent = collapsed ? "Show" : "Hide";
}
async function saveUiState() {
  await chrome.storage.local.set({ [UI_KEY]: { collapsed } });
}
function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success");
  if (tone) node.classList.add(tone);
}
function setMainStatus(message, tone = "") {
  setStatus(statusNode, message, tone);
}
function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}
function lockVault() {
  currentPassphrase = "";
  heldDek = null;
  dekEnvelopeMeta = null;
  if (unlockPassphraseInput) unlockPassphraseInput.value = "";
  setUnlockStatus("");
  entries = [];
  if (settings.clearClipboard) {
    copyHistory = [];
    renderCopyHistory();
  }
  clearSessionUnlock();
  undoTombstone = null;
  purgeUndoTombstone();
  setLocked(true);
  renderEntries();
}
function noteActivity() {
  lastActivity = Date.now();
}
function bindAutoLockActivity() {
  let lastNoted = 0;
  const throttled = () => {
    const now = Date.now();
    if (now - lastNoted < 1e3) return;
    lastNoted = now;
    noteActivity();
  };
  document.addEventListener("pointermove", throttled);
  document.addEventListener("keydown", throttled);
}
async function readUnlockGuard() {
  try {
    const stored = await chrome.storage.local.get(UNLOCK_GUARD_KEY);
    const parsed = stored[UNLOCK_GUARD_KEY];
    return { attempts: Number(parsed?.attempts) || 0, lockedUntil: Number(parsed?.lockedUntil) || 0 };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}
function writeUnlockGuard(guard) {
  return chrome.storage.local.set({ [UNLOCK_GUARD_KEY]: guard });
}
function unlockBackoffSeconds(attempts) {
  return Math.min(60, 2 ** Math.max(0, attempts - 3));
}
function collectMigrationPayloads(rawText) {
  const uris = extractMigrationUris(rawText);
  if (uris.length === 0) return { payloads: [], warnings: [] };
  const payloads = [];
  const warnings = [];
  for (const uri of uris) {
    try {
      payloads.push(parseMigrationUri(uri).payloadBytes);
    } catch (error) {
      warnings.push(toUserMessage(error, "A migration QR could not be read"));
    }
  }
  return { payloads, warnings };
}
function stageMigrationPayloads(payloadByteArrays, sourceLabel) {
  const stitched = stitchMigrationBatches(payloadByteArrays);
  const warnings = [...stitched.warnings];
  if (stitched.entries.length === 0) {
    throw new Error(`No importable entries found in the ${sourceLabel} export${warnings.length ? `: ${warnings.join(" ")}` : ""}`);
  }
  const candidates = [];
  let skipped = 0;
  let invalid = 0;
  for (const params of stitched.entries) {
    try {
      const candidate = migrationToEntryCandidates([params])[0];
      const entry = normalizeEntry(candidate);
      if (hasDuplicateEntry(entries, entry) || candidates.some((existing) => existing.secret === entry.secret && existing.label === entry.label)) {
        candidates.push({ ...entry, duplicateHint: true });
        skipped += 1;
        continue;
      }
      candidates.push(entry);
    } catch (error) {
      invalid += 1;
      warnings.push(toUserMessage(error, "An entry could not be mapped"));
    }
  }
  openMigrationPreview({ candidates, skipped, invalid, warnings, sourceLabel });
}
function openMigrationPreview(previewResult) {
  migrationPreviewState = previewResult;
  renderMigrationPreview();
  migrationPreviewDialog?.showModal?.();
}
function renderMigrationPreview() {
  if (!migrationPreviewState || !migrationPreviewList) return;
  const { candidates, skipped, invalid, warnings, sourceLabel } = migrationPreviewState;
  let statusText = `${sourceLabel}: ${candidates.length} entr${candidates.length === 1 ? "y" : "ies"} found.`;
  if (skipped > 0) statusText += ` ${skipped} duplicate${skipped === 1 ? "" : "s"} pre-unchecked.`;
  if (invalid > 0) statusText += ` ${invalid} could not be mapped.`;
  if (warnings.length > 0) statusText += ` ${warnings.join(" ")}`;
  migrationPreviewStatus.textContent = statusText;
  migrationPreviewList.innerHTML = "";
  candidates.forEach((entry, index) => {
    const row = document.createElement("label");
    row.className = "toggle-row";
    row.dataset.index = String(index);
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "migration-include";
    checkbox.checked = !entry.duplicateHint;
    const summaryParts = [entry.label, `${entry.digits} digits`];
    if (entry.type === "hotp") summaryParts.push(`HOTP #${entry.counter}`);
    if (entry.algorithm && entry.algorithm !== "SHA1") summaryParts.push(entry.algorithm.replace(/^SHA/, "SHA-"));
    const text = document.createElement("span");
    text.textContent = entry.duplicateHint ? `${summaryParts.join(" \u2022 ")} (already in vault)` : summaryParts.join(" \u2022 ");
    row.append(checkbox, text);
    migrationPreviewList.appendChild(row);
  });
}
async function commitMigrationPreview() {
  if (!migrationPreviewState) return;
  const rows = [...migrationPreviewList.querySelectorAll(".toggle-row")];
  const nextOrder = nextOrderValueFrom(entries);
  const selected = rows.flatMap((row, index) => {
    const checkbox = row.querySelector(".migration-include");
    if (!checkbox?.checked) return [];
    const candidate = migrationPreviewState.candidates[index];
    return [normalizeEntry({ ...candidate, order: nextOrder + index })];
  });
  if (selected.length === 0) throw new Error("Select at least one entry to import");
  await replaceEntries([...entries, ...selected]);
  migrationPreviewState = null;
}
async function writeUndoTombstone(items) {
  try {
    if (!settings.encrypt) {
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes: items.map((item) => item.index), entries: items.map((item) => item.entry) }
      });
      return;
    }
    const indexes = items.map((item) => item.index);
    const deletedEntries = items.map((item) => item.entry);
    if (currentPassphrase) {
      const vault = await encryptEntries(deletedEntries, currentPassphrase);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, vault }
      });
      return;
    }
    if (heldDek && dekEnvelopeMeta) {
      const dekVault = await encryptEntriesWithDek(deletedEntries, heldDek, dekEnvelopeMeta);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, dekVault }
      });
    }
  } catch (error) {
    reportError("Undo tombstone write failed", error);
  }
}
async function purgeUndoTombstone() {
  await chrome.storage.local.remove(UNDO_TOMBSTONE_KEY);
}
async function readLiveUndoTombstone() {
  try {
    const stored = await chrome.storage.local.get(UNDO_TOMBSTONE_KEY);
    const tombstone = stored[UNDO_TOMBSTONE_KEY];
    if (!tombstone || typeof tombstone.at !== "number" || Date.now() - tombstone.at > UNDO_TOMBSTONE_TTL_MS) {
      await purgeUndoTombstone();
      return null;
    }
    let deletedEntries = tombstone.entries || [];
    if (tombstone.dekVault) {
      if (!heldDek) {
        await purgeUndoTombstone();
        return null;
      }
      deletedEntries = await decryptVaultEntriesWithKey(heldDek, tombstone.dekVault);
    } else if (tombstone.vault) {
      deletedEntries = await decryptVaultEntries(tombstone.vault, currentPassphrase);
    }
    if (!Array.isArray(deletedEntries) || deletedEntries.length === 0) {
      await purgeUndoTombstone();
      return null;
    }
    const indexes = Array.isArray(tombstone.indexes) ? tombstone.indexes : [];
    return deletedEntries.map((entry, position) => ({ entry, index: indexes[position] ?? position }));
  } catch (error) {
    reportError("Undo tombstone read failed", error);
    await purgeUndoTombstone();
    return null;
  }
}
async function undoDelete(items) {
  undoTombstone = null;
  await purgeUndoTombstone();
  let reinserted = 0;
  const nextEntries = [...entries];
  for (const { entry, index } of items) {
    if (nextEntries.some((existing) => existing.id === entry.id)) continue;
    nextEntries.splice(Math.min(Math.max(index, 0), nextEntries.length), 0, entry);
    reinserted += 1;
  }
  if (reinserted === 0) {
    setMainStatus("Nothing to undo \u2014 those entries already exist again", "warning");
    return;
  }
  await replaceEntries(nextEntries);
  setMainStatus(`Restored ${reinserted} entr${reinserted === 1 ? "y" : "ies"}`, "success");
}
async function offerUndoDelete(items) {
  await writeUndoTombstone(items);
  undoTombstone = items;
  setMainStatus(`${items.length === 1 ? "Entry removed" : `${items.length} entries removed`} \u2014 reopening this popup offers Undo for 10 minutes`, "warning");
  setTimeout(async () => {
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOAST_MS);
}
async function offerUndoFromTombstone() {
  if (undoTombstone || !unlockPanel.classList.contains("hidden")) return;
  const items = await readLiveUndoTombstone();
  if (!items) return;
  undoTombstone = items;
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = items.length === 1 ? "An entry was deleted before this popup closed. Undo?" : `${items.length} entries were deleted before this popup closed. Undo?`;
  status.classList.add("error");
  const undoBtn = document.createElement("button");
  undoBtn.type = "button";
  undoBtn.className = "ghost-btn";
  undoBtn.textContent = "Undo delete";
  undoBtn.addEventListener("click", async () => {
    undoBtn.remove();
    await undoDelete(items);
  });
  status.appendChild(document.createElement("br"));
  status.appendChild(undoBtn);
  setTimeout(async () => {
    undoBtn.remove();
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOMBSTONE_TTL_MS);
}
function parseTraceTimestamp(text) {
  const match = /(?:^|\n)ts=([0-9.]+)/.exec(text || "");
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds * 1e3 : null;
}
async function stampBackupExport(envelope) {
  settings.lastBackupAt = Date.now();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(envelope.payload)));
  settings.lastBackupHash = [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
  await persistSettings();
}
async function exportBackup() {
  const previousPassphrase = currentPassphrase;
  await requirePassphrase("export a backup");
  try {
    let envelope;
    if (settings.encrypt) {
      if (!currentPassphrase) throw new Error("Unlock the extension vault before exporting an encrypted backup");
      const encryptedPayload = await encryptEntries(entries, currentPassphrase);
      envelope = await createEncryptedBackup(encryptedPayload);
    } else {
      envelope = await createPlainBackup(entries);
    }
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "otp-vault-extension-backup.json";
    link.click();
    URL.revokeObjectURL(url);
    await stampBackupExport(envelope);
  } finally {
    releasePassphrase(previousPassphrase);
  }
}
function renderBackupReminder() {
  const line = document.getElementById("last-export-line");
  if (!line) return;
  if (shouldWarnBackup(settings, entries.length)) {
    line.textContent = settings.lastBackupAt ? "No export in over 30 days \u2014 export a backup below." : entries.length > 0 ? "No export yet \u2014 back this vault up below." : "";
    line.classList.remove("hidden");
    return;
  }
  const days = Math.floor((Date.now() - Number(settings.lastBackupAt)) / 864e5);
  line.textContent = `Last export: ${days === 0 ? "today" : `${days} day${days === 1 ? "" : "s"} ago`} (checksum ${String(settings.lastBackupHash || "").slice(0, 8)}). A cancelled download cannot be detected.`;
}
async function checkTimeDrift() {
  if (!settings.timeDriftCheck) return;
  try {
    const response = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
    const serverMs = parseTraceTimestamp(await response.text());
    const skewMs = Number.isFinite(serverMs) ? Math.abs(Date.now() - serverMs) : null;
    const banner = document.getElementById("drift-banner");
    if (banner) {
      const skewMs2 = skewMs;
      banner.querySelector("#drift-skew").textContent = skewMs2 !== null ? `${(skewMs2 / 1e3).toFixed(1)}s` : "";
      banner.classList.toggle("hidden", !(skewMs2 !== null && skewMs2 > 5e3));
    }
  } catch (error) {
    reportError("Extension time drift check skipped", error);
    document.getElementById("drift-banner")?.classList.add("hidden");
  }
}
function renderPassphraseStrength(input, meterRoot) {
  if (!input || !meterRoot) return;
  const assessment = assessPassphraseStrength(input.value);
  meterRoot.classList.toggle("hidden", input.value.length === 0);
  const fill = meterRoot.querySelector(".strength-fill");
  if (fill) fill.dataset.score = String(assessment.score);
  const label = meterRoot.querySelector(".strength-label");
  if (label) label.textContent = assessment.label;
  const warnings = meterRoot.querySelector(".strength-warnings");
  if (warnings) warnings.textContent = assessment.warnings.join(" ");
}
function bindPassphraseStrengthMeters() {
  const unlockMeter = document.getElementById("unlock-passphrase-strength");
  const setMeter = document.getElementById("set-passphrase-strength");
  unlockPassphraseInput?.addEventListener("input", () => renderPassphraseStrength(unlockPassphraseInput, unlockMeter));
  passphraseInput?.addEventListener("input", () => renderPassphraseStrength(passphraseInput, setMeter));
  passphraseConfirmInput?.addEventListener("input", () => renderPassphraseStrength(passphraseConfirmInput, setMeter));
}
async function changeVaultPassphrase(currentPassphraseCandidate, nextPassphraseCandidate, confirmPassphraseCandidate) {
  if (!settings.encrypt) {
    throw new Error("Enable encrypted storage before changing the extension passphrase");
  }
  const previousPassphrase = currentPassphrase;
  if (!previousPassphrase) {
    await requirePassphrase("change the extension passphrase");
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    releasePassphrase(previousPassphrase);
    throw new Error("Current passphrase is incorrect");
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    releasePassphrase(previousPassphrase);
    throw new Error("Passphrase confirmation does not match");
  }
  const normalizedNext = normalizePassphrase(nextPassphraseCandidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && isDekEncryptedPayload(payload)) {
    try {
      const dek = await unwrapDekWithPassphrase(payload, currentPassphrase);
      const meta = extractDekEnvelopeMeta(payload);
      const nextDekBlock = await wrapDekWithPassphrase(dek, normalizedNext, base64ToBytes(meta.salt), meta.kdf);
      const envelope = await encryptEntriesWithDek(entries, dek, { ...meta, dek: nextDekBlock });
      await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
      heldDek = dek;
      dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
      currentPassphrase = normalizedNext;
      await writeSessionUnlock(envelope, currentPassphrase, heldDek);
    } finally {
      releasePassphrase(previousPassphrase);
    }
    return;
  }
  currentPassphrase = normalizedNext;
  try {
    await persistEntries();
    await clearSessionUnlock();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
  releasePassphrase(previousPassphrase);
}
function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  form.querySelectorAll("input, select, button").forEach((node) => {
    node.disabled = locked;
  });
  qrFileInput.disabled = locked;
  searchInput.disabled = locked;
  sortSelect.disabled = locked;
  pasteUriBtn.disabled = locked;
  lockBtn.disabled = locked || !settings.encrypt;
  changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || locked);
  if (locked) {
    changePassphraseForm.classList.add("hidden");
  }
}
function sortEntries(items) {
  const sorted = [...items];
  if (settings.sortBy === "custom") {
    return sorted.sort((left, right) => (left.order ?? 0) - (right.order ?? 0) || left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
  }
  if (settings.sortBy === "recent") {
    return sorted.sort((left, right) => right.createdAt - left.createdAt);
  }
  if (settings.sortBy === "period") {
    return sorted.sort((left, right) => left.period - right.period || left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
  }
  return sorted.sort((left, right) => left.label.localeCompare(right.label, void 0, { sensitivity: "base" }));
}
function filteredEntries() {
  const query = (searchInput.value || "").trim().toLowerCase();
  return sortEntries(entries).filter((entry) => [entry.label, ...entry.tags || []].join(" ").toLowerCase().includes(query));
}
function refreshEntryNode(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".avatar").textContent = getIssuerInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits \u2022 ${entry.period}s`;
  const algoBadge = node.querySelector(".algo");
  if (algoBadge) {
    const showAlgo = entry.algorithm && entry.algorithm !== "SHA1";
    algoBadge.textContent = showAlgo ? entry.algorithm.replace(/^SHA/, "SHA-") : "";
    algoBadge.classList.toggle("hidden", !showAlgo);
  }
  const counterBadge = node.querySelector(".counter");
  if (counterBadge) {
    const isHotp = entry.type === "hotp";
    counterBadge.textContent = isHotp ? `#${entry.counter}` : "";
    counterBadge.classList.toggle("hidden", !isHotp);
  }
  const tagRoot = node.querySelector(".tags");
  tagRoot.innerHTML = "";
  for (const tag of entry.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag";
    chip.textContent = tag;
    tagRoot.appendChild(chip);
  }
}
function addCopyHistory(label, code) {
  copyHistory = [
    {
      label,
      code: formatCode(code),
      at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    },
    ...copyHistory.filter((item) => item.label !== label)
  ].slice(0, 5);
  renderCopyHistory();
}
function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  copyHistoryRoot.innerHTML = "";
  if (copyHistory.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Copied OTPs will appear here.";
    copyHistoryRoot.appendChild(empty);
    return;
  }
  for (const item of copyHistory) {
    const row = document.createElement("div");
    row.className = "history-item";
    const strong = document.createElement("strong");
    strong.textContent = item.label;
    const span = document.createElement("span");
    span.textContent = `${item.code} \u2022 ${item.at}`;
    row.append(strong, span);
    copyHistoryRoot.appendChild(row);
  }
}
function nextOrderValue(items = entries) {
  if (items.length === 0) return 1;
  return Math.max(...items.map((entry) => Number(entry.order) || 0)) + 1;
}
function resequenceEntries(items) {
  return items.map((entry, index) => ({ ...entry, order: index + 1 }));
}
function resequenceIfUnordered(decrypted) {
  return decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
}
async function unlockWithBiometrics() {
  const guard = await readUnlockGuard();
  if (guard.lockedUntil > Date.now()) {
    setUnlockStatus(`Too many failed attempts \u2014 unlock available in ${Math.ceil((guard.lockedUntil - Date.now()) / 1e3)}s`, "error");
    return;
  }
  const record = await readBiometricRecord();
  if (!record) {
    setUnlockStatus("No biometric unlock is enrolled on this device", "error");
    return;
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    await reconcileOrphanedBiometricRecord();
    setUnlockStatus("Biometric unlock is no longer available \u2014 use your passphrase", "error");
    return;
  }
  try {
    const prfSalt = fromB64u(record.prfSalt);
    const { prfOutput } = await runAssertCeremony({ credentialId: record.credentialId, prfSalt });
    const kek = await deriveKek(prfOutput, prfSalt);
    const dek = await unwrapDek(fromB64u(record.wrappedDek), fromB64u(record.wrappedIv), kek);
    const decrypted = await decryptVaultEntriesWithKey(dek, payload);
    heldDek = dek;
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
    currentPassphrase = "";
    entries = resequenceIfUnordered(decrypted);
    await writeSessionUnlock(payload, "", heldDek);
    await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
    setLocked(false);
    renderEntries();
    tick();
    setUnlockStatus("Vault unlocked with biometrics", "success");
    setMainStatus("Encrypted extension unlocked", "success");
  } catch (error) {
    reportError("Biometric unlock failed", error);
    setUnlockStatus(toUserMessage(error, "Biometric unlock failed \u2014 use your passphrase"), "error");
  }
}
async function enrollVaultBiometrics() {
  if (!settings.encrypt) {
    throw new Error("Enable encrypted storage before enabling biometric unlock");
  }
  if (!currentPassphrase && !heldDek) {
    throw new Error("Unlock the extension vault before enabling biometric unlock");
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && !isDekEncryptedPayload(payload) && !currentPassphrase) {
    throw new Error("Unlock the extension vault before enabling biometric unlock");
  }
  const enrollment = await enrollBiometricUnlock({});
  const prfSalt = enrollment.prfSalt;
  const kek = await deriveKek(enrollment.firstPrfOutput, prfSalt);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  let dek;
  let envelope = null;
  if (payload && isDekEncryptedPayload(payload)) {
    dek = heldDek || await unwrapDekWithPassphrase(payload, currentPassphrase);
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  } else {
    dek = await generateVaultDek();
    const saltBytes = crypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
    const dekBlock = await wrapDekWithPassphrase(dek, currentPassphrase, saltBytes, KDF_PARAMS_DEFAULT);
    envelope = await encryptEntriesWithDek(entries, dek, {
      salt: bytesToBase64(saltBytes),
      kdf: { ...KDF_PARAMS_DEFAULT },
      dek: dekBlock
    });
  }
  const rawDek = await exportDekRawBytes(dek);
  const wrappedDek = await wrapDek(rawDek, kek, wrapIv);
  const record = {
    credentialId: enrollment.credentialId,
    prfSalt: toB64u(prfSalt),
    wrappedDek: toB64u(wrappedDek),
    wrappedIv: toB64u(wrapIv)
  };
  if (envelope) {
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
  }
  await writeBiometricRecord(record);
  heldDek = dek;
  if (envelope) {
    dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
    await refreshSessionCacheForDek(envelope);
  }
  renderBiometricControls();
}
async function disenrollVaultBiometrics() {
  const record = await readBiometricRecord();
  if (!record) {
    setMainStatus("Biometric unlock is not enabled", "error");
    return;
  }
  const confirmed = window.confirm("Disable biometric unlock? The vault returns to passphrase-only storage.");
  if (!confirmed) return;
  const previousPassphrase = currentPassphrase;
  await requirePassphrase("disable biometric unlock");
  try {
    const restored = await encryptEntries(entries, currentPassphrase);
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: restored });
    await removeBiometricRecord();
    await clearSessionUnlock();
    heldDek = null;
    dekEnvelopeMeta = null;
    setMainStatus("Biometric unlock disabled \u2014 passphrase-only vault restored", "success");
  } finally {
    releasePassphrase(previousPassphrase);
  }
  renderBiometricControls();
}
function renderBiometricControls() {
  const section = document.getElementById("biometric-settings");
  if (!section) return;
  readBiometricRecord().then((record) => {
    section.classList.toggle("hidden", !biometricCapable);
    const enrollBtn = document.getElementById("enroll-biometric-btn");
    const disenrollBtn = document.getElementById("disenroll-biometric-btn");
    const statusLine = document.getElementById("biometric-status-line");
    if (enrollBtn) {
      enrollBtn.classList.toggle("hidden", !biometricCapable || Boolean(record) || !settings.encrypt);
    }
    if (disenrollBtn) {
      disenrollBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
    if (statusLine) {
      statusLine.textContent = !biometricCapable ? "" : record ? "Biometric unlock is enrolled. Your passphrase remains the recovery method." : settings.encrypt ? "Unlock with your platform authenticator instead of your passphrase." : "Enable encrypted storage first, then enroll biometric unlock.";
    }
    const unlockBiometricBtn = document.getElementById("biometric-unlock-btn");
    if (unlockBiometricBtn) {
      unlockBiometricBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
  });
}
function openEditEntryDialog(entry) {
  if (!editEntryDialog?.showModal) return;
  editEntryIdInput.value = entry.id;
  editLabelInput.value = entry.label;
  editSecretInput.value = entry.secret;
  editTagsInput.value = (entry.tags || []).join(", ");
  editDigitsInput.value = String(entry.digits);
  editPeriodInput.value = String(entry.period);
  editAlgorithmSelect.value = entry.algorithm || "SHA1";
  editCounterInput?.classList.toggle("hidden", entry.type !== "hotp");
  if (editCounterInput) editCounterInput.value = String(entry.type === "hotp" ? entry.counter : 0);
  setStatus(editStatus, "");
  editEntryDialog.showModal();
}
async function saveEditedEntry() {
  const id = editEntryIdInput.value;
  const current = entries.find((entry) => entry.id === id);
  if (!current) throw new Error("Entry no longer exists");
  const updated = normalizeEntry({
    ...current,
    label: editLabelInput.value,
    secret: editSecretInput.value,
    tags: normalizeTags(editTagsInput.value),
    digits: Number(editDigitsInput.value),
    period: Number(editPeriodInput.value),
    algorithm: editAlgorithmSelect.value,
    counter: current.type === "hotp" && editCounterInput ? Number(editCounterInput.value) : current.counter,
    order: current.order
  });
  if (entries.some((entry) => entry.id !== id && entry.secret === updated.secret && entry.digits === updated.digits && entry.period === updated.period)) {
    throw new Error("Another entry already uses this secret, digits, and period");
  }
  await replaceEntries(entries.map((entry) => entry.id === id ? updated : entry));
}
async function moveEntry(entryId, direction) {
  const ordered = sortEntries(entries);
  const index = ordered.findIndex((entry) => entry.id === entryId);
  const nextIndex = index + direction;
  if (index < 0 || nextIndex < 0 || nextIndex >= ordered.length) return;
  [ordered[index], ordered[nextIndex]] = [ordered[nextIndex], ordered[index]];
  await replaceEntries(resequenceEntries(ordered));
}
function showRemoveConfirmation(message) {
  if (!confirmRemoveDialog?.showModal) {
    return Promise.resolve(window.confirm(message));
  }
  confirmRemoveMessage.textContent = message;
  return new Promise((resolve) => {
    confirmRemoveCallback = resolve;
    confirmRemoveDialog.showModal();
  });
}
var entryDragState = null;
function popupCardMidpoints() {
  return [...entriesRoot.querySelectorAll(".entry-card")].map(
    (card) => card.getBoundingClientRect().top + card.offsetHeight / 2
  );
}
function startEntryDrag(event, entry, node) {
  if (settings.sortBy !== "custom" || event.button !== 0 || entryDragState) return;
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const fromIndex = ordered.findIndex((item) => item.id === entry.id);
  if (fromIndex < 0 || ordered.length < 2) return;
  event.preventDefault();
  entryDragState = { entryId: entry.id, fromIndex, node };
  node.classList.add("dragging");
  document.body.classList.add("dragging-entry");
  try {
    node.setPointerCapture(event.pointerId);
  } catch {
  }
  node.addEventListener("pointermove", moveEntryDrag);
  node.addEventListener("pointerup", endEntryDrag);
  node.addEventListener("pointercancel", endEntryDrag);
}
function moveEntryDrag(event) {
  if (!entryDragState) return;
  const hovered = [...entriesRoot.querySelectorAll(".entry-card")].find((card) => {
    if (card === entryDragState.node) return false;
    const rect = card.getBoundingClientRect();
    return event.clientY >= rect.top && event.clientY <= rect.bottom;
  });
  [...entriesRoot.querySelectorAll(".entry-card")].forEach((card) => {
    card.classList.toggle("drag-over", card === hovered);
  });
}
async function endEntryDrag(event) {
  const state = entryDragState;
  if (!state) return;
  entryDragState = null;
  state.node.removeEventListener("pointermove", moveEntryDrag);
  state.node.removeEventListener("pointerup", endEntryDrag);
  state.node.removeEventListener("pointercancel", endEntryDrag);
  state.node.classList.remove("dragging");
  document.body.classList.remove("dragging-entry");
  entriesRoot.querySelectorAll(".entry-card").forEach((card) => card.classList.remove("drag-over"));
  const target = computeDropIndex(popupCardMidpoints(), state.fromIndex, event.clientY);
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const currentIndex = ordered.findIndex((item) => item.id === state.entryId);
  if (currentIndex < 0) return;
  const [moved] = ordered.splice(currentIndex, 1);
  ordered.splice(Math.min(target, ordered.length), 0, moved);
  try {
    await replaceEntries(resequenceEntries(ordered));
    setMainStatus("Manual order updated", "success");
  } catch (error) {
    reportError("Extension drag reorder failed", error);
    setMainStatus(toUserMessage(error, "Could not reorder entries"), "error");
  }
}
function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  refreshEntryNode(node, entry);
  const dragHandle = node.querySelector(".drag-handle");
  if (dragHandle) {
    dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
    dragHandle.addEventListener("pointerdown", (event) => {
      startEntryDrag(event, entry, node);
    });
  }
  node.querySelector(".copy").addEventListener("click", async () => {
    try {
      const otp = node.dataset.otp;
      if (!otp) return;
      await navigator.clipboard.writeText(otp);
      navigator.vibrate?.(20);
      addCopyHistory(entry.label, otp);
      setMainStatus(`Copied ${parseLabelParts(entry.label).issuer} code`, "success");
      await consumeHotpCounter(entry);
    } catch (error) {
      reportError("Extension copy failed", error);
      setMainStatus(toUserMessage(error, "Could not copy OTP"), "error");
    }
  });
  async function consumeHotpCounter(currentEntry) {
    if (currentEntry.type !== "hotp") return;
    try {
      await replaceEntries(entries.map((item) => item.id === currentEntry.id ? { ...item, counter: item.counter + 1 } : item));
    } catch (error) {
      reportError("HOTP counter persist failed (copy)", error);
      setMainStatus("Counter save failed \u2014 the next code may repeat. Edit the entry to set the counter manually.", "error");
    }
  }
  node.querySelector(".edit")?.addEventListener("click", () => {
    openEditEntryDialog(entry);
  });
  node.querySelector(".move-up")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, -1);
      setMainStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Extension move up failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });
  node.querySelector(".move-down")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, 1);
      setMainStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Extension move down failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });
  node.querySelector(".remove").addEventListener("click", async () => {
    try {
      const confirmed = await showRemoveConfirmation(`Remove "${entry.label}" from the extension vault? You can undo for 10 minutes by reopening the popup.`);
      if (!confirmed) return;
      const index = entries.findIndex((item) => item.id === entry.id);
      await replaceEntries(entries.filter((item) => item.id !== entry.id));
      setMainStatus("Removed entry", "success");
      if (index >= 0) await offerUndoDelete([{ entry, index }]);
    } catch (error) {
      reportError("Extension remove failed", error);
      setMainStatus(toUserMessage(error, "Could not remove entry"), "error");
    }
  });
  return node;
}
function renderEntries() {
  if (!unlockPanel.classList.contains("hidden")) {
    entriesRoot.innerHTML = '<div class="empty-state">Vault is locked. Unlock to view and use your codes.</div>';
    return;
  }
  const visible = filteredEntries();
  if (visible.length === 0) {
    entriesRoot.innerHTML = '<div class="empty-state">No entries yet. Add one, import a QR file, or paste an otpauth URI.</div>';
    return;
  }
  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (const entry of visible) {
    let node = entryNodes.get(entry.id);
    if (!node) {
      node = createEntryNode(entry);
      entryNodes.set(entry.id, node);
    }
    refreshEntryNode(node, entry);
    const dragHandle = node.querySelector(".drag-handle");
    if (dragHandle) dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
    fragment.appendChild(node);
  }
  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }
  entriesRoot.appendChild(fragment);
}
async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  try {
    let code;
    if (entry.type === "hotp") {
      node.querySelector(".seconds").textContent = `#${entry.counter}`;
      node.querySelector(".bar").style.transform = "scaleX(1)";
      const hotpRing = node.querySelector(".ring-progress");
      if (hotpRing) hotpRing.style.strokeDashoffset = "0";
      node.classList.toggle("urgent", false);
      code = await generateHotp(entry.secret, entry.counter, entry.digits, entry.algorithm);
    } else {
      const remaining = entry.period - now % entry.period;
      code = await generateTotp(entry.secret, entry.digits, entry.period, now, entry.algorithm);
      node.querySelector(".seconds").textContent = `${remaining}s`;
      node.querySelector(".bar").style.transform = `scaleX(${remaining / entry.period})`;
      const ring = node.querySelector(".ring-progress");
      if (ring) ring.style.strokeDashoffset = String(100 - remaining / entry.period * 100);
      node.classList.toggle("urgent", remaining <= 10);
    }
    node.dataset.otp = code;
    node.querySelector(".code").textContent = formatCode(code);
  } catch (error) {
    reportError("Extension OTP generation failed", error);
    node.querySelector(".code").textContent = "Invalid";
    node.dataset.otp = "";
  }
}
function updateGlobalTimer(now) {
  const visible = filteredEntries();
  const period = visible.length > 0 ? Math.min(...visible.map((entry) => entry.period)) : 30;
  const remaining = period - now % period;
  globalSeconds.textContent = `${remaining}s`;
  globalBar.style.transform = `scaleX(${remaining / period})`;
}
async function tick() {
  const now = Math.floor(Date.now() / 1e3);
  updateGlobalTimer(now);
  const vaultLocked = !unlockPanel.classList.contains("hidden");
  if (settings.encrypt && settings.autoLockMinutes > 0 && !vaultLocked && Date.now() - lastActivity >= settings.autoLockMinutes * 6e4) {
    lockVault();
    return;
  }
  if (vaultLocked) {
    const guard = await readUnlockGuard();
    const remainingMs = guard.lockedUntil - Date.now();
    unlockBtn.disabled = remainingMs > 0;
    if (remainingMs > 0) {
      setUnlockStatus(`Too many failed attempts \u2014 unlock available in ${Math.ceil(remainingMs / 1e3)}s`, "error");
    } else if (unlockStatus.classList.contains("error") && unlockStatus.textContent.startsWith("Too many failed attempts")) {
      setUnlockStatus("");
    }
    return;
  }
  await Promise.all(filteredEntries().map((entry) => updateEntryNode(entry, now)));
}
async function snapshotVaultArtifacts() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY]);
  return {
    plain: stored[STORAGE_KEY] ?? null,
    legacyPlain: stored[LEGACY_STORAGE_KEY] ?? null,
    encrypted: stored[ENCRYPTED_KEY] ?? null
  };
}
async function restoreVaultArtifacts(snapshot) {
  const updates = {};
  const removes = [];
  if (snapshot.plain === null) {
    removes.push(STORAGE_KEY);
  } else {
    updates[STORAGE_KEY] = snapshot.plain;
  }
  if (snapshot.legacyPlain === null) {
    removes.push(LEGACY_STORAGE_KEY);
  } else {
    updates[LEGACY_STORAGE_KEY] = snapshot.legacyPlain;
  }
  if (snapshot.encrypted === null) {
    removes.push(ENCRYPTED_KEY);
  } else {
    updates[ENCRYPTED_KEY] = snapshot.encrypted;
  }
  if (Object.keys(updates).length > 0) await chrome.storage.local.set(updates);
  if (removes.length > 0) await chrome.storage.local.remove(removes);
}
async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  await chrome.storage.local.set({ [ENCRYPTED_KEY]: encryptedPayload });
  await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
}
async function persistEntries() {
  const previousArtifacts = await snapshotVaultArtifacts();
  try {
    if (settings.encrypt) {
      if (heldDek) {
        const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
        const payload = stored[ENCRYPTED_KEY];
        if (!payload || !isDekEncryptedPayload(payload) || !dekEnvelopeMeta) {
          throw new Error("Biometric vault envelope is missing \u2014 unlock with your passphrase to restore it");
        }
        const envelope = await encryptEntriesWithDek(entries, heldDek, dekEnvelopeMeta);
        await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
        await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
        await refreshSessionCacheForDek(envelope);
        return;
      }
      if (!currentPassphrase) throw new Error("Unlock extension vault before saving encrypted entries");
      await saveEncryptedEntries(entries, currentPassphrase);
      return;
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: entries });
    await chrome.storage.local.remove(ENCRYPTED_KEY);
    await removeBiometricRecord();
    heldDek = null;
    dekEnvelopeMeta = null;
  } catch (error) {
    await restoreVaultArtifacts(previousArtifacts);
    throw error;
  }
}
async function persistSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}
async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);
  if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
  try {
    await persistEntries();
  } catch (error) {
    entries = previousEntries;
    renderEntries();
    await tick();
    throw error;
  }
  renderEntries();
  await tick();
}
async function addEntry(input) {
  const entry = normalizeEntry({ ...input, order: nextOrderValue() });
  if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
  await replaceEntries([...entries, entry]);
}
async function importFromQrFile(file) {
  if (typeof BarcodeDetector !== "function") {
    throw new Error("QR file import requires Chrome BarcodeDetector support");
  }
  const bitmap = await createImageBitmap(file);
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const results = await detector.detect(bitmap);
  bitmap.close();
  if (!results.length || !results[0].rawValue) {
    throw new Error("Could not detect a QR code in that file");
  }
  const uri = extractOtpAuthUri(results[0].rawValue);
  if (!uri) {
    throw new Error("QR code was detected but does not contain a valid OTP URI");
  }
  return normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
}
function bindEvents() {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        tags: normalizeTags(tagsInput.value),
        type: entryTypeSelect?.value || "totp",
        counter: entryTypeSelect?.value === "hotp" ? Number(counterInput?.value || 0) : 0,
        algorithm: algorithmSelect?.value || "SHA1",
        digits: Number(digitsInput.value),
        period: Number(periodInput.value)
      });
      form.reset();
      tagsInput.value = "";
      digitsInput.value = "6";
      periodInput.value = "30";
      counterInput?.classList.add("hidden");
      setMainStatus("Entry added", "success");
    } catch (error) {
      reportError("Extension manual entry failed", error);
      setMainStatus(toUserMessage(error, "Could not add entry"), "error");
    }
  });
  entryTypeSelect?.addEventListener("change", () => {
    counterInput?.classList.toggle("hidden", entryTypeSelect.value !== "hotp");
  });
  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    try {
      const entry = await importFromQrFile(file);
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setMainStatus("Imported QR entry", "success");
    } catch (error) {
      reportError("Extension QR import failed", error);
      setMainStatus(toUserMessage(error, "Could not import QR file"), "error");
    } finally {
      qrFileInput.value = "";
    }
  });
  pasteUriBtn.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error("Clipboard permission denied. Copy the URI into the secret field instead.");
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length > 0) {
        stageMigrationPayloads(migration.payloads, "Clipboard");
        return;
      }
      const uri = extractOtpAuthUri(text);
      if (!uri) throw new Error("Clipboard does not contain a valid OTP URI");
      const entry = normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setMainStatus("Imported URI from clipboard", "success");
    } catch (error) {
      reportError("Extension clipboard import failed", error);
      setMainStatus(toUserMessage(error, "Could not import URI"), "error");
    }
  });
  pasteGaBtn?.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error("Clipboard permission denied. Copy the export URI and try again.");
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length === 0) {
        throw new Error(migration.warnings[0] || "Clipboard does not contain a Google Authenticator export");
      }
      stageMigrationPayloads(migration.payloads, "Google Authenticator");
    } catch (error) {
      reportError("Extension GA import failed", error);
      setMainStatus(toUserMessage(error, "Could not import the Google Authenticator export"), "error");
    }
  });
  migrationPreviewForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await commitMigrationPreview();
      migrationPreviewDialog?.close("accept");
      setMainStatus("Google Authenticator entries imported", "success");
    } catch (error) {
      reportError("Extension GA preview commit failed", error);
      setMainStatus(toUserMessage(error, "Could not import entries"), "error");
    }
  });
  migrationPreviewDialog?.addEventListener("close", () => {
    migrationPreviewState = null;
  });
  exportBackupBtn?.addEventListener("click", async () => {
    try {
      await exportBackup();
      renderBackupReminder();
      setMainStatus("Backup exported", "success");
    } catch (error) {
      reportError("Extension backup export failed", error);
      setMainStatus(toUserMessage(error, "Could not export backup"), "error");
    }
  });
  document.getElementById("check-drift-btn")?.addEventListener("click", async () => {
    if (!settings.timeDriftCheck) {
      setMainStatus("Enable the time-drift check first", "warning");
      return;
    }
    await checkTimeDrift();
    setMainStatus("Time check complete \u2014 see the banner if your clock is off", "success");
  });
  document.getElementById("drift-dismiss")?.addEventListener("click", () => {
    document.getElementById("drift-banner")?.classList.add("hidden");
  });
  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });
  sortSelect.addEventListener("change", async () => {
    settings.sortBy = sortSelect.value;
    await persistSettings();
    renderEntries();
    tick();
  });
  toggleFormBtn.addEventListener("click", async () => {
    collapsed = !collapsed;
    applyUiState();
    await saveUiState();
  });
  encryptToggle.addEventListener("change", () => {
    passphraseFields.classList.toggle("hidden", !encryptToggle.checked);
  });
  changePassphraseBtn?.addEventListener("click", () => {
    changePassphraseForm.classList.toggle("hidden");
    currentPassphraseInput.value = "";
    newPassphraseInput.value = "";
    newPassphraseConfirmInput.value = "";
  });
  changePassphraseForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await changeVaultPassphrase(
        currentPassphraseInput.value.trim(),
        newPassphraseInput.value.trim(),
        newPassphraseConfirmInput.value.trim()
      );
      changePassphraseForm.classList.add("hidden");
      currentPassphraseInput.value = "";
      newPassphraseInput.value = "";
      newPassphraseConfirmInput.value = "";
      setMainStatus("Extension passphrase updated", "success");
    } catch (error) {
      reportError("Extension change passphrase failed", error);
      setMainStatus(toUserMessage(error, "Could not update passphrase"), "error");
    }
  });
  securityForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const previousSettings = { ...settings };
    const previousPassphrase = currentPassphrase;
    let previousArtifacts;
    try {
      previousArtifacts = await snapshotVaultArtifacts();
      settings.encrypt = encryptToggle.checked;
      const autoLockSelect = document.getElementById("auto-lock-select");
      if (autoLockSelect) settings.autoLockMinutes = Number(autoLockSelect.value) || 0;
      const timeDriftToggle = document.getElementById("time-drift-toggle");
      if (timeDriftToggle) settings.timeDriftCheck = timeDriftToggle.checked;
      const themeSelect = document.getElementById("theme-select");
      if (themeSelect) {
        settings.theme = themeSelect.value;
        applyTheme();
      }
      if (settings.encrypt) {
        let nextPassphrase = currentPassphrase;
        if (!nextPassphrase) {
          if (previousSettings.encrypt) {
            passphraseInput.value = "";
            passphraseConfirmInput.value = "";
            await persistSettings();
            renderBiometricControls();
            setMainStatus("Encrypted extension vault saved", "success");
            return;
          }
          const first = passphraseInput.value.trim();
          const second = passphraseConfirmInput.value.trim();
          if (first !== second) throw new Error("Passphrase confirmation does not match");
          nextPassphrase = normalizePassphrase(first);
        }
        currentPassphrase = nextPassphrase;
        await saveEncryptedEntries(entries, currentPassphrase);
      } else {
        currentPassphrase = "";
        heldDek = null;
        dekEnvelopeMeta = null;
        await clearSessionUnlock();
        await removeBiometricRecord();
        await chrome.storage.local.set({ [STORAGE_KEY]: entries });
        await chrome.storage.local.remove(ENCRYPTED_KEY);
      }
      await persistSettings();
      passphraseInput.value = "";
      passphraseConfirmInput.value = "";
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      const encryptedVaultExists = Boolean(settings.encrypt && (currentPassphrase || previousArtifacts?.encrypted));
      passphraseFields.classList.toggle("hidden", !settings.encrypt || encryptedVaultExists);
      passphraseGuidance?.classList.toggle("hidden", !encryptedVaultExists);
      setMainStatus(
        encryptedVaultExists ? "Encrypted extension vault saved. Use Change Passphrase to rotate your extension secret." : settings.encrypt ? "Encrypted extension vault saved" : "Extension storage is now plain local storage",
        "success"
      );
      renderBiometricControls();
    } catch (error) {
      settings = previousSettings;
      currentPassphrase = previousPassphrase;
      if (previousArtifacts) await restoreVaultArtifacts(previousArtifacts);
      encryptToggle.checked = settings.encrypt;
      passphraseFields.classList.toggle("hidden", !settings.encrypt);
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      reportError("Extension save security failed", error);
      setMainStatus(toUserMessage(error, "Could not save security settings"), "error");
    }
  });
  lockBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setMainStatus("Enable encrypted storage first", "error");
      return;
    }
    lockVault();
  });
  document.getElementById("biometric-unlock-btn")?.addEventListener("click", () => {
    unlockWithBiometrics();
  });
  document.getElementById("enroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await enrollVaultBiometrics();
      setMainStatus("Biometric unlock enabled on this device", "success");
    } catch (error) {
      reportError("Biometric enrollment failed", error);
      setMainStatus(toUserMessage(error, "Could not enable biometric unlock"), "error");
      renderBiometricControls();
    }
  });
  document.getElementById("disenroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await disenrollVaultBiometrics();
    } catch (error) {
      reportError("Biometric disenroll failed", error);
      setMainStatus(toUserMessage(error, "Could not disable biometric unlock"), "error");
    }
  });
  let unlockInFlight = false;
  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (unlockInFlight) return;
    unlockInFlight = true;
    try {
      const guard = await readUnlockGuard();
      const now = Date.now();
      if (guard.lockedUntil > now) {
        setUnlockStatus(`Too many failed attempts \u2014 unlock available in ${Math.ceil((guard.lockedUntil - now) / 1e3)}s`, "error");
        return;
      }
      unlockBtn.disabled = true;
      try {
        const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
        const payload = stored[ENCRYPTED_KEY];
        const candidate = unlockPassphraseInput.value;
        let keyHandle;
        if (isDekEncryptedPayload(payload)) {
          heldDek = await unwrapDekWithPassphrase(payload, normalizePassphrase(candidate));
          dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
          keyHandle = heldDek;
          entries = resequenceIfUnordered(await decryptVaultEntriesWithKey(heldDek, payload));
        } else {
          heldDek = null;
          dekEnvelopeMeta = null;
          keyHandle = await deriveVaultKeyFromPayload(payload, normalizePassphrase(candidate));
          entries = resequenceIfUnordered(await decryptVaultEntries(payload, candidate));
        }
        currentPassphrase = normalizePassphrase(candidate);
        if (isLegacyEncryptedPayload(payload)) {
          await persistEntries();
        }
        await writeSessionUnlock(payload, currentPassphrase, keyHandle);
        await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
        unlockPassphraseInput.value = "";
        setLocked(false);
        renderEntries();
        tick();
        setUnlockStatus("Vault unlocked", "success");
        setMainStatus("Encrypted extension unlocked", "success");
      } catch (error) {
        const attempts = guard.attempts + 1;
        const backoff = unlockBackoffSeconds(attempts);
        await writeUnlockGuard({ attempts, lockedUntil: attempts >= 3 ? now + backoff * 1e3 : 0 });
        const suffix = attempts >= 3 ? ` Locked for ${backoff}s.` : "";
        reportError("Extension unlock failed", error);
        setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted data") + suffix, "error");
      } finally {
        unlockBtn.disabled = false;
      }
    } finally {
      unlockInFlight = false;
    }
  });
  cancelEditBtn.addEventListener("click", () => {
    editEntryDialog.close("cancel");
  });
  editEntryForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await saveEditedEntry();
      editEntryDialog.close("accept");
      setMainStatus("Entry updated", "success");
    } catch (error) {
      setStatus(editStatus, toUserMessage(error, "Could not update entry"), "error");
    }
  });
  confirmRemoveDialog?.addEventListener("close", () => {
    if (!confirmRemoveCallback) return;
    const accepted = confirmRemoveDialog.returnValue === "accept";
    confirmRemoveCallback(accepted);
    confirmRemoveCallback = null;
  });
}
