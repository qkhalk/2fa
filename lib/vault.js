import { OtpVaultError, base32ToBytes, normalizeEntries, sanitizeBase32 } from "./otp.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BACKUP_VERSION = 2;

export const KDF_PARAMS_DEFAULT = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 600000,
  hash: "SHA-256",
  saltBytes: 16,
});

export const KDF_PARAMS_LEGACY = Object.freeze({
  algorithm: "PBKDF2",
  iterations: 150000,
  hash: "SHA-256",
  saltBytes: 16,
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

export function normalizePassphrase(passphrase) {
  const clean = (passphrase || "").trim();
  if (clean.length < 8) {
    throw new OtpVaultError("Use a passphrase with at least 8 characters", { code: "PASSPHRASE_TOO_SHORT" });
  }
  return clean;
}

async function deriveVaultKey(passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  // wrapKey/unwrapKey support the DEK-mode envelope (biometric unlock).
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: params.hash },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
  );
}

// Derives the AES-GCM vault key for an envelope (session-cache path: the
// popup derives once, caches the CryptoKey, and later opens reuse it).
export async function deriveVaultKeyFromPayload(payload, passphrase, cryptoApi = globalThis.crypto) {
  const normalizedPayload = validateEncryptedPayload(payload);
  return deriveVaultKey(
    normalizePassphrase(passphrase),
    fromBase64(normalizedPayload.salt),
    resolveKdfParams(normalizedPayload.kdf),
    requireCrypto(cryptoApi)
  );
}

// Decrypts with an already-derived AES-GCM key (session-cache path: a popup
// re-open reuses the cached CryptoKey and pays no PBKDF2 cost).
// Shared AES-GCM decrypt + strict normalize used by every decrypt consumer;
// errors keep their identity so the callers' OtpVaultError rethrow wrappers
// preserve codes exactly.
async function decryptAndNormalize(key, normalizedPayload, safeCrypto) {
  const decrypted = await safeCrypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(normalizedPayload.iv) },
    key,
    fromBase64(normalizedPayload.data)
  );
  const parsed = JSON.parse(decoder.decode(decrypted));
  return normalizeBackupEntriesStrict(parsed, {
    message: "Decrypted vault entries are invalid",
    code: "VAULT_ENTRIES_INVALID",
  });
}

export async function decryptVaultEntriesWithKey(key, payload, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    return await decryptAndNormalize(key, normalizedPayload, safeCrypto);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error,
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
  if (kdf.saltBytes !== undefined && (!Number.isInteger(kdf.saltBytes) || kdf.saltBytes <= 0)) {
    throw new OtpVaultError("Encrypted data has an invalid kdf block", { code: "VAULT_FIELDS" });
  }
  return kdf;
}

function resolveKdfParams(kdf) {
  if (!kdf) return KDF_PARAMS_LEGACY;
  validateKdfParams(kdf);
  // The backup checksum is unkeyed, so envelope kdf params are tamperable.
  // A sub-floor work factor is treated as legacy and force-upgraded on the
  // next save — it is never honored (FR2/FR6).
  if (kdf.iterations < KDF_PARAMS_LEGACY.iterations) return KDF_PARAMS_LEGACY;
  return kdf;
}

export function isLegacyEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") return false;
  if (!payload.kdf) return true;
  if (typeof payload.kdf !== "object") return true;
  return typeof payload.kdf.iterations !== "number" || payload.kdf.iterations < KDF_PARAMS_LEGACY.iterations;
}

const COMMON_PASSPHRASE_PATTERNS = [
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
  "vault",
];

const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Good", "Strong"];

const BACKUP_REMINDER_MS = 30 * 24 * 60 * 60 * 1000;

// Warn when the vault holds entries and either no export was ever completed
// or the last one is older than 30 days. Pure: `now` injectable for tests.
export function shouldWarnBackup(settings, entryCount, now = Date.now()) {
  if (!Number.isInteger(entryCount) || entryCount < 1) return false;
  const lastBackupAt = Number(settings?.lastBackupAt);
  if (!Number.isFinite(lastBackupAt) || lastBackupAt <= 0) return true;
  return now - lastBackupAt > BACKUP_REMINDER_MS;
}

export function assessPassphraseStrength(passphrase) {
  const value = String(passphrase || "");
  if (value.length === 0) {
    return { score: 0, label: STRENGTH_LABELS[0], warnings: ["Enter a passphrase"] };
  }

  let score = 0;
  if (value.length >= 8) score = 1;
  if (value.length >= 12) score = 2;

  const characterClasses = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]
    .filter((pattern) => pattern.test(value)).length;
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

export async function encryptEntries(entries, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, KDF_PARAMS_DEFAULT, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);

  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...KDF_PARAMS_DEFAULT },
  };
}

function validateEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Encrypted data is missing or invalid", { code: "VAULT_INVALID" });
  }
  if (typeof payload.salt !== "string" || typeof payload.iv !== "string" || typeof payload.data !== "string") {
    throw new OtpVaultError("Encrypted data is missing required fields", { code: "VAULT_FIELDS" });
  }
  if (payload.kdf !== undefined) {
    validateKdfParams(payload.kdf);
  }
  if (payload.dek !== undefined) {
    const dek = payload.dek;
    if (!dek || typeof dek !== "object"
        || typeof dek.wrapped !== "string" || typeof dek.iv !== "string") {
      throw new OtpVaultError("Encrypted data has an invalid dek block", { code: "VAULT_FIELDS" });
    }
  }
  return payload;
}

// DEK two-envelope mode (biometric unlock): `data` is encrypted under a
// random vault DEK; `dek.wrapped` holds the DEK wrapped under the
// passphrase-derived key (recovery), and the PRF-wrapped copy lives in the
// separate biometric record storage. kdf.mode lets pre-0.1.5 code fail with
// a clear "newer format" signal instead of a misleading passphrase error.
export function isDekEncryptedPayload(payload) {
  return Boolean(payload && typeof payload === "object"
    && payload.kdf && typeof payload.kdf === "object"
    && payload.kdf.mode === "dek-v1"
    && payload.dek && typeof payload.dek === "object");
}

// Unwraps the passphrase-wrapped DEK from a DEK-mode envelope (recovery path
// used by passphrase unlock and backup import).
export async function unwrapDekWithPassphrase(payload, passphrase, cryptoApi = globalThis.crypto) {
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
      cause: error,
    });
  }
}

// Wraps a DEK under a passphrase-derived key (enrollment writes the initial
// wrap; a passphrase change re-wraps the SAME DEK without touching data).
export async function wrapDekWithPassphrase(dek, passphrase, salt, params = KDF_PARAMS_DEFAULT, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const wrapKey = await deriveVaultKey(normalizePassphrase(passphrase), salt, params, safeCrypto);
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const wrapped = await safeCrypto.subtle.wrapKey("raw", dek, wrapKey, { name: "AES-GCM", iv });
  return { wrapped: toBase64(new Uint8Array(wrapped)), iv: toBase64(iv) };
}

export async function generateVaultDek(cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  // extractable is required for wrapKey("raw") envelope wrapping; the key only
  // ever leaves the boundary as AES-GCM ciphertext, never plaintext.
  return safeCrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
}

// Encrypts vault data under a held DEK, keeping the envelope's kdf/salt and
// passphrase DEK wrap stable across saves (biometric-mode save path FR8).
export async function encryptEntriesWithDek(entries, dek, envelopeMeta, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const { salt, kdf, dek: dekBlock } = envelopeMeta || {};
  if (typeof salt !== "string" || !kdf || !dekBlock) {
    throw new OtpVaultError("A DEK-mode envelope meta block is required", { code: "VAULT_FIELDS" });
  }
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const payload = encoder.encode(JSON.stringify(entries));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, payload);
  return {
    salt,
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
    kdf: { ...kdf, mode: "dek-v1" },
    dek: { ...dekBlock },
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
  return Boolean(entry)
    && typeof entry === "object"
    && typeof entry.id === "string"
    && entry.id.trim().length > 0
    && typeof entry.label === "string"
    && entry.label.trim().length > 0
    && hasRequiredBackupSecret(entry.secret)
    && Number.isInteger(entry.digits)
    && Number.isInteger(entry.period)
    && typeof entry.createdAt === "number"
    && Number.isFinite(entry.createdAt);
}

function normalizeBackupEntriesStrict(entries, { message, code }) {
  if (!Array.isArray(entries) || !entries.every(hasRequiredBackupEntryShape)) {
    throw new OtpVaultError(message, { code });
  }

  const normalizedEntries = normalizeEntries(entries);
  if (normalizedEntries.length !== entries.length) {
    throw new OtpVaultError(message, { code });
  }

  return normalizedEntries;
}

export async function decryptVaultEntries(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const normalizedPayload = validateEncryptedPayload(payload);

  try {
    if (isDekEncryptedPayload(normalizedPayload)) {
      // DEK mode: the passphrase unwraps the vault DEK, then the DEK
      // decrypts the data. Covers passphrase unlock, backup import, and the
      // extension unlock consumer centrally (FR9).
      const dek = await unwrapDekWithPassphrase(normalizedPayload, normalizedPassphrase, safeCrypto);
      // return await, not return: an un-awaited rejection escapes this catch.
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
      cause: error,
    });
  }
}

async function buildBackupEnvelope(payload, encrypted, cryptoApi = globalThis.crypto) {
  return {
    version: BACKUP_VERSION,
    encrypted,
    createdAt: new Date().toISOString(),
    itemCount: encrypted ? 0 : payload.entries.length,
    checksum: await sha256Hex(JSON.stringify(payload), cryptoApi),
    payload,
  };
}

export async function createPlainBackup(entries, cryptoApi = globalThis.crypto) {
  const payload = {
    schemaVersion: 1,
    entries,
  };

  return buildBackupEnvelope(payload, false, cryptoApi);
}

export async function createEncryptedBackup(vaultPayload, cryptoApi = globalThis.crypto) {
  validateEncryptedPayload(vaultPayload);
  return buildBackupEnvelope({
    schemaVersion: 1,
    vault: vaultPayload,
  }, true, cryptoApi);
}

async function migrateBackup(rawBackup) {
  if (rawBackup.version === 1) {
    if (rawBackup.encrypted === true && rawBackup.vault) {
      validateEncryptedPayload(rawBackup.vault);
      return {
        version: 1,
        encrypted: true,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: 1,
          vault: rawBackup.vault,
        },
      };
    }

    if (rawBackup.encrypted === true && rawBackup.payload?.vault) {
      validateEncryptedPayload(rawBackup.payload.vault);
      return {
        version: 1,
        encrypted: true,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: rawBackup.payload.schemaVersion || 1,
          vault: rawBackup.payload.vault,
        },
      };
    }

    // Real v1 exports always set encrypted:false; tolerate files where the
    // field was dropped. Entries are validated leniently by parseBackupFile,
    // which skips invalid items and reports invalidItemCount.
    if (rawBackup.encrypted !== true && Array.isArray(rawBackup.entries)) {
      return {
        version: 1,
        encrypted: false,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: 1,
          entries: rawBackup.entries,
        },
      };
    }

    if (rawBackup.encrypted !== true && Array.isArray(rawBackup.payload?.entries)) {
      return {
        version: 1,
        encrypted: false,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: rawBackup.payload.schemaVersion || 1,
          entries: rawBackup.payload.entries,
        },
      };
    }
  }

  if (rawBackup.version === BACKUP_VERSION) {
    return rawBackup;
  }

  throw new OtpVaultError("Backup version is not supported", { code: "BACKUP_VERSION" });
}

export async function parseBackupFile(rawBackup, cryptoApi = globalThis.crypto) {
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
      vault: payload.vault,
    };
  }

  if (!Array.isArray(payload.entries)) {
    throw new OtpVaultError("Backup entries are missing or invalid", { code: "BACKUP_ENTRIES" });
  }

  const totalItemCount = payload.entries.length;
  const entries = normalizeEntries(payload.entries);
  if (entries.length === 0) {
    throw new OtpVaultError("Backup contains invalid entries", { code: "BACKUP_ENTRIES_INVALID" });
  }
  return {
    encrypted: false,
    integrity,
    createdAt: migrated.createdAt || null,
    itemCount: totalItemCount,
    invalidItemCount: totalItemCount - entries.length,
    schemaVersion: payload.schemaVersion || 1,
    entries,
  };
}
