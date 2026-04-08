import { OtpVaultError, base32ToBytes, normalizeEntries, sanitizeBase32 } from "./otp.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const BACKUP_VERSION = 2;

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

async function deriveVaultKey(passphrase, salt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptEntries(entries, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(16));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);

  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted)),
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
    const key = await deriveVaultKey(normalizedPassphrase, fromBase64(normalizedPayload.salt), safeCrypto);
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

    if (rawBackup.encrypted === false && Array.isArray(rawBackup.entries)) {
      return {
        version: 1,
        encrypted: false,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: 1,
          entries: normalizeBackupEntriesStrict(rawBackup.entries, {
            message: "Backup contains invalid entries",
            code: "BACKUP_ENTRIES_INVALID",
          }),
        },
      };
    }

    if (rawBackup.encrypted === false && Array.isArray(rawBackup.payload?.entries)) {
      return {
        version: 1,
        encrypted: false,
        createdAt: rawBackup.createdAt || null,
        payload: {
          schemaVersion: rawBackup.payload.schemaVersion || 1,
          entries: normalizeBackupEntriesStrict(rawBackup.payload.entries, {
            message: "Backup contains invalid entries",
            code: "BACKUP_ENTRIES_INVALID",
          }),
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

  const entries = normalizeBackupEntriesStrict(payload.entries, {
    message: "Backup contains invalid entries",
    code: "BACKUP_ENTRIES_INVALID",
  });
  return {
    encrypted: false,
    integrity,
    createdAt: migrated.createdAt || null,
    itemCount: entries.length,
    schemaVersion: payload.schemaVersion || 1,
    entries,
  };
}
