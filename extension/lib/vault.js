import { OtpVaultError, normalizeEntries } from "./otp.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
    return normalizeEntries(parsed);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error,
    });
  }
}

export function createPlainBackup(entries) {
  return {
    version: 1,
    encrypted: false,
    createdAt: new Date().toISOString(),
    entries,
  };
}

export function createEncryptedBackup(vaultPayload) {
  validateEncryptedPayload(vaultPayload);
  return {
    version: 1,
    encrypted: true,
    createdAt: new Date().toISOString(),
    vault: vaultPayload,
  };
}

export function parseBackupFile(rawBackup) {
  if (!rawBackup || typeof rawBackup !== "object") {
    throw new OtpVaultError("Backup file is invalid", { code: "BACKUP_INVALID" });
  }
  if (rawBackup.version !== 1) {
    throw new OtpVaultError("Backup version is not supported", { code: "BACKUP_VERSION" });
  }
  if (rawBackup.encrypted === true) {
    validateEncryptedPayload(rawBackup.vault);
    return {
      encrypted: true,
      vault: rawBackup.vault,
    };
  }
  if (rawBackup.encrypted === false) {
    if (!Array.isArray(rawBackup.entries)) {
      throw new OtpVaultError("Backup entries are missing or invalid", { code: "BACKUP_ENTRIES" });
    }
    return {
      encrypted: false,
      entries: normalizeEntries(rawBackup.entries),
    };
  }
  throw new OtpVaultError("Backup file is missing encryption metadata", { code: "BACKUP_METADATA" });
}
