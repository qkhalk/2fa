import { describe, expect, it } from "vitest";

import {
  assessPassphraseStrength,
  createEncryptedBackup,
  createPlainBackup,
  decryptVaultEntries,
  encryptEntries,
  isLegacyEncryptedPayload,
  KDF_PARAMS_DEFAULT,
  parseBackupFile,
} from "../../lib/vault.js";

const encoder = new TextEncoder();

function toBase64String(uint8) {
  return btoa(String.fromCharCode(...uint8));
}

// Builds a pre-0.1.2 {salt, iv, data} envelope at the legacy 150k work factor.
async function encryptWithLegacyParams(entries, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(entries)));
  return {
    salt: toBase64String(salt),
    iv: toBase64String(iv),
    data: toBase64String(new Uint8Array(encrypted)),
  };
}

describe("vault helpers", () => {
  const entries = [
    {
      id: "entry_1",
      label: "GitHub:user@example.com",
      secret: "JBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
      pinned: false,
      tags: [],
      createdAt: 1,
    },
  ];

  function omitEntryField(field) {
    const { [field]: _omitted, ...rest } = entries[0];
    return rest;
  }

  function withEntryField(field, value) {
    return { ...entries[0], [field]: value };
  }

  it("encrypts and decrypts entry collections", async () => {
    const payload = await encryptEntries(entries, "correct horse battery");
    const decrypted = await decryptVaultEntries(payload, "correct horse battery");

    expect(decrypted).toEqual([expect.objectContaining(entries[0])]);
  });

  it("rejects the wrong passphrase", async () => {
    const payload = await encryptEntries(entries, "correct horse battery");
    await expect(decryptVaultEntries(payload, "wrong passphrase")).rejects.toThrow(
      "Incorrect passphrase or unreadable encrypted data"
    );
  });

  it("writes kdf params into new envelopes at the 600k default", async () => {
    const payload = await encryptEntries(entries, "correct horse battery");

    expect(payload.kdf).toEqual({ ...KDF_PARAMS_DEFAULT });
    expect(payload.kdf.iterations).toBe(600000);
  });

  it("decrypts legacy {salt, iv, data} envelopes at the 150k work factor", async () => {
    const legacyPayload = await encryptWithLegacyParams(entries, "correct horse battery");

    expect(legacyPayload.kdf).toBeUndefined();
    const decrypted = await decryptVaultEntries(legacyPayload, "correct horse battery");

    expect(decrypted).toEqual([expect.objectContaining(entries[0])]);
    expect(isLegacyEncryptedPayload(legacyPayload)).toBe(true);
  });

  it("treats a sub-floor kdf as legacy instead of honoring it", async () => {
    const legacyPayload = await encryptWithLegacyParams(entries, "correct horse battery");
    const tampered = { ...legacyPayload, kdf: { algorithm: "PBKDF2", iterations: 1000, hash: "SHA-256", saltBytes: 16 } };

    expect(isLegacyEncryptedPayload(tampered)).toBe(true);
    // Decrypting via the legacy work factor succeeds — proof the tampered
    // 1000-iteration value was never used for derivation.
    const decrypted = await decryptVaultEntries(tampered, "correct horse battery");
    expect(decrypted).toEqual([expect.objectContaining(entries[0])]);
  });

  it("rejects malformed kdf blocks with VAULT_FIELDS", async () => {
    const base = await encryptEntries(entries, "correct horse battery");
    const malformedCases = [
      { ...base, kdf: { algorithm: "PBKDF2", iterations: -1, hash: "SHA-256" } },
      { ...base, kdf: { algorithm: "PBKDF2", iterations: "600000", hash: "SHA-256" } },
      { ...base, kdf: { algorithm: "PBKDF2", iterations: 600000, hash: "MD5" } },
      { ...base, kdf: { algorithm: "ARGON2", iterations: 600000, hash: "SHA-256" } },
      { ...base, kdf: "600000" },
    ];

    for (const payload of malformedCases) {
      await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toMatchObject({
        code: "VAULT_FIELDS",
      });
    }
  });

  it("flags isLegacyEncryptedPayload for missing and sub-floor kdf only", async () => {
    expect(isLegacyEncryptedPayload(null)).toBe(false);
    expect(isLegacyEncryptedPayload({ salt: "a", iv: "b", data: "c" })).toBe(true);
    expect(isLegacyEncryptedPayload({ salt: "a", iv: "b", data: "c", kdf: { iterations: 149999 } })).toBe(true);
    const payload = await encryptEntries(entries, "correct horse battery");
    expect(isLegacyEncryptedPayload(payload)).toBe(false);
  });

  it("scores passphrase strength across the advisory scale", () => {
    expect(assessPassphraseStrength("")).toEqual({ score: 0, label: "Very weak", warnings: ["Enter a passphrase"] });
    expect(assessPassphraseStrength("short").score).toBeLessThanOrEqual(1);

    const weak = assessPassphraseStrength("password123");
    expect(weak.score).toBeLessThanOrEqual(1);
    expect(weak.warnings).toContain("Avoid common words and patterns");

    const fair = assessPassphraseStrength("qwertyuiop"); // 10 chars, one class, common pattern
    expect(fair.score).toBeLessThanOrEqual(1);

    const good = assessPassphraseStrength("CorrectHorse42"); // 14 chars, 3 classes
    expect(good.score).toBe(3);
    expect(good.label).toBe("Good");

    const strong = assessPassphraseStrength("Correct-Horse-Battery-42!");
    expect(strong.score).toBe(4);
    expect(strong.label).toBe("Strong");
    expect(strong.warnings).toEqual([]);
  });

  it("parses plain backups", async () => {
    const backup = await createPlainBackup(entries);
    const parsed = parseBackupFile(backup);

    await expect(parsed).resolves.toEqual(expect.objectContaining({
      encrypted: false,
      integrity: "verified",
      itemCount: 1,
      entries: [expect.objectContaining(entries[0])],
    }));
  });

  it("parses encrypted backups", async () => {
    const backup = createEncryptedBackup(await encryptEntries(entries, "correct horse battery"));
    const parsed = await parseBackupFile(await backup);

    expect(parsed.encrypted).toBe(true);
    expect(parsed.integrity).toBe("verified");
    expect(parsed.vault).toHaveProperty("salt");
    expect(parsed.vault).toHaveProperty("iv");
    expect(parsed.vault).toHaveProperty("data");
  });

  it("parses legacy v1 plain backups that use payload.entries wrapper", async () => {
    const legacyWrappedBackup = {
      version: 1,
      encrypted: false,
      createdAt: "2024-01-01T00:00:00.000Z",
      payload: {
        schemaVersion: 1,
        entries,
      },
    };

    const parsed = await parseBackupFile(legacyWrappedBackup);

    expect(parsed.encrypted).toBe(false);
    expect(parsed.integrity).toBe("legacy");
    expect(parsed.itemCount).toBe(1);
    expect(parsed.entries).toEqual([expect.objectContaining(entries[0])]);
  });

  it("parses legacy v1 encrypted backups that use payload.vault wrapper", async () => {
    const vault = await encryptEntries(entries, "correct horse battery");
    const legacyWrappedEncryptedBackup = {
      version: 1,
      encrypted: true,
      createdAt: "2024-01-01T00:00:00.000Z",
      payload: {
        schemaVersion: 1,
        vault,
      },
    };

    const parsed = await parseBackupFile(legacyWrappedEncryptedBackup);

    expect(parsed.encrypted).toBe(true);
    expect(parsed.integrity).toBe("legacy");
    expect(parsed.itemCount).toBe(0);
    expect(parsed.vault).toEqual(vault);
  });

  it("parses legacy v1 plain backups that omit the encrypted field", async () => {
    const legacyBackupWithoutEncryptedField = {
      version: 1,
      createdAt: "2024-01-01T00:00:00.000Z",
      entries,
    };

    const parsed = await parseBackupFile(legacyBackupWithoutEncryptedField);

    expect(parsed.encrypted).toBe(false);
    expect(parsed.integrity).toBe("legacy");
    expect(parsed.itemCount).toBe(1);
    expect(parsed.entries).toEqual([expect.objectContaining(entries[0])]);
  });

  it("fills a generated id for plain backups with entries missing id", async () => {
    const backup = await createPlainBackup([omitEntryField("id")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.invalidItemCount).toBe(0);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].id).toBeTruthy();
  });

  it("fills a fallback label for plain backups with entries missing label", async () => {
    const backup = await createPlainBackup([omitEntryField("label")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.invalidItemCount).toBe(0);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].label).toContain("Secret");
  });

  it("rejects plain backups with entries missing required secret", async () => {
    const backup = await createPlainBackup([omitEntryField("secret")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries containing an empty secret", async () => {
    const backup = await createPlainBackup([withEntryField("secret", "")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries containing a whitespace-only secret", async () => {
    const backup = await createPlainBackup([withEntryField("secret", "   ")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries containing a non-string secret", async () => {
    const backup = await createPlainBackup([withEntryField("secret", 123456)]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries containing an invalid Base32 secret", async () => {
    const backup = await createPlainBackup([withEntryField("secret", "BAD*")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("fills the current time for plain backups with entries missing createdAt", async () => {
    const backup = await createPlainBackup([omitEntryField("createdAt")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.invalidItemCount).toBe(0);
    expect(parsed.entries).toHaveLength(1);
    expect(typeof parsed.entries[0].createdAt).toBe("number");
  });

  it("fills default digits for plain backups with entries missing digits", async () => {
    const backup = await createPlainBackup([omitEntryField("digits")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.invalidItemCount).toBe(0);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].digits).toBe(6);
  });

  it("fills default period for plain backups with entries missing period", async () => {
    const backup = await createPlainBackup([omitEntryField("period")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.invalidItemCount).toBe(0);
    expect(parsed.entries).toHaveLength(1);
    expect(parsed.entries[0].period).toBe(30);
  });

  it("skips invalid entries in mixed plain backups and reports invalidItemCount", async () => {
    const backup = await createPlainBackup([entries[0], withEntryField("secret", "BAD*")]);
    const parsed = await parseBackupFile(backup);

    expect(parsed.encrypted).toBe(false);
    expect(parsed.itemCount).toBe(2);
    expect(parsed.invalidItemCount).toBe(1);
    expect(parsed.entries).toEqual([expect.objectContaining(entries[0])]);
  });

  it("skips invalid entries in legacy v1 mixed backups and reports invalidItemCount", async () => {
    const legacyMixedBackup = {
      version: 1,
      encrypted: false,
      createdAt: "2024-01-01T00:00:00.000Z",
      entries: [entries[0], withEntryField("secret", "BAD*")],
    };

    const parsed = await parseBackupFile(legacyMixedBackup);

    expect(parsed.encrypted).toBe(false);
    expect(parsed.integrity).toBe("legacy");
    expect(parsed.itemCount).toBe(2);
    expect(parsed.invalidItemCount).toBe(1);
    expect(parsed.entries).toEqual([expect.objectContaining(entries[0])]);
  });

  it("rejects plain backups where every entry is invalid", async () => {
    const backup = await createPlainBackup([withEntryField("secret", "BAD*")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects decrypted vault payloads with entries missing required id", async () => {
    const payload = await encryptEntries([omitEntryField("id")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries missing required label", async () => {
    const payload = await encryptEntries([omitEntryField("label")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries missing required secret", async () => {
    const payload = await encryptEntries([omitEntryField("secret")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries containing an empty secret", async () => {
    const payload = await encryptEntries([withEntryField("secret", "")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries containing an invalid Base32 secret", async () => {
    const payload = await encryptEntries([withEntryField("secret", "BAD*")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries missing required createdAt", async () => {
    const payload = await encryptEntries([omitEntryField("createdAt")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries missing required digits", async () => {
    const payload = await encryptEntries([omitEntryField("digits")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });

  it("rejects decrypted vault payloads with entries missing required period", async () => {
    const payload = await encryptEntries([omitEntryField("period")], "correct horse battery");

    await expect(decryptVaultEntries(payload, "correct horse battery")).rejects.toThrow(
      "Decrypted vault entries are invalid"
    );
  });
});
