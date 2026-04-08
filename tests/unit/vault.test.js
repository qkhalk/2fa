import { describe, expect, it } from "vitest";

import {
  createEncryptedBackup,
  createPlainBackup,
  decryptVaultEntries,
  encryptEntries,
  parseBackupFile,
} from "../../lib/vault.js";

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

  it("rejects plain backups with entries missing required id", async () => {
    const backup = await createPlainBackup([omitEntryField("id")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries missing required label", async () => {
    const backup = await createPlainBackup([omitEntryField("label")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
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

  it("rejects plain backups with entries missing required createdAt", async () => {
    const backup = await createPlainBackup([omitEntryField("createdAt")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries missing required digits", async () => {
    const backup = await createPlainBackup([omitEntryField("digits")]);

    await expect(parseBackupFile(backup)).rejects.toThrow("Backup contains invalid entries");
  });

  it("rejects plain backups with entries missing required period", async () => {
    const backup = await createPlainBackup([omitEntryField("period")]);

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
