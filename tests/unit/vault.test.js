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
});
