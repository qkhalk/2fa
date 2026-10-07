import { describe, expect, it } from "vitest";

import {
  base32ToBytes,
  bytesToBase32,
  compareEntries,
  extractOtpAuthUri,
  generateEntryId,
  generateHotp,
  generateTotp,
  hasDuplicateEntry,
  nextOrderValueFrom,
  normalizeEntries,
  normalizeEntry,
  parseOtpAuthUri,
} from "../../lib/otp.js";

describe("otp helpers", () => {
  it("parses valid OTP URIs and normalizes issuer labels", () => {
    const entry = parseOtpAuthUri("otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30");

    expect(entry.label).toBe("GitHub:user@example.com");
    expect(entry.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(entry.digits).toBe(6);
    expect(entry.period).toBe(30);
  });

  it("rejects unsupported OTP algorithms", () => {
    expect(() => parseOtpAuthUri(
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"
    )).toThrow("Only SHA1, SHA256, and SHA512 OTP URIs are supported");
  });

  it("parses SHA-256 and SHA-512 TOTP URIs", () => {
    const sha256 = parseOtpAuthUri(
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256"
    );
    expect(sha256.algorithm).toBe("SHA256");

    const sha512 = parseOtpAuthUri(
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=sha512&digits=8"
    );
    expect(sha512.algorithm).toBe("SHA512");
    expect(sha512.digits).toBe(8);
  });

  it("parses HOTP URIs with counter defaults and validation", () => {
    const withCounter = parseOtpAuthUri(
      "otpauth://hotp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&counter=5"
    );
    expect(withCounter.type).toBe("hotp");
    expect(withCounter.counter).toBe(5);

    const withoutCounter = parseOtpAuthUri(
      "otpauth://hotp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&period=60"
    );
    expect(withoutCounter.type).toBe("hotp");
    expect(withoutCounter.counter).toBe(0);
    // Period is ignored for HOTP; the stored shape keeps the default 30s.
    expect(withoutCounter.period).toBe(30);
  });

  it("rejects invalid HOTP counters", () => {
    expect(() => parseOtpAuthUri(
      "otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&counter=-1"
    )).toThrow("HOTP counter must be a non-negative integer");
    expect(() => parseOtpAuthUri(
      `otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&counter=${Number.MAX_SAFE_INTEGER + 1}`
    )).toThrow("HOTP counter must be a non-negative integer");
    expect(() => parseOtpAuthUri(
      "otpauth://hotp/X:y?secret=JBSWY3DPEHPK3PXP&counter=abc"
    )).toThrow("HOTP counter must be a non-negative integer");
  });

  it("rejects non-otpauth hosts", () => {
    expect(() => parseOtpAuthUri(
      "otpauth://foodir/X:y?secret=JBSWY3DPEHPK3PXP"
    )).toThrow("Only TOTP and HOTP URIs are supported");
  });

  it("rejects issuer mismatches", () => {
    expect(() => parseOtpAuthUri(
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitLab"
    )).toThrow("OTP URI issuer does not match the label");
  });

  it("normalizes issuer/account composition when URI label has surrounding whitespace", () => {
    const entry = parseOtpAuthUri(
      "otpauth://totp/%20%20user%40example.com%20%20?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    );

    expect(entry.label).toBe("GitHub:user@example.com");
  });

  it("uses issuer fallback account label when URI label only contains separators", () => {
    const entry = parseOtpAuthUri(
      "otpauth://totp/GitHub%3A%20%20?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    );

    expect(entry.label).toBe("GitHub:No account label");
  });

  it("uses issuer param when URI label issuer is empty", () => {
    const entry = parseOtpAuthUri(
      "otpauth://totp/%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    );

    expect(entry.label).toBe("GitHub:user@example.com");
  });

  it("extracts encoded OTP URIs from surrounding text", () => {
    const raw = "scan=otpauth%3A%2F%2Ftotp%2FGitHub%3Auser%40example.com%3Fsecret%3DJBSWY3DPEHPK3PXP%26digits%3D6%26period%3D30";
    expect(extractOtpAuthUri(raw)).toBe("otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&digits=6&period=30");
  });

  it("rejects false-positive OTP URI matches with invalid secrets", () => {
    expect(extractOtpAuthUri("otpauth://totp/Foo:bar?secret=BAD*&digits=6&period=30")).toBe("");
  });

  it("normalizes manual entries and rejects invalid periods", () => {
    const entry = normalizeEntry({ label: "", secret: "jbswy3dpehpk3pxp", digits: 6, period: 30 });
    expect(entry.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(entry.label).toContain("Secret");

    expect(() => normalizeEntry({ secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 10 })).toThrow(
      "Period must be an integer between 15 and 120 seconds"
    );
  });

  it("treats normalized tags as duplicates for equivalent OTP settings", () => {
    const existing = normalizeEntry({
      label: "GitHub:user@example.com",
      secret: "JBSW Y3DP EHPK 3PXP",
      digits: 6,
      period: 30,
      tags: " work, ops ",
    });
    const candidate = normalizeEntry({
      label: "GitHub:user@example.com",
      secret: "jbswy3dpehpk3pxp",
      digits: 6,
      period: 30,
      tags: ["ops", "work"],
    });

    expect(hasDuplicateEntry([existing], candidate)).toBe(true);
    expect(existing.tags).toEqual(["work", "ops"]);
  });

  it("uses fallback label when normalizeEntry receives a whitespace-only label", () => {
    const entry = normalizeEntry({
      label: "   ",
      secret: "JBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
    });

    expect(entry.label).toBe("Secret JBSW...3PXP");
  });

  it("preserves the order field through normalizeEntry round-trips", () => {
    const entry = normalizeEntry({ label: "GitHub:user", secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 30, order: 7 });

    expect(entry.order).toBe(7);
    expect(normalizeEntries([entry])[0].order).toBe(7);
  });

  it("defaults the order field to 0 when an entry has no order", () => {
    const entry = normalizeEntry({ label: "GitHub:user", secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 30 });

    expect(entry.order).toBe(0);
  });

  it("sorts by manual order when sortBy is custom", () => {
    const later = normalizeEntry({ label: "A:one", secret: "JBSWY3DPEHPK3PXP", order: 2 });
    const first = normalizeEntry({ label: "B:two", secret: "NB2W45DFOIZA", order: 1 });

    expect(compareEntries(later, first, "custom")).toBe(1);
    expect(compareEntries(first, later, "custom")).toBe(-1);
  });

  it("generates crypto-random entry ids with high entropy", () => {
    const id = generateEntryId();
    expect(id).toMatch(/^entry_[0-9a-z]+_[0-9a-z]+$/);
    expect(generateEntryId()).not.toBe(id);
  });

  it("mints 10k entry ids without collisions", () => {
    const seen = new Set();
    for (let index = 0; index < 10000; index += 1) {
      const id = generateEntryId();
      expect(seen.has(id)).toBe(false);
      seen.add(id);
    }
  });

  it("computes the next manual order value from item lists", () => {
    expect(nextOrderValueFrom([])).toBe(1);
    expect(nextOrderValueFrom([{ order: 3 }, { order: 7 }, {}])).toBe(8);
  });

  it("generates RFC 6238 test-vector codes", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    await expect(generateTotp(secret, 8, 30, 59)).resolves.toBe("94287082");
  });

  it("generates all RFC 4226 Appendix D HOTP vectors", async () => {
    const secretBase32 = bytesToBase32(new Uint8Array(Buffer.from("12345678901234567890", "ascii")));
    const expected = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];

    for (let counter = 0; counter < expected.length; counter += 1) {
      await expect(generateHotp(secretBase32, counter, 6)).resolves.toBe(String(expected[counter]));
    }
  });

  it("generates all RFC 6238 Appendix B vectors across SHA-1/256/512", async () => {
    const seeds = {
      SHA1: bytesToBase32(new Uint8Array(Buffer.from("12345678901234567890", "ascii"))),
      SHA256: bytesToBase32(
        new Uint8Array(Buffer.from("12345678901234567890123456789012", "ascii"))
      ),
      SHA512: bytesToBase32(
        new Uint8Array(Buffer.from("1234567890123456789012345678901234567890123456789012345678901234", "ascii"))
      ),
    };
    const vectors = [
      [59, "94287082", "46119246", "90693936"],
      [1111111109, "07081804", "68084774", "25091201"],
      [1111111111, "14050471", "67062674", "99943326"],
      [1234567890, "89005924", "91819424", "93441116"],
      [2000000000, "69279037", "90698825", "38618901"],
      [20000000000, "65353130", "77737706", "47863826"],
    ];

    for (const [t, sha1, sha256, sha512] of vectors) {
      await expect(generateTotp(seeds.SHA1, 8, 30, t, "SHA1")).resolves.toBe(sha1);
      await expect(generateTotp(seeds.SHA256, 8, 30, t, "SHA256")).resolves.toBe(sha256);
      await expect(generateTotp(seeds.SHA512, 8, 30, t, "SHA512")).resolves.toBe(sha512);
    }
  });

  it("defaults type, counter, and algorithm on legacy entries", () => {
    const entry = normalizeEntry({ label: "Legacy:one", secret: "JBSWY3DPEHPK3PXP", digits: 6, period: 30 });
    expect(entry.type).toBe("totp");
    expect(entry.counter).toBe(0);
    expect(entry.algorithm).toBe("SHA1");
  });

  it("normalizes HOTP entries and forces counter to 0 for TOTP", () => {
    const hotp = normalizeEntry({
      label: "Hotp:one", secret: "JBSWY3DPEHPK3PXP", type: "HOTP", counter: 7, digits: 6, period: 30,
    });
    expect(hotp.type).toBe("hotp");
    expect(hotp.counter).toBe(7);

    const totp = normalizeEntry({
      label: "Totp:one", secret: "JBSWY3DPEHPK3PXP", type: "totp", counter: 9, digits: 6, period: 30,
    });
    expect(totp.counter).toBe(0);

    expect(() => normalizeEntry({
      label: "Bad:type", secret: "JBSWY3DPEHPK3PXP", type: "sotp", digits: 6, period: 30,
    })).toThrow("OTP type must be totp or hotp");
    expect(() => normalizeEntry({
      label: "Bad:counter", secret: "JBSWY3DPEHPK3PXP", type: "hotp", counter: -2, digits: 6, period: 30,
    })).toThrow("HOTP counter must be a non-negative integer");
    expect(() => normalizeEntry({
      label: "Bad:algo", secret: "JBSWY3DPEHPK3PXP", algorithm: "MD5", digits: 6, period: 30,
    })).toThrow("OTP algorithm must be SHA1, SHA256, or SHA512");
  });

  it("preserves type, counter, and algorithm through a backup-style round-trip", () => {
    const entry = normalizeEntry({
      label: "Round:trip", secret: "JBSWY3DPEHPK3PXP", type: "hotp", counter: 42,
      algorithm: "SHA256", digits: 8, period: 30,
    });
    const revived = normalizeEntries(JSON.parse(JSON.stringify([entry])))[0];
    expect(revived.type).toBe("hotp");
    expect(revived.counter).toBe(42);
    expect(revived.algorithm).toBe("SHA256");
  });

  it("round-trips bytes through Base32", () => {
    const samples = [
      new Uint8Array([0, 1, 2, 250, 251, 255]),
      new Uint8Array(Buffer.from("12345678901234567890", "ascii")),
      new Uint8Array([7]),
      new Uint8Array(),
    ];
    for (const bytes of samples) {
      expect(base32ToBytes(bytesToBase32(bytes))).toEqual(bytes);
    }
    expect(bytesToBase32(new Uint8Array([0]))).toBe("AA======".replaceAll("=", ""));
  });
});
