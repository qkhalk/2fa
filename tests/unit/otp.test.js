import { describe, expect, it } from "vitest";

import {
  extractOtpAuthUri,
  generateTotp,
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
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256"
    )).toThrow("Only SHA1 TOTP URIs are supported");
  });

  it("rejects issuer mismatches", () => {
    expect(() => parseOtpAuthUri(
      "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitLab"
    )).toThrow("OTP URI issuer does not match the label");
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

  it("generates RFC 6238 test-vector codes", async () => {
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    await expect(generateTotp(secret, 8, 30, 59)).resolves.toBe("94287082");
  });
});
