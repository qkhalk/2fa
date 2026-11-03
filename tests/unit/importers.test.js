import { describe, expect, it } from "vitest";

import { MAX_IMPORT_ENTRIES, parse2FasExport, parseAegisExport, parseThirdPartyImport } from "../../lib/importers.js";

const aegisExport = {
  version: 3,
  header: { slots: null, params: null },
  db: {
    version: 1,
    entries: [
      {
        type: "totp",
        uuid: "a1",
        name: "GitHub:user@example.com",
        issuer: "GitHub",
        note: "",
        favorite: false,
        tags: ["work"],
        token: { secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, counter: 0 },
      },
      {
        type: "hotp",
        uuid: "a2",
        name: "Identity Server",
        issuer: "",
        token: { secret: "JBSWY3DPEHPK3PXQ", algorithm: "SHA256", digits: 8, period: 30, counter: 4 },
      },
      {
        type: "steam",
        uuid: "a3",
        name: "Steam:user",
        issuer: "Steam",
        token: { secret: "JBSWY3DPEHPK3PXR", algorithm: "SHA1", digits: 5, period: 30, counter: 0 },
      },
      {
        type: "totp",
        uuid: "a4",
        name: "Broken:entry",
        issuer: "Broken",
        token: { secret: "not base32!!", algorithm: "SHA1", digits: 6, period: 30, counter: 0 },
      },
    ],
  },
};

const twoFasExport = {
  app_version: "6.1.2",
  app_origin: "android",
  services: [
    {
      name: "GitHub",
      secret: "JBSWY3DPEHPK3PXP",
      otp: {
        label: "user@example.com",
        tokenIssuer: "GitHub",
        tokenType: "TOTP",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        counter: 0,
      },
      groupUuid: "g1",
    },
    {
      name: "Cloudflare",
      secret: "JBSWY3DPEHPK3PXQ",
      otp: {
        label: "ops@team.dev",
        tokenIssuer: "Cloudflare",
        tokenType: "HOTP",
        algorithm: "SHA512",
        digits: 8,
        period: 30,
        counter: 2,
      },
      groupUuid: "g1",
    },
    {
      name: "Legacy",
      secret: "",
      otp: { label: "x", tokenIssuer: "Legacy", tokenType: "TOTP", algorithm: "SHA1", digits: 6, period: 30 },
      groupUuid: null,
    },
  ],
  groups: [{ uuid: "g1", name: "Work" }],
};

describe("third-party importers", () => {
  it("parses an Aegis plain-text export into vault candidates", () => {
    const { format, entries, warnings } = parseAegisExport(aegisExport);

    expect(format).toBeUndefined();
    expect(entries).toEqual([
      expect.objectContaining({
        label: "GitHub:user@example.com",
        secret: "JBSWY3DPEHPK3PXP",
        type: "totp",
        algorithm: "SHA1",
        digits: 6,
        period: 30,
        counter: 0,
        tags: ["work"],
      }),
      expect.objectContaining({
        label: "Identity Server",
        type: "hotp",
        algorithm: "SHA256",
        digits: 8,
        counter: 4,
      }),
    ]);
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain("Steam");
    expect(warnings[0]).toContain("unsupported OTP type");
    expect(warnings[1]).toContain("Broken:entry");
  });

  it("rejects encrypted Aegis exports with guidance instead of a shape error", () => {
    const encrypted = {
      version: 3,
      header: { slots: [{ type: 1, uuid: "s" }], params: { nonce: "x" } },
    };

    expect(() => parseAegisExport(encrypted)).toThrow("Re-export from Aegis with the plain-text");
    expect(() => parseAegisExport(encrypted)).toThrowError(
      expect.objectContaining({ code: "IMPORT_ENCRYPTED_UNSUPPORTED" })
    );
  });

  it("defaults missing digits and period to 6 and 30", () => {
    const minimal = {
      header: {},
      db: {
        entries: [
          {
            type: "totp",
            name: "Minimal:entry",
            issuer: "Minimal",
            token: { secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1" },
          },
        ],
      },
    };
    const { entries: parsed, warnings } = parseAegisExport(minimal);

    expect(warnings).toHaveLength(0);
    expect(parsed[0]).toEqual(expect.objectContaining({ digits: 6, period: 30 }));
  });

  it("rejects files that are not Aegis exports", () => {
    expect(() => parseAegisExport({ version: 3, header: {} })).toThrow("does not look like an Aegis export");
  });

  it("parses a 2FAS backup into vault candidates with group tags", () => {
    const { entries, warnings } = parse2FasExport(twoFasExport);

    expect(entries).toEqual([
      expect.objectContaining({
        label: "GitHub:user@example.com",
        secret: "JBSWY3DPEHPK3PXP",
        type: "totp",
        tags: ["Work"],
      }),
      expect.objectContaining({
        label: "Cloudflare:ops@team.dev",
        type: "hotp",
        algorithm: "SHA512",
        digits: 8,
        counter: 2,
        tags: ["Work"],
      }),
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("Legacy");
  });

  it("rejects files that are not 2FAS exports", () => {
    expect(() => parse2FasExport({ app_version: "6" })).toThrow("does not look like a 2FAS export");
  });

  it("detects the format from the file shape", () => {
    expect(parseThirdPartyImport(JSON.stringify(aegisExport)).format).toBe("Aegis");
    expect(parseThirdPartyImport(JSON.stringify(twoFasExport)).format).toBe("2FAS");
  });

  it("fails closed on malformed text and unknown shapes", () => {
    expect(() => parseThirdPartyImport("not json {")).toThrow("Import file is not valid JSON");
    expect(() => parseThirdPartyImport(JSON.stringify({ hello: "world" }))).toThrow(
      "not a recognized Aegis or 2FAS export"
    );
    expect(() => parseThirdPartyImport("[]")).toThrow("not a recognized export format");
  });

  it("caps the entry count with a warning", () => {
    const entries = Array.from({ length: MAX_IMPORT_ENTRIES + 5 }, (_, index) => ({
      type: "totp",
      name: `Service ${index}`,
      issuer: "",
      token: { secret: "JBSWY3DPEHPK3PXP", algorithm: "SHA1", digits: 6, period: 30, counter: 0 },
    }));
    const { entries: parsed, warnings } = parseAegisExport({ header: {}, db: { entries } });

    expect(parsed).toHaveLength(MAX_IMPORT_ENTRIES);
    expect(warnings.at(-1)).toContain("500 entry limit");
  });
});
