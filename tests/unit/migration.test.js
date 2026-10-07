import { describe, expect, it } from "vitest";

import { OtpVaultError, base32ToBytes } from "../../lib/otp.js";
import {
  MAX_BATCH_SIZE,
  MAX_PAYLOAD_BYTES,
  MAX_STITCHED_ENTRIES,
  b64DecodeBytes,
  decodeMigrationPayload,
  decodeOtpParameters,
  migrationToEntryCandidates,
  parseMigrationUri,
  stitchMigrationBatches,
} from "../../lib/migration.js";

// --- test-local protobuf encoders (fixtures are hand-built binary) ---

function encodeVarint(value) {
  let current = BigInt(value);
  const bytes = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current > 0n) byte |= 0x80;
    bytes.push(byte);
  } while (current > 0n);
  return bytes;
}

function encodeTag(fieldNumber, wireType) {
  return encodeVarint((fieldNumber << 3) | wireType);
}

function encodeLenField(fieldNumber, payload) {
  return [...encodeTag(fieldNumber, 2), ...encodeVarint(payload.length), ...payload];
}

function encodeVarintField(fieldNumber, value) {
  return [...encodeTag(fieldNumber, 0), ...encodeVarint(value)];
}

function utf8Bytes(value) {
  return Array.from(new TextEncoder().encode(value));
}

function encodeOtpParameters(options) {
  const out = [];
  if (options.secret !== undefined) out.push(...encodeLenField(1, options.secret));
  if (options.name !== undefined) out.push(...encodeLenField(2, utf8Bytes(options.name)));
  if (options.issuer !== undefined) out.push(...encodeLenField(3, utf8Bytes(options.issuer)));
  if (options.algorithm !== undefined) out.push(...encodeVarintField(4, options.algorithm));
  if (options.digits !== undefined) out.push(...encodeVarintField(5, options.digits));
  if (options.type !== undefined) out.push(...encodeVarintField(6, options.type));
  if (options.counter !== undefined) out.push(...encodeVarintField(7, options.counter));
  return out;
}

function encodeMigrationPayload(options) {
  const out = [];
  for (const entry of options.entries || []) out.push(...encodeLenField(1, entry));
  if (options.version !== undefined) out.push(...encodeVarintField(2, options.version));
  if (options.batchSize !== undefined) out.push(...encodeVarintField(3, options.batchSize));
  if (options.batchIndex !== undefined) out.push(...encodeVarintField(4, options.batchIndex));
  if (options.batchId !== undefined) out.push(...encodeVarintField(5, options.batchId));
  for (const extra of options.extra || []) out.push(...extra);
  return new Uint8Array(out);
}

function toMigrationUri(payloadBytes) {
  const base64 = Buffer.from(payloadBytes).toString("base64");
  return `otpauth-migration://offline?data=${encodeURIComponent(base64)}`;
}

function expectErrorCode(fn, code) {
  let caught;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(OtpVaultError);
  expect(caught.code).toBe(code);
}

describe("otpauth-migration import", () => {
  it("decodes a two-entry payload with TOTP and HOTP parameters (fixture a)", () => {
    const payload = encodeMigrationPayload({
      entries: [
        encodeOtpParameters({
          secret: Array.from(base32ToBytes("JBSWY3DPEHPK3PXP")),
          name: "alice@example.com",
          issuer: "GitHub",
          algorithm: 1, // SHA1
          digits: 1, // 6
          type: 2, // TOTP
        }),
        encodeOtpParameters({
          secret: Array.from(base32ToBytes("GEZDGNBVGY3TQOJQ")),
          name: "bob@example.com",
          issuer: "",
          algorithm: 2, // SHA256
          digits: 2, // 8
          type: 1, // HOTP
          counter: 5,
        }),
      ],
      version: 1,
      batchSize: 1,
      batchIndex: 0,
      batchId: 77,
    });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.warnings).toEqual([]);
    expect(result.batch).toEqual({ size: 1, index: 0, id: 77 });
    expect(result.entries).toHaveLength(2);

    // Raw QR-enum values survive on OtpParameters; counter stays BigInt.
    expect(result.entries[0].type).toBe(2);
    expect(result.entries[1].type).toBe(1);
    expect(result.entries[1].algorithm).toBe(2);
    expect(result.entries[1].counter).toBe(5n);

    const [totp, hotp] = migrationToEntryCandidates(result.entries);
    expect(totp).toEqual({
      label: "GitHub:alice@example.com",
      secret: "JBSWY3DPEHPK3PXP",
      digits: 6,
      period: 30,
      type: "totp",
      counter: 0,
      algorithm: "SHA1",
    });
    expect(hotp.type).toBe("hotp");
    expect(hotp.algorithm).toBe("SHA256");
    expect(hotp.digits).toBe(8);
    expect(hotp.counter).toBe(5);
    expect(hotp.label).toBe("bob@example.com");
    expect(base32ToBytes(hotp.secret)).toEqual(base32ToBytes("GEZDGNBVGY3TQOJQ"));
  });

  it("splits issuer from the name at the first colon when issuer is empty (fixture b)", () => {
    const payload = encodeMigrationPayload({
      entries: [
        encodeOtpParameters({ secret: [1, 2, 3, 4], name: "AWS: iam@prod", algorithm: 1, digits: 1, type: 2 }),
        encodeOtpParameters({ secret: [5, 6, 7, 8], name: "Issuer:acct:with:colons", algorithm: 1, digits: 1, type: 2 }),
        encodeOtpParameters({ secret: [9, 10, 11, 12], name: "plain-account", algorithm: 1, digits: 1, type: 2 }),
        encodeOtpParameters({
          secret: [13, 14, 15, 16],
          name: "GitHub:alice@example.com",
          issuer: "GitHub",
          algorithm: 1,
          digits: 1,
          type: 2,
        }),
      ],
      batchSize: 1,
      batchIndex: 0,
      batchId: 1,
    });

    const result = parseMigrationUri(toMigrationUri(payload));
    const labels = migrationToEntryCandidates(result.entries).map((candidate) => candidate.label);
    expect(labels).toEqual([
      "AWS:iam@prod",
      "Issuer:acct:with:colons",
      "plain-account",
      "GitHub:alice@example.com",
    ]);
  });

  it("skips MD5 and unknown-algorithm entries with warnings, importing nothing from an all-bad payload (fixture c)", () => {
    const payload = encodeMigrationPayload({
      entries: [
        encodeOtpParameters({ secret: [1, 2, 3], name: "MD5 Token", algorithm: 4, digits: 1, type: 2 }),
        encodeOtpParameters({ secret: [4, 5, 6], name: "Alien Token", algorithm: 9, digits: 1, type: 2 }),
      ],
      batchSize: 1,
      batchIndex: 0,
      batchId: 2,
    });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.entries).toHaveLength(0);
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]).toContain("MD5 Token");
    expect(result.warnings[0]).toContain("MD5");
    expect(result.warnings[1]).toContain("Alien Token");
  });

  it("defaults digits/type/algorithm 0 and absent fields to 6 digits, TOTP, SHA1 (fixture d)", () => {
    const payload = encodeMigrationPayload({
      entries: [
        encodeOtpParameters({ secret: [9, 9, 9], algorithm: 0, digits: 0, type: 0 }),
        encodeOtpParameters({ secret: [8, 8, 8] }),
      ],
      batchSize: 1,
      batchIndex: 0,
      batchId: 3,
    });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.entries).toHaveLength(2);
    const candidates = migrationToEntryCandidates(result.entries);
    for (const candidate of candidates) {
      expect(candidate.digits).toBe(6);
      expect(candidate.type).toBe("totp");
      expect(candidate.algorithm).toBe("SHA1");
      expect(candidate.period).toBe(30);
    }
  });

  it("stitches batches in batch_index order and dedupes by secret and name (fixture e)", () => {
    const entry = (secretBytes, name) =>
      encodeOtpParameters({ secret: secretBytes, name, algorithm: 1, digits: 1, type: 2 });
    const payload = (batchIndex, entries) =>
      encodeMigrationPayload({ entries, batchSize: 3, batchIndex, batchId: 42 });

    // Scanned out of order; payload index 2 re-sends entry (1, "a@x") already in index 0.
    const scanned = [
      payload(2, [entry([4], "d@x"), entry([1], "a@x")]),
      payload(0, [entry([1], "a@x"), entry([2], "b@x")]),
      payload(1, [entry([3], "c@x")]),
    ];

    const result = stitchMigrationBatches(scanned);
    expect(result.warnings).toEqual([]);
    expect(result.batches).toEqual([{ id: 42, size: 3, scannedIndexes: [0, 1, 2] }]);
    expect(result.entries.map((params) => params.name)).toEqual(["a@x", "b@x", "c@x", "d@x"]);
  });

  it("parses standard base64 with percent-encoded +/=/ and restores +-as-space corruption (fixture f)", () => {
    // These bytes encode to "+/+pw==": standard base64 containing '+', '/' and padding.
    const secretBytes = [0xfb, 0xff, 0xbf, 0xa7];
    const payload = encodeMigrationPayload({
      entries: [encodeOtpParameters({ secret: secretBytes, name: "Plus Test", algorithm: 1, digits: 1, type: 2 })],
      // batchId 250 encodes to varint [0xfa, 0x01], which lands the payload's
      // final base64 group on '+' — keep the fixture containing +, / and =.
      batchSize: 1,
      batchIndex: 0,
      batchId: 250,
    });
    const base64 = Buffer.from(payload).toString("base64");
    expect(base64).toContain("+");
    expect(base64).toContain("/");
    expect(base64).toContain("=");

    const canonical = parseMigrationUri(`otpauth-migration://offline?data=${encodeURIComponent(base64)}`);
    // Literal (unencoded) '+' '/' '=' in the query string.
    const literal = parseMigrationUri(`otpauth-migration://offline?data=${base64}`);
    // A producer that mangled '+' into '%20' (form-urlencoded damage).
    const mangled = parseMigrationUri(
      `otpauth-migration://offline?data=${encodeURIComponent(base64).replace(/%2B/g, "%20")}`
    );

    for (const result of [literal, mangled]) {
      expect(result.entries).toHaveLength(1);
      const [candidate] = migrationToEntryCandidates(result.entries);
      const [expected] = migrationToEntryCandidates(canonical.entries);
      expect(candidate).toEqual(expected);
    }
    const [candidate] = migrationToEntryCandidates(canonical.entries);
    expect(Array.from(base32ToBytes(candidate.secret))).toEqual(secretBytes);
  });

  it("tolerates base64url data without padding (fixture g)", () => {
    const payload = encodeMigrationPayload({
      entries: [encodeOtpParameters({ secret: [0xfb, 0xff, 0xbf, 0xa7], name: "UrlSafe", algorithm: 1, digits: 1, type: 2 })],
      batchSize: 1,
      batchIndex: 0,
      batchId: 4,
    });
    const urlSafe = Buffer.from(payload)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const result = parseMigrationUri(`otpauth-migration://offline?data=${urlSafe}`);
    expect(result.warnings).toEqual([]);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].name).toBe("UrlSafe");
    expect(result.entries[0].secret).toEqual(new Uint8Array([0xfb, 0xff, 0xbf, 0xa7]));
  });

  it("skips unknown fields of every wire type at both payload and entry level (fixture h)", () => {
    const entryWithUnknowns = [
      ...encodeVarintField(99, 300),
      ...encodeLenField(99, [1, 2, 3]),
      ...encodeOtpParameters({
        secret: [1, 2, 3, 4, 5, 6, 7, 8],
        name: "Known",
        issuer: "Iss",
        algorithm: 1,
        digits: 1,
        type: 2,
      }),
      ...encodeTag(99, 1),
      ...Array(8).fill(0xaa),
      ...encodeTag(99, 5),
      ...[0xde, 0xad, 0xbe, 0xef],
    ];
    const payload = encodeMigrationPayload({
      entries: [entryWithUnknowns],
      batchSize: 1,
      batchIndex: 0,
      batchId: 5,
      extra: [
        encodeVarintField(99, 7),
        encodeLenField(98, [9, 9]),
        [...encodeTag(97, 1), ...Array(8).fill(0)],
        [...encodeTag(96, 5), 1, 2, 3, 4],
      ],
    });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.warnings).toEqual([]);
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].name).toBe("Known");
    expect(result.entries[0].issuer).toBe("Iss");
    expect(result.entries[0].secret).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
  });

  it("throws MIGRATION_DATA_MALFORMED on truncated varints, truncated fields and group wire types (fixture i)", () => {
    // Varint continuation byte with nothing after it (payload level).
    const truncatedVarint = new Uint8Array([...encodeTag(3, 0), 0x80]);
    expectErrorCode(() => parseMigrationUri(toMigrationUri(truncatedVarint)), "MIGRATION_DATA_MALFORMED");
    expectErrorCode(() => decodeMigrationPayload(truncatedVarint), "MIGRATION_DATA_MALFORMED");

    // Varint cut off inside an OtpParameters submessage.
    const truncatedEntryVarint = new Uint8Array(
      encodeMigrationPayload({
        entries: [[...encodeTag(4, 0), 0x80]],
        batchSize: 1,
        batchIndex: 0,
      })
    );
    expectErrorCode(() => decodeMigrationPayload(truncatedEntryVarint), "MIGRATION_DATA_MALFORMED");

    // Length-delimited field claims 10 bytes, only 2 follow.
    const truncatedLength = new Uint8Array([...encodeTag(1, 2), 0x0a, 0x01, 0x02]);
    expectErrorCode(() => decodeMigrationPayload(truncatedLength), "MIGRATION_DATA_MALFORMED");

    // Deprecated group start (wire type 3).
    const groupField = new Uint8Array([...encodeTag(2, 3)]);
    expectErrorCode(() => decodeMigrationPayload(groupField), "MIGRATION_DATA_MALFORMED");
  });

  it("decodes a 10-byte varint int64 counter (fixture j)", () => {
    // Value 5 redundantly encoded across 10 bytes (0x85 then 8x 0x80, terminator 0x00).
    const paddedFive = [0x85, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    const entry = [
      ...encodeOtpParameters({ secret: [1, 2, 3], name: "Padded Counter", algorithm: 1, digits: 1, type: 1 }),
      ...encodeTag(7, 0),
      ...paddedFive,
    ];
    const payload = encodeMigrationPayload({ entries: [entry], batchSize: 1, batchIndex: 0, batchId: 6 });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.entries).toHaveLength(1);
    expect(result.entries[0].counter).toBe(5n);
    expect(migrationToEntryCandidates(result.entries)[0].counter).toBe(5);
  });

  it("rejects negative two's-complement counters with a warning", () => {
    const entry = [
      ...encodeOtpParameters({ secret: [1, 2, 3], name: "Negative Counter", algorithm: 1, digits: 1, type: 1 }),
      ...encodeVarintField(7, (1n << 64n) - 1n), // -1 as int64, 10-byte varint
    ];
    const payload = encodeMigrationPayload({ entries: [entry], batchSize: 1, batchIndex: 0, batchId: 6 });

    const result = parseMigrationUri(toMigrationUri(payload));
    expect(result.entries).toHaveLength(0);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("Negative Counter");
    expect(result.warnings[0]).toContain("counter");
  });

  it("rejects batch_index outside [0, batch_size) (fixture k)", () => {
    const payload = encodeMigrationPayload({
      entries: [encodeOtpParameters({ secret: [1, 2, 3], algorithm: 1, digits: 1, type: 2 })],
      batchSize: 2,
      batchIndex: 2,
      batchId: 1,
    });
    expectErrorCode(() => parseMigrationUri(toMigrationUri(payload)), "MIGRATION_DATA_MALFORMED");
    expectErrorCode(() => stitchMigrationBatches([payload]), "MIGRATION_DATA_MALFORMED");
  });

  it("rejects batch_size above the cap (fixture k)", () => {
    const payload = encodeMigrationPayload({
      entries: [encodeOtpParameters({ secret: [1, 2, 3], algorithm: 1, digits: 1, type: 2 })],
      batchSize: MAX_BATCH_SIZE + 1,
      batchIndex: 0,
      batchId: 1,
    });
    expectErrorCode(() => parseMigrationUri(toMigrationUri(payload)), "MIGRATION_DATA_MALFORMED");
    expectErrorCode(() => stitchMigrationBatches([payload]), "MIGRATION_DATA_MALFORMED");
  });

  it("rejects oversized per-payload byte input before decoding (fixture k)", () => {
    const oversized = new Uint8Array(MAX_PAYLOAD_BYTES + 1);
    expectErrorCode(() => stitchMigrationBatches([oversized]), "MIGRATION_DATA_MALFORMED");
    expectErrorCode(() => parseMigrationUri(toMigrationUri(oversized)), "MIGRATION_DATA_MALFORMED");
  });

  it("caps stitched entries at 500 with a warning (fixture k)", () => {
    const payloads = [];
    for (let payloadIndex = 0; payloadIndex < 2; payloadIndex += 1) {
      const entries = [];
      for (let i = 0; i < 300; i += 1) {
        const n = payloadIndex * 300 + i;
        entries.push(
          encodeOtpParameters({
            secret: [n & 0xff, (n >> 8) & 0xff],
            algorithm: 1,
            digits: 1,
            type: 2,
          })
        );
      }
      payloads.push(encodeMigrationPayload({ entries, batchSize: 2, batchIndex: payloadIndex, batchId: 9 }));
    }

    const result = stitchMigrationBatches(payloads);
    expect(result.entries).toHaveLength(MAX_STITCHED_ENTRIES);
    expect(result.batches).toEqual([{ id: 9, size: 2, scannedIndexes: [0, 1] }]);
    expect(result.warnings.some((warning) => warning.includes(String(MAX_STITCHED_ENTRIES)))).toBe(true);
  });

  it("rejects non-migration URIs and missing or malformed data parameters", () => {
    expectErrorCode(() => parseMigrationUri("otpauth://totp/GitHub:alice?secret=ABC"), "MIGRATION_URI_INVALID");
    expectErrorCode(() => parseMigrationUri("otpauth-migration://offline?foo=bar"), "MIGRATION_URI_INVALID");
    expectErrorCode(() => parseMigrationUri("not a uri"), "MIGRATION_URI_INVALID");
    expectErrorCode(() => parseMigrationUri("otpauth-migration://offline?data=!!!!"), "MIGRATION_DATA_MALFORMED");
    expectErrorCode(() => b64DecodeBytes("ABCDE"), "MIGRATION_DATA_MALFORMED");
  });

  it("exposes the wire decoders directly for tests and tooling", () => {
    const empty = decodeMigrationPayload(new Uint8Array(0));
    expect(empty).toEqual({ entries: [], version: 0, batchSize: 1, batchIndex: 0, batchId: 0 });
    expect(stitchMigrationBatches([])).toEqual({ entries: [], warnings: [], batches: [] });

    const raw = decodeOtpParameters(
      new Uint8Array(encodeOtpParameters({ secret: [1, 2, 3], name: "N", type: 1, counter: 9 }))
    );
    expect(raw.name).toBe("N");
    expect(raw.type).toBe(1);
    expect(raw.counter).toBe(9n);
    expect(raw.secret).toEqual(new Uint8Array([1, 2, 3]));
  });
});
