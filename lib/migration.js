// Google Authenticator export import ("otpauth-migration://offline?data=<base64 protobuf>").
//
// The wire format is reverse-engineered (Google never published the .proto); two
// independent sources agree on every field number and enum value:
//   - https://alexbakker.me/post/parsing-google-auth-export-qr-code.html (Aegis author)
//   - https://github.com/qistoph/otp_export (OtpMigration.proto)
//
// The decoder is total on unknown fields and fails closed only on truncated or
// malformed structure. Decoded secrets are never logged (NFR3): warnings carry
// counts and entry labels only, never secret material.

import { OtpVaultError } from "./otp.js";

// Fail-closed limits (phase-04 FR1 / red-team notes). MAX_BATCH_SIZE bounds the
// QR count of one export; MAX_PAYLOAD_BYTES bounds each payload's decoded byte
// length BEFORE the protobuf walk so a crafted QR cannot balloon memory;
// MAX_STITCHED_ENTRIES caps total accumulation so an import loop always
// terminates with a bounded result.
export const MAX_BATCH_SIZE = 10;
export const MAX_STITCHED_ENTRIES = 500;
export const MAX_PAYLOAD_BYTES = 64 * 1024;

const MAX_SAFE_COUNTER = BigInt(Number.MAX_SAFE_INTEGER);
// QR enum: 0 = unspecified, 1 = SHA1, 2 = SHA256, 3 = SHA512, 4 = MD5 (skip:
// WebCrypto has no MD5 and carrying it is a security downgrade), >4 unknown.
const ALGORITHM_NAMES = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 3548; padding omitted by app convention
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_LOOKUP = new Int8Array(256).fill(-1);
for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
  BASE64_LOOKUP[BASE64_ALPHABET.charCodeAt(index)] = index;
}
const TEXT_DECODER = new TextDecoder("utf-8");

function malformed(message) {
  return new OtpVaultError(message, { code: "MIGRATION_DATA_MALFORMED" });
}

function toInt32(value) {
  return Number(BigInt.asIntN(32, value));
}

// Varint: 1-10 bytes, low 7 bits little-endian, MSB = continuation. Returns a
// BigInt so int64 counters survive; callers narrow with asIntN where needed.
function varint(bytes, pos) {
  let value = 0n;
  let shift = 0n;
  for (;;) {
    if (pos >= bytes.length) {
      throw malformed("Migration payload ends inside a varint");
    }
    const byte = bytes[pos];
    pos += 1;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [value, pos];
    shift += 7n;
    if (shift >= 70n) {
      throw malformed("Migration payload contains an overlong varint");
    }
  }
}

// Skip an unknown field using its wire type (proto3 contract). Wire types 3/4
// (deprecated groups) and 6/7 are invalid; reject instead of guessing.
function skipField(bytes, pos, wireType) {
  if (wireType === 0) return varint(bytes, pos)[1];
  if (wireType === 1) {
    if (pos + 8 > bytes.length) throw malformed("Migration payload has a truncated fixed64 field");
    return pos + 8;
  }
  if (wireType === 2) return lenBytes(bytes, pos)[1];
  if (wireType === 5) {
    if (pos + 4 > bytes.length) throw malformed("Migration payload has a truncated fixed32 field");
    return pos + 4;
  }
  throw malformed(`Migration payload uses unsupported wire type ${wireType}`);
}

function lenBytes(bytes, pos) {
  const [length, start] = varint(bytes, pos);
  const end = start + Number(length);
  if (end > bytes.length) {
    throw malformed("Migration payload has a truncated length-delimited field");
  }
  return [bytes.subarray(start, end), end];
}

// OtpParameters (wire defaults follow proto3: absent fields are 0/unspecified).
// counter stays a BigInt on the wire object; candidate mapping narrows it.
export function decodeOtpParameters(bytes) {
  const params = { secret: new Uint8Array(0), name: "", issuer: "", algorithm: 0, digits: 0, type: 0, counter: 0n };
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      [params.secret, pos] = lenBytes(bytes, pos);
    } else if ((field === 2 || field === 3) && wireType === 2) {
      const [value, after] = lenBytes(bytes, pos);
      pos = after;
      const text = TEXT_DECODER.decode(value);
      if (field === 2) params.name = text;
      else params.issuer = text;
    } else if (field >= 4 && field <= 6 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      if (field === 4) params.algorithm = Number(value);
      else if (field === 5) params.digits = Number(value);
      else params.type = Number(value);
    } else if (field === 7 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      params.counter = BigInt.asIntN(64, value);
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return params;
}

// One top-level walk that records entry byte ranges without decoding them, so
// untrusted batch metadata can be validated BEFORE any entry is decoded.
function scanPayload(bytes) {
  const entryRanges = [];
  let version;
  let batchSize;
  let batchIndex;
  let batchId;
  let pos = 0;
  while (pos < bytes.length) {
    const [key, next] = varint(bytes, pos);
    pos = next;
    const field = Number(key >> 3n);
    const wireType = Number(key & 7n);
    if (field === 1 && wireType === 2) {
      const [length, start] = varint(bytes, pos);
      const end = start + Number(length);
      if (end > bytes.length) throw malformed("Migration payload has a truncated entry");
      entryRanges.push([start, end]);
      pos = end;
    } else if (field >= 2 && field <= 5 && wireType === 0) {
      const [value, after] = varint(bytes, pos);
      pos = after;
      // int32 scalars: last occurrence wins (proto3).
      if (field === 2) version = value;
      else if (field === 3) batchSize = value;
      else if (field === 4) batchIndex = value;
      else batchId = value;
    } else {
      pos = skipField(bytes, pos, wireType);
    }
  }
  return { entryRanges, version, batchSize, batchIndex, batchId };
}

export function decodeMigrationPayload(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw malformed("Migration payload must be raw bytes");
  }
  if (bytes.length > MAX_PAYLOAD_BYTES) {
    throw malformed(`Migration payload exceeds the ${MAX_PAYLOAD_BYTES} byte limit`);
  }

  const scanned = scanPayload(bytes);
  const batchSize = scanned.batchSize === undefined ? 1 : toInt32(scanned.batchSize);
  const batchIndex = scanned.batchIndex === undefined ? 0 : toInt32(scanned.batchIndex);
  if (batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
    throw malformed(`Migration batch size ${batchSize} is outside the allowed range 1-${MAX_BATCH_SIZE}`);
  }
  if (batchIndex < 0 || batchIndex >= batchSize) {
    throw malformed(`Migration batch index ${batchIndex} is outside the batch size ${batchSize}`);
  }

  const entries = scanned.entryRanges.map(([start, end]) => decodeOtpParameters(bytes.subarray(start, end)));
  return {
    entries,
    version: scanned.version === undefined ? 0 : toInt32(scanned.version),
    batchSize,
    batchIndex,
    batchId: scanned.batchId === undefined ? 0 : toInt32(scanned.batchId),
  };
}

// Standard base64 decoder that also tolerates base64url (- and _), missing
// padding, and stray whitespace. Invalid characters fail closed.
export function b64DecodeBytes(value) {
  if (typeof value !== "string") {
    throw malformed("Migration data must be a base64 string");
  }
  const normalized = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (normalized.length % 4 === 1) {
    throw malformed("Migration data is not valid base64");
  }
  // Refuse inputs that could decode past MAX_PAYLOAD_BYTES before allocating.
  if (normalized.length > Math.ceil(MAX_PAYLOAD_BYTES / 3) * 4) {
    throw malformed(`Migration data exceeds the ${MAX_PAYLOAD_BYTES} byte payload limit`);
  }

  const out = new Uint8Array(Math.ceil((normalized.length * 3) / 4));
  let outLength = 0;
  let acc = 0;
  let bits = 0;
  for (let index = 0; index < normalized.length; index += 1) {
    const code = normalized.charCodeAt(index);
    const decoded = code < 256 ? BASE64_LOOKUP[code] : -1;
    if (decoded === -1) {
      throw malformed("Migration data is not valid base64");
    }
    acc = (acc << 6) | decoded;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[outLength] = (acc >>> bits) & 0xff;
      outLength += 1;
    }
  }
  return out.subarray(0, outLength);
}

// The data param is percent-encoded STANDARD base64 (+ / =). URLSearchParams
// would corrupt it by turning '+' into space, so the query is parsed manually
// and any literal space (form-urlencoded damage) is restored to '+'.
export function parseMigrationUri(uri) {
  const raw = typeof uri === "string" ? uri.trim() : "";
  if (!raw.toLowerCase().startsWith("otpauth-migration://")) {
    throw new OtpVaultError("URI must be an otpauth-migration:// export URI", { code: "MIGRATION_URI_INVALID" });
  }

  const queryIndex = raw.indexOf("?");
  if (queryIndex === -1) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }
  let dataParam;
  for (const pair of raw.slice(queryIndex + 1).split("&")) {
    const equals = pair.indexOf("=");
    const key = equals === -1 ? pair : pair.slice(0, equals);
    if (key.toLowerCase() === "data") {
      dataParam = equals === -1 ? "" : pair.slice(equals + 1);
      break;
    }
  }
  if (!dataParam) {
    throw new OtpVaultError("Migration URI is missing the data parameter", { code: "MIGRATION_URI_INVALID" });
  }

  let data = dataParam;
  try {
    data = decodeURIComponent(dataParam);
  } catch {
    // Keep the raw value; base64 validation below fails closed on garbage.
  }
  data = data.replace(/ /g, "+");

  const payload = decodeMigrationPayload(b64DecodeBytes(data));
  const { entries, warnings } = filterMigrationEntries(payload.entries);
  return {
    entries,
    warnings,
    batch: { size: payload.batchSize, index: payload.batchIndex, id: payload.batchId },
    // Raw decoded payload bytes so multi-QR camera flows can accumulate and
    // stitch via stitchMigrationBatches without re-parsing the URI.
    payloadBytes: b64DecodeBytes(data),
  };
}

// Label-ish text for warnings: labels only, never secrets (NFR3).
function entryDisplayName(params) {
  const name = (params.name || "").trim();
  if (name) return name;
  const issuer = (params.issuer || "").trim();
  return issuer || "unnamed entry";
}

// One bad entry never aborts the batch; every skipped token is reported.
function filterMigrationEntries(rawEntries) {
  const entries = [];
  const warnings = [];
  for (const params of rawEntries) {
    const label = entryDisplayName(params);
    if (!params.secret.length) {
      warnings.push(`Skipped "${label}": entry has no secret`);
      continue;
    }
    if (params.algorithm === 4) {
      warnings.push(`Skipped "${label}": unsupported algorithm (MD5)`);
      continue;
    }
    if (params.algorithm > 3) {
      warnings.push(`Skipped "${label}": unsupported algorithm (code ${params.algorithm})`);
      continue;
    }
    if (params.digits > 2) {
      warnings.push(`Skipped "${label}": unsupported digits code ${params.digits}`);
      continue;
    }
    if (params.type > 2) {
      warnings.push(`Skipped "${label}": unsupported OTP type code ${params.type}`);
      continue;
    }
    if (params.counter < 0n) {
      warnings.push(`Skipped "${label}": invalid negative HOTP counter`);
      continue;
    }
    if (params.counter > MAX_SAFE_COUNTER) {
      warnings.push(`Skipped "${label}": HOTP counter exceeds the supported range`);
      continue;
    }
    entries.push(params);
  }
  return { entries, warnings };
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Local RFC 3548 base32 encoder (no padding). A shared bytesToBase32 export
// will move to lib/otp.js in a later step; this keeps the module self-contained.
function bytesToBase32(bytes) {
  let output = "";
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(acc << (5 - bits)) & 31];
  return output;
}

function buildMigrationLabel(params) {
  const issuer = (params.issuer || "").trim();
  const name = (params.name || "").trim();
  if (!issuer) {
    // GA often leaves issuer empty and stores "Issuer:account" in the name;
    // split at the FIRST colon and trim the account (Aegis production rule).
    const colon = name.indexOf(":");
    if (colon === -1) return name;
    const nameIssuer = name.slice(0, colon).trim();
    const account = name.slice(colon + 1).trim();
    if (!account) return nameIssuer;
    if (!nameIssuer) return account;
    return `${nameIssuer}:${account}`;
  }
  if (!name) return issuer;
  if (name.toLowerCase().startsWith(`${issuer.toLowerCase()}:`)) return name;
  return `${issuer}:${name}`;
}

// Map decoded OtpParameters to plain vault entry candidates. Does NOT call
// normalizeEntry: Phase 3 extends it with type/counter/algorithm, and this
// module must stay usable before that lands. Inputs are expected to come from
// parseMigrationUri/stitchMigrationBatches (already filtered); direct calls
// with unmappable enum values fail closed.
export function migrationToEntryCandidates(entries) {
  const source = Array.isArray(entries) ? entries : [];
  return source.map((params) => {
    const algorithm = ALGORITHM_NAMES[params.algorithm];
    if (!algorithm) {
      throw malformed(`Unsupported migration algorithm code ${params.algorithm}`);
    }
    if (params.digits !== 0 && params.digits !== 1 && params.digits !== 2) {
      throw malformed(`Unsupported migration digits code ${params.digits}`);
    }
    if (params.type !== 0 && params.type !== 1 && params.type !== 2) {
      throw malformed(`Unsupported migration OTP type code ${params.type}`);
    }
    const counter = BigInt(params.counter ?? 0n);
    if (counter < 0n || counter > MAX_SAFE_COUNTER) {
      throw malformed("Migration HOTP counter is outside the supported range");
    }
    return {
      label: buildMigrationLabel(params),
      secret: bytesToBase32(params.secret),
      digits: params.digits === 2 ? 8 : 6, // QR enum: 0 unspecified, 1 = SIX, 2 = EIGHT
      period: 30, // the payload has no period field; GA assumes 30s
      // CRITICAL: the migration QR enum order (1 = HOTP, 2 = TOTP) is the
      // OPPOSITE of Google Authenticator's internal SQLite DB order
      // (TOTP = 0, HOTP = 1 — see Aegis GoogleAuthImporter). Never share one
      // mapping between the two formats.
      type: params.type === 1 ? "hotp" : "totp",
      counter: Number(counter),
      algorithm,
    };
  });
}

// Stitch independently decodable per-QR payloads. Groups by batch_id, orders
// entries by batch_index, dedupes by (secret, name). Returns one batch summary
// per group (multiple export attempts can be scanned into one session).
export function stitchMigrationBatches(payloads) {
  if (!Array.isArray(payloads)) {
    throw malformed("Migration payloads must be an array of byte arrays");
  }

  const warnings = [];
  const groups = new Map();
  for (const bytes of payloads) {
    const payload = decodeMigrationPayload(bytes);
    const { entries, warnings: entryWarnings } = filterMigrationEntries(payload.entries);
    warnings.push(...entryWarnings);
    let group = groups.get(payload.batchId);
    if (!group) {
      group = { id: payload.batchId, size: payload.batchSize, scanned: new Set(), buckets: new Map() };
      groups.set(payload.batchId, group);
    }
    if (group.size !== payload.batchSize) {
      throw malformed("Migration payloads disagree on the batch size");
    }
    group.scanned.add(payload.batchIndex);
    if (!group.buckets.has(payload.batchIndex)) {
      group.buckets.set(payload.batchIndex, []);
    }
    group.buckets.get(payload.batchIndex).push(...entries);
  }

  const entries = [];
  const batches = [];
  const seen = new Set();
  let capped = false;
  outer: for (const group of groups.values()) {
    batches.push({
      id: group.id,
      size: group.size,
      scannedIndexes: [...group.scanned].sort((a, b) => a - b),
    });
    for (let index = 0; index < group.size; index += 1) {
      for (const params of group.buckets.get(index) || []) {
        if (entries.length >= MAX_STITCHED_ENTRIES) {
          capped = true;
          break outer;
        }
        const key = `${bytesToHex(params.secret)}|${params.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push(params);
      }
    }
  }
  if (capped) {
    warnings.push(`Stopped at the ${MAX_STITCHED_ENTRIES} entry limit; remaining entries were not imported`);
  }

  return { entries, warnings, batches };
}
