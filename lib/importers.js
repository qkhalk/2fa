// Third-party app import: Aegis plain-text JSON exports and 2FAS JSON
// backups. Both formats decode into the same vault entry candidate shape the
// Google Authenticator migration flow produces, so callers can reuse the
// shared import preview. Aegis ENCRYPTED exports are rejected with guidance
// (Web Crypto has no scrypt to honor Aegis' KDF); only the app's own
// passphrase backups use encryption. Decoded secrets are never logged.
//
// Fail-closed limits mirror lib/migration.js: the whole file is bounded, the
// entry count is capped, and one bad entry never aborts the batch.

import { OtpVaultError, base32ToBytes, sanitizeBase32 } from "./otp.js";

export const MAX_IMPORT_FILE_BYTES = 8 * 1024 * 1024;
export const MAX_IMPORT_ENTRIES = 500;

const OTP_TYPES = new Set(["totp", "hotp"]);
const ALGORITHMS = new Set(["SHA1", "SHA256", "SHA512"]);
const MIN_PERIOD = 15;
const MAX_PERIOD = 120;
const MAX_SAFE_COUNTER = Number.MAX_SAFE_INTEGER;

function malformed(message, code = "IMPORT_FILE_MALFORMED") {
  return new OtpVaultError(message, { code });
}

function toCandidate({ label, secret, type, algorithm, digits, period, counter, tags = [] }) {
  const normalizedSecret = sanitizeBase32(secret);
  if (!normalizedSecret) throw malformed("entry has no secret");
  if (!/^[A-Z2-7]+$/.test(normalizedSecret)) throw malformed("entry has an invalid Base32 secret");
  if (base32ToBytes(normalizedSecret).length === 0) throw malformed("entry secret is too short to decode");
  const normalizedType = String(type || "totp").toLowerCase();
  if (!OTP_TYPES.has(normalizedType)) throw malformed(`unsupported OTP type "${type}"`);
  const normalizedAlgorithm = String(algorithm || "SHA1").toUpperCase();
  if (!ALGORITHMS.has(normalizedAlgorithm)) throw malformed(`unsupported algorithm "${algorithm}"`);
  const normalizedDigits = Number(digits);
  if (normalizedDigits !== 6 && normalizedDigits !== 8) throw malformed(`unsupported digit count "${digits}"`);
  const normalizedPeriod = Number(period);
  if (!Number.isInteger(normalizedPeriod) || normalizedPeriod < MIN_PERIOD || normalizedPeriod > MAX_PERIOD) {
    throw malformed(`period ${period} is outside ${MIN_PERIOD}-${MAX_PERIOD} seconds`);
  }
  let normalizedCounter = 0;
  if (normalizedType === "hotp") {
    normalizedCounter = Number(counter ?? 0);
    if (!Number.isInteger(normalizedCounter) || normalizedCounter < 0 || normalizedCounter > MAX_SAFE_COUNTER) {
      throw malformed("HOTP counter is outside the supported range");
    }
  }
  const normalizedLabel = String(label || "").trim();
  if (!normalizedLabel) throw malformed("entry has no label");
  return {
    label: normalizedLabel,
    secret: normalizedSecret,
    type: normalizedType,
    algorithm: normalizedAlgorithm,
    digits: normalizedDigits,
    period: normalizedPeriod,
    counter: normalizedCounter,
    tags: (Array.isArray(tags) ? tags : [])
      .map((tag) => String(tag).trim())
      .filter(Boolean)
      .slice(0, 8),
  };
}

// "Issuer" + "account" combine into the shared "Issuer:account" label
// convention. An issuer already embedded in the name wins as-is.
function buildLabel(issuer, name) {
  const cleanIssuer = String(issuer || "").trim();
  const cleanName = String(name || "").trim();
  if (!cleanIssuer) return cleanName;
  if (!cleanName) return cleanIssuer;
  if (cleanName.toLowerCase().startsWith(`${cleanIssuer.toLowerCase()}:`)) return cleanName;
  return `${cleanIssuer}:${cleanName}`;
}

// Encrypted Aegis exports carry KDF slots/params in the header instead of a
// plain db. Both detection sites must agree so such files route to the
// guidance error in parseAegisExport, not a generic "not recognized" one.
function looksLikeEncryptedAegis(data) {
  return Array.isArray(data?.header?.slots) || Boolean(data?.header?.params);
}

// Decodes an Aegis plain-text export. Encrypted exports (header slots + no
// db) are rejected with guidance instead of a cryptic shape error.
export function parseAegisExport(data) {
  const entriesRaw = data?.db?.entries;
  if (!Array.isArray(entriesRaw)) {
    if (looksLikeEncryptedAegis(data)) {
      throw malformed(
        "This Aegis export is encrypted. Re-export from Aegis with the plain-text (unencrypted) option and try again.",
        "IMPORT_ENCRYPTED_UNSUPPORTED"
      );
    }
    throw malformed("This file does not look like an Aegis export (no entry database found)");
  }

  const entries = [];
  const warnings = [];
  for (const raw of entriesRaw) {
    const label = buildLabel(raw?.issuer, raw?.name || raw?.token?.label);
    if (entries.length >= MAX_IMPORT_ENTRIES) {
      warnings.push(`Stopped at the ${MAX_IMPORT_ENTRIES} entry limit; remaining Aegis entries were not imported`);
      break;
    }
    try {
      entries.push(toCandidate({
        label,
        secret: raw?.token?.secret,
        type: raw?.type,
        algorithm: raw?.token?.algorithm,
        digits: raw?.token?.digits ?? 6,
        period: raw?.token?.period ?? 30,
        counter: raw?.token?.counter,
        tags: Array.isArray(raw?.tags) ? raw.tags : [],
      }));
    } catch (error) {
      warnings.push(`Skipped "${label || "unnamed entry"}": ${error.message}`);
    }
  }
  return { entries, warnings };
}

// Decodes a 2FAS app backup. Group membership becomes a first tag so the
// organization survives the move.
export function parse2FasExport(data) {
  const servicesRaw = data?.services;
  if (!Array.isArray(servicesRaw)) {
    throw malformed("This file does not look like a 2FAS export (no services found)");
  }
  const groupNames = new Map();
  if (Array.isArray(data?.groups)) {
    for (const group of data.groups) {
      if (group?.uuid && group?.name) groupNames.set(group.uuid, String(group.name));
    }
  }

  const entries = [];
  const warnings = [];
  for (const raw of servicesRaw) {
    const otp = raw?.otp || {};
    const issuer = otp.tokenIssuer || raw?.name;
    const label = buildLabel(issuer, otp.label);
    if (entries.length >= MAX_IMPORT_ENTRIES) {
      warnings.push(`Stopped at the ${MAX_IMPORT_ENTRIES} entry limit; remaining 2FAS entries were not imported`);
      break;
    }
    try {
      const tags = [];
      if (raw?.groupUuid && groupNames.has(raw.groupUuid)) tags.push(groupNames.get(raw.groupUuid));
      entries.push(toCandidate({
        label,
        secret: otp.secret ?? raw?.secret,
        type: otp.tokenType,
        algorithm: otp.algorithm,
        digits: otp.digits ?? 6,
        period: otp.period ?? 30,
        counter: otp.counter,
        tags,
      }));
    } catch (error) {
      warnings.push(`Skipped "${label || "unnamed entry"}": ${error.message}`);
    }
  }
  return { entries, warnings };
}

// Top-level entry point: JSON text in, candidates out. The format is
// detected from the file shape and returned so callers can label the import
// source ("Aegis" / "2FAS") without re-parsing.
export function parseThirdPartyImport(rawText) {
  const text = typeof rawText === "string" ? rawText : "";
  if (text.length > MAX_IMPORT_FILE_BYTES) {
    throw malformed(`Import file exceeds the ${MAX_IMPORT_FILE_BYTES} byte limit`);
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw malformed("Import file is not valid JSON");
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw malformed("Import file is not a recognized export format");
  }

  if (Array.isArray(data.services)) {
    const { entries, warnings } = parse2FasExport(data);
    return { format: "2FAS", entries, warnings };
  }
  if (Array.isArray(data.db?.entries) || looksLikeEncryptedAegis(data)) {
    const { entries, warnings } = parseAegisExport(data);
    return { format: "Aegis", entries, warnings };
  }
  throw malformed("Import file is not a recognized Aegis or 2FAS export");
}
