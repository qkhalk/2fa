const BASE32_REGEX = /^[A-Z2-7]+$/;
const OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
const MIN_PERIOD = 15;
const MAX_PERIOD = 120;
const OTP_TYPES = ["totp", "hotp"];
const OTP_ALGORITHMS = ["SHA1", "SHA256", "SHA512"];
const HMAC_HASH_NAMES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
const MAX_SAFE_COUNTER = Number.MAX_SAFE_INTEGER;

export class OtpVaultError extends Error {
  constructor(message, { code = "OTP_VAULT_ERROR", cause } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = "OtpVaultError";
    this.code = code;
  }
}

export function reportError(context, error) {
  console.error(`[OTP Vault] ${context}`, error);
}

export function toUserMessage(error, fallback = "Something went wrong") {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}

export function sanitizeBase32(value) {
  return (value || "").toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}

export function normalizeTags(value) {
  const raw = Array.isArray(value) ? value : String(value || "").split(",");
  return [...new Set(raw
    .map((tag) => String(tag).trim().replace(/\s+/g, " "))
    .filter(Boolean)
    .map((tag) => tag.slice(0, 24))
  )];
}

export function generateEntryId() {
  // >=6 random bytes via crypto.getRandomValues (not a single Uint16: a
  // colliding id makes delete-by-id remove multiple entries).
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(6));
  const random = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `entry_${Date.now().toString(36)}_${random}`;
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function ensureBase32Secret(secret) {
  const clean = sanitizeBase32(secret);
  if (!clean) {
    throw new OtpVaultError("Secret is required", { code: "SECRET_REQUIRED" });
  }
  if (!BASE32_REGEX.test(clean)) {
    throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
  }
  if (base32ToBytes(clean).length === 0) {
    throw new OtpVaultError("Secret is too short to decode", { code: "SECRET_TOO_SHORT" });
  }
  return clean;
}

function ensureDigits(digits) {
  const value = Number(digits);
  if (value !== 6 && value !== 8) {
    throw new OtpVaultError("Only 6-digit and 8-digit OTP codes are supported", { code: "DIGITS_UNSUPPORTED" });
  }
  return value;
}

function ensurePeriod(period) {
  const value = Number(period);
  if (!Number.isInteger(value) || value < MIN_PERIOD || value > MAX_PERIOD) {
    throw new OtpVaultError(`Period must be an integer between ${MIN_PERIOD} and ${MAX_PERIOD} seconds`, {
      code: "PERIOD_INVALID",
    });
  }
  return value;
}

function ensureType(type) {
  const value = String(type || "totp").toLowerCase();
  if (!OTP_TYPES.includes(value)) {
    throw new OtpVaultError("OTP type must be totp or hotp", { code: "OTP_TYPE_INVALID" });
  }
  return value;
}

function ensureAlgorithm(algorithm) {
  const value = String(algorithm || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(value)) {
    throw new OtpVaultError("OTP algorithm must be SHA1, SHA256, or SHA512", { code: "ALGORITHM_UNSUPPORTED" });
  }
  return value;
}

function ensureCounter(counter) {
  if (counter === undefined || counter === null || counter === "") return 0;
  const value = Number(counter);
  if (!Number.isInteger(value) || value < 0 || value > MAX_SAFE_COUNTER) {
    throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "COUNTER_INVALID" });
  }
  return value;
}

export function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}

export function nextOrderValueFrom(items = []) {
  if (items.length === 0) return 1;
  return Math.max(...items.map((entry) => Number(entry.order) || 0)) + 1;
}

function normalizeLabel(label, secret) {
  const clean = (label || "").trim();
  return clean || createFallbackLabel(secret);
}

export function normalizeEntry(entry) {
  const secret = ensureBase32Secret(entry.secret || "");
  const type = ensureType(entry.type);
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    type,
    counter: type === "hotp" ? ensureCounter(entry.counter) : 0,
    algorithm: ensureAlgorithm(entry.algorithm),
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now(),
    order: Number.isFinite(Number(entry.order)) ? Number(entry.order) : 0,
  };
}

export function normalizeEntries(entries) {
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry) => {
    try {
      return [normalizeEntry(entry)];
    } catch {
      return [];
    }
  });
}

export function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };

  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return {
      issuer: issuer.trim() || "Unknown",
      account: rest.join(":").trim() || "No account label",
    };
  }

  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(" - ").trim() || "No account label",
    };
  }

  return { issuer: clean, account: "No account label" };
}

export function getIssuerInitials(label) {
  const issuer = parseLabelParts(label).issuer;
  const parts = issuer.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "OT";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}

function normalizeOtpUriCandidate(value) {
  return safeDecode((value || "").trim()).replace(/[)\],.;]+$/, "");
}

export function parseOtpAuthUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch (error) {
    throw new OtpVaultError("OTP URI is not a valid URL", { code: "URI_INVALID", cause: error });
  }

  if (parsed.protocol !== "otpauth:") {
    throw new OtpVaultError("URI must start with otpauth://", { code: "URI_PROTOCOL" });
  }
  const type = parsed.hostname.toLowerCase();
  if (type !== "totp" && type !== "hotp") {
    throw new OtpVaultError("Only TOTP and HOTP URIs are supported", { code: "URI_TYPE" });
  }

  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (!OTP_ALGORITHMS.includes(algorithm)) {
    throw new OtpVaultError("Only SHA1, SHA256, and SHA512 OTP URIs are supported", { code: "URI_ALGORITHM" });
  }

  let counter;
  if (type === "hotp") {
    const counterParam = parsed.searchParams.get("counter");
    counter = counterParam === null ? 0 : Number(counterParam);
    if (!Number.isInteger(counter) || counter < 0 || counter > MAX_SAFE_COUNTER) {
      throw new OtpVaultError("HOTP counter must be a non-negative integer", { code: "URI_COUNTER" });
    }
  }

  const issuerParam = safeDecode(parsed.searchParams.get("issuer") || "").trim();
  const rawLabel = safeDecode(parsed.pathname.replace(/^\/+/, "")).trim();
  const labelParts = parseLabelParts(rawLabel);
  if (issuerParam && rawLabel && labelParts.issuer !== "Unknown" && labelParts.account !== "No account label") {
    if (labelParts.issuer.toLowerCase() !== issuerParam.toLowerCase()) {
      throw new OtpVaultError("OTP URI issuer does not match the label", { code: "URI_ISSUER_MISMATCH" });
    }
  }

  const label = rawLabel
    ? issuerParam && rawLabel.includes(":")
      ? labelParts.account === "No account label"
        ? `${labelParts.issuer === "Unknown" ? issuerParam : labelParts.issuer}:${labelParts.account}`
        : labelParts.issuer === "Unknown"
          ? `${issuerParam}:${labelParts.account}`
          : rawLabel
      : !issuerParam
        ? rawLabel
        : `${issuerParam}:${rawLabel}`
    : issuerParam
      ? `${issuerParam}:Imported Account`
      : "Imported Account";

  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    type,
    counter,
    algorithm,
    // Period is meaningless for HOTP but stored so the entry shape stays valid.
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: type === "hotp" ? 30 : parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30,
  });
}

export function extractOtpAuthUri(rawText) {
  return extractOtpAuthUris(rawText)[0] || "";
}

export function extractOtpAuthUris(rawText) {
  const candidates = new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];

  candidates.add(normalizeOtpUriCandidate(raw));
  for (const match of raw.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }

  const decoded = safeDecode(raw);
  candidates.add(normalizeOtpUriCandidate(decoded));
  for (const match of decoded.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }

  const valid = [];
  for (const candidate of candidates) {
    if (!candidate.startsWith("otpauth://")) continue;
    try {
      parseOtpAuthUri(candidate);
      valid.push(candidate);
    } catch {
      continue;
    }
  }

  return valid;
}

export function hasDuplicateEntry(entries, candidate) {
  return entries.some((entry) => (
    entry.secret === candidate.secret
    && entry.digits === candidate.digits
    && entry.period === candidate.period
  ));
}

export function entryMatchesQuery(entry, query) {
  const text = query.trim().toLowerCase();
  if (!text) return true;
  return [entry.label, ...(entry.tags || [])]
    .join(" ")
    .toLowerCase()
    .includes(text);
}

export function getEntryGroup(entry, groupBy) {
  if (groupBy === "issuer") return parseLabelParts(entry.label).issuer;
  if (groupBy === "tag") return entry.tags?.[0] || "Untagged";
  return "All Entries";
}

export function compareEntries(a, b, sortBy = "pinned-alpha") {
  if (sortBy === "recent") return b.createdAt - a.createdAt;
  if (sortBy === "period") return a.period - b.period || a.label.localeCompare(b.label, undefined, { sensitivity: "base" });
  if (sortBy === "custom") return a.order - b.order || a.label.localeCompare(b.label, undefined, { sensitivity: "base" });

  if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
  return a.label.localeCompare(b.label, undefined, { sensitivity: "base" });
}

export function base32ToBytes(base32) {
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();

  let bits = "";
  for (const char of clean) {
    const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    if (idx === -1) {
      throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
    }
    bits += idx.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// RFC 3548 Base32, no padding (app convention).
export function bytesToBase32(bytes) {
  let bits = "";
  for (const byte of bytes) {
    bits += byte.toString(2).padStart(8, "0");
  }
  let output = "";
  for (let index = 0; index + 5 <= bits.length; index += 5) {
    output += BASE32_ALPHABET[Number.parseInt(bits.slice(index, index + 5), 2)];
  }
  const remainder = bits.length % 5;
  if (remainder > 0) {
    output += BASE32_ALPHABET[Number.parseInt(bits.slice(bits.length - remainder).padEnd(5, "0"), 2)];
  }
  return output;
}

const MIGRATION_URI_REGEX = /otpauth-migration:\/\/[^\s"'<>]+/gi;

export function extractMigrationUris(rawText) {
  const found = new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  for (const match of raw.matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  for (const match of safeDecode(raw).matchAll(MIGRATION_URI_REGEX)) {
    found.add(match[0]);
  }
  return [...found];
}

function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

async function hmac(keyBytes, messageBytes, hash, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }

  const algorithmName = HMAC_HASH_NAMES[hash] || hash;
  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algorithmName }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}

// RFC 4226 dynamic truncation over the HMAC digest — hash-agnostic.
function truncateDigest(digest, digits) {
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  return (binary % (10 ** digits)).toString().padStart(digits, "0");
}

export async function generateHotp(secret, counter, digits, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedCounter = ensureCounter(counter);
  const normalizedDigits = ensureDigits(digits);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(normalizedCounter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}

export async function generateTotp(secret, digits, period, now, algorithm = "SHA1", cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const normalizedAlgorithm = ensureAlgorithm(algorithm);
  // Number math stays correct past 2038 (never int32).
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmac(
    base32ToBytes(normalizedSecret),
    toCounterBytes(counter),
    normalizedAlgorithm,
    cryptoApi
  );
  return truncateDigest(digest, normalizedDigits);
}

export function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
