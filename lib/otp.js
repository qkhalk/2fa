const BASE32_REGEX = /^[A-Z2-7]+$/;
const OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
const MIN_PERIOD = 15;
const MAX_PERIOD = 120;

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
  return `entry_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
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

export function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}

function normalizeLabel(label, secret) {
  const clean = (label || "").trim();
  return clean || createFallbackLabel(secret);
}

export function normalizeEntry(entry) {
  const secret = ensureBase32Secret(entry.secret || "");
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now(),
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
      issuer: issuer.trim() || clean,
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
  if (parsed.hostname.toLowerCase() !== "totp") {
    throw new OtpVaultError("Only TOTP URIs are supported", { code: "URI_TYPE" });
  }

  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (algorithm !== "SHA1") {
    throw new OtpVaultError("Only SHA1 TOTP URIs are supported", { code: "URI_ALGORITHM" });
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
    ? rawLabel.includes(":") || !issuerParam
      ? rawLabel
      : `${issuerParam}:${rawLabel}`
    : issuerParam
      ? `${issuerParam}:Imported Account`
      : "Imported Account";

  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30,
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

function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

async function hmacSha1(keyBytes, messageBytes, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }

  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}

export async function generateTotp(secret, digits, period, now, cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmacSha1(base32ToBytes(normalizedSecret), toCounterBytes(counter), cryptoApi);
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  return (binary % (10 ** normalizedDigits)).toString().padStart(normalizedDigits, "0");
}

export function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
