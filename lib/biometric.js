import { OtpVaultError } from "./otp.js";

// WebAuthn PRF biometric unlock (phase 6). Key hierarchy:
// PRF output (held by the authenticator) →HKDF→ KEK (never stored)
// →wrapKey/unwrapKey→ DEK (random 256-bit, stored only wrapped twice).
// Storage may keep credentialId and prfSalt — both public, non-secret —
// but PRF output, KEK, and DEK material are never persisted or logged.

const encoder = new TextEncoder();

const RP_NAME = "Personal OTP Vault";
const USER_NAME = "otp-vault";
const KEK_INFO = encoder.encode("2fa-vault-kek-v1");
const CEREMONY_TIMEOUT_MS = 60000;
const CHALLENGE_BYTES = 32;
const USER_ID_BYTES = 16;
const PRF_SALT_BYTES = 32;
const DEK_BYTES = 32;

function defaultCredentialsApi() {
  return globalThis.navigator?.credentials;
}

function requireCrypto(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}

function requireCredentials(credentialsApi, method) {
  if (!credentialsApi || typeof credentialsApi[method] !== "function") {
    throw new OtpVaultError("WebAuthn is unavailable in this context", { code: "BIOMETRIC_UNSUPPORTED" });
  }
  return credentialsApi;
}

function randomBytes(length, cryptoApi) {
  return requireCrypto(cryptoApi).getRandomValues(new Uint8Array(length));
}

function toRawBase64(bytes) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index]);
  }
  return btoa(binary);
}

export function toB64u(bytes) {
  if (!ArrayBuffer.isView(bytes)) {
    throw new OtpVaultError("Base64url encoding expects bytes", { code: "BIOMETRIC_INVALID_STATE" });
  }
  return toRawBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(value) {
  try {
    if (typeof value !== "string") {
      throw new TypeError("base64url input must be a string");
    }
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const bytes = typeof Buffer !== "undefined"
      ? new Uint8Array(Buffer.from(padded, "base64"))
      : Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
    // Fail closed on non-canonical input so a corrupted credentialId can
    // never reach a ceremony.
    if (toB64u(bytes) !== value) {
      throw new Error("value is not canonical base64url");
    }
    return bytes;
  } catch (error) {
    throw new OtpVaultError("Value is not valid base64url", { code: "BIOMETRIC_INVALID_STATE", cause: error });
  }
}

export async function prfCapable({
  credentialsApi = defaultCredentialsApi(),
  publicKeyCredential = globalThis.PublicKeyCredential,
} = {}) {
  // Node and insecure contexts expose neither piece; without either there is
  // no WebAuthn at all.
  if (!credentialsApi || typeof publicKeyCredential !== "function") {
    return false;
  }

  let platformAuthenticatorAvailable = false;
  try {
    platformAuthenticatorAvailable = await publicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    platformAuthenticatorAvailable = false;
  }
  if (!platformAuthenticatorAvailable) {
    return false;
  }

  try {
    if (typeof publicKeyCredential.getClientCapabilities !== "function") {
      return true;
    }
    const capabilities = await publicKeyCredential.getClientCapabilities();
    return capabilities?.prf === true;
  } catch {
    // Older engine without a capabilities probe: the enrollment ceremony's
    // enabled flag remains the source of truth.
    return true;
  }
}

function mapCeremonyError(error) {
  if (error instanceof OtpVaultError) return error;
  if (error?.name === "NotAllowedError") {
    return new OtpVaultError("Biometric verification was cancelled or blocked — use the passphrase to unlock", {
      code: "BIOMETRIC_NOT_ALLOWED",
      cause: error,
    });
  }
  if (error?.name === "InvalidStateError") {
    return new OtpVaultError("The authenticator is in an invalid state — use the passphrase to unlock", {
      code: "BIOMETRIC_INVALID_STATE",
      cause: error,
    });
  }
  if (error?.name === "NotSupportedError") {
    return new OtpVaultError("This authenticator does not support PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED",
      cause: error,
    });
  }
  return new OtpVaultError("WebAuthn ceremony failed", { code: "BIOMETRIC_CEREMONY_FAILED", cause: error });
}

export async function runCreateCeremony({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto,
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "create");
  const safeCrypto = requireCrypto(cryptoApi);

  const publicKey = {
    challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
    rp: { name: RP_NAME, id: rpId },
    user: {
      id: randomBytes(USER_ID_BYTES, safeCrypto),
      name: USER_NAME,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ],
    authenticatorSelection: {
      userVerification: "required",
      residentKey: "preferred",
    },
    timeout: CEREMONY_TIMEOUT_MS,
    attestation: "none",
    extensions: { prf: {} },
  };

  let credential;
  try {
    credential = await safeCredentials.create({ publicKey });
  } catch (error) {
    throw mapCeremonyError(error);
  }

  // The enabled flag (not a UA string) is the authoritative prf signal; the
  // first real PRF output only ever comes from a later assertion.
  const extensionResults = credential?.getClientExtensionResults?.() ?? {};
  if (extensionResults.prf?.enabled !== true) {
    throw new OtpVaultError("This authenticator cannot provide PRF-based unlock", {
      code: "BIOMETRIC_UNSUPPORTED",
    });
  }
  if (!credential.rawId) {
    throw new OtpVaultError("The authenticator did not return a credential", {
      code: "BIOMETRIC_CEREMONY_FAILED",
    });
  }
  return { credentialId: toB64u(new Uint8Array(credential.rawId)) };
}

export async function runAssertCeremony({
  credentialId,
  prfSalt,
  credentialsApi = defaultCredentialsApi(),
  allowEvalFallback = true,
  rpId,
  cryptoApi = globalThis.crypto,
} = {}) {
  const safeCredentials = requireCredentials(credentialsApi, "get");
  const safeCrypto = requireCrypto(cryptoApi);

  if (!credentialId || typeof credentialId !== "string") {
    throw new OtpVaultError("No biometric credential is enrolled", { code: "BIOMETRIC_INVALID_STATE" });
  }
  if (!ArrayBuffer.isView(prfSalt) || prfSalt.byteLength === 0) {
    throw new OtpVaultError("The stored PRF salt is missing", { code: "BIOMETRIC_INVALID_STATE" });
  }

  // Exactly one pinned credential — an empty allowCredentials list must never
  // be sent, and a stray passkey must not be able to produce the key.
  const idBytes = fromB64u(credentialId);
  const salts = { first: prfSalt };
  const buildOptions = (extensions) => {
    const publicKey = {
      challenge: randomBytes(CHALLENGE_BYTES, safeCrypto),
      allowCredentials: [{ id: idBytes, type: "public-key" }],
      userVerification: "required",
      timeout: CEREMONY_TIMEOUT_MS,
      extensions,
    };
    if (rpId !== undefined) {
      publicKey.rpId = rpId;
    }
    return { publicKey };
  };

  let assertion;
  try {
    assertion = await safeCredentials.get(buildOptions({
      prf: { evalByCredential: { [credentialId]: salts } },
    }));
  } catch (error) {
    // Some engines only implement the per-assertion `eval` form; retry once.
    if (!allowEvalFallback || error?.name !== "NotSupportedError") {
      throw mapCeremonyError(error);
    }
    try {
      assertion = await safeCredentials.get(buildOptions({ prf: { eval: salts } }));
    } catch (retryError) {
      throw mapCeremonyError(retryError);
    }
  }

  const extensionResults = assertion?.getClientExtensionResults?.() ?? {};
  const first = extensionResults.prf?.results?.first;
  if (!first) {
    // Capability is proven by results.first — never by the user agent.
    throw new OtpVaultError("The authenticator did not return PRF output", {
      code: "BIOMETRIC_UNSUPPORTED",
    });
  }
  return { credentialId, prfOutput: new Uint8Array(first) };
}

export async function deriveKek(prfOutput, prfSalt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  try {
    if (!ArrayBuffer.isView(prfOutput) || prfOutput.byteLength < 16) {
      throw new Error("PRF output must be at least 16 bytes");
    }
    const ikm = await safeCrypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
    return await safeCrypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: prfSalt, info: KEK_INFO },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not derive the biometric unlock key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error,
    });
  }
}

export async function wrapDek(dek, kek, iv, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  try {
    if (!ArrayBuffer.isView(dek) || dek.byteLength !== DEK_BYTES) {
      throw new Error("The vault key must be 256 bits");
    }
    // wrapKey exports the key material, so the transient DEK handle used for
    // wrapping must be importable as extractable; the raw bytes never leave
    // the caller's memory.
    const dekKey = await safeCrypto.subtle.importKey("raw", dek, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
    const wrapped = await safeCrypto.subtle.wrapKey("raw", dekKey, kek, { name: "AES-GCM", iv });
    return new Uint8Array(wrapped);
  } catch (error) {
    throw new OtpVaultError("Could not wrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error,
    });
  }
}

export async function unwrapDek(wrapped, iv, kek, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  try {
    return await safeCrypto.subtle.unwrapKey(
      "raw",
      wrapped,
      kek,
      { name: "AES-GCM", iv },
      { name: "AES-GCM", length: 256 },
      // extractable + wrapKey so re-enrollment can re-wrap the held DEK under
      // a new KEK; raw bytes never leave memory and are never persisted.
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new OtpVaultError("Could not unwrap the vault key with the biometric key", {
      code: "BIOMETRIC_KEY_DERIVATION_FAILED",
      cause: error,
    });
  }
}

export async function enrollBiometricUnlock({
  rpId,
  credentialsApi = defaultCredentialsApi(),
  cryptoApi = globalThis.crypto,
} = {}) {
  const safeCrypto = requireCrypto(cryptoApi);
  const { credentialId } = await runCreateCeremony({ rpId, credentialsApi, cryptoApi: safeCrypto });
  const prfSalt = randomBytes(PRF_SALT_BYTES, safeCrypto);
  const { prfOutput } = await runAssertCeremony({
    credentialId,
    prfSalt,
    credentialsApi,
    rpId,
    cryptoApi: safeCrypto,
  });
  return { credentialId, prfSalt, firstPrfOutput: prfOutput };
}
