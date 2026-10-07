import { describe, expect, it } from "vitest";
import { webcrypto } from "node:crypto";

import {
  deriveKek,
  enrollBiometricUnlock,
  fromB64u,
  prfCapable,
  runAssertCeremony,
  runCreateCeremony,
  toB64u,
  unwrapDek,
  wrapDek,
} from "../../lib/biometric.js";

const cryptoApi = webcrypto;
const RP_ID = "vault.example";

// Deterministic stand-in for the authenticator's per-credential PRF secret:
// stable for a given (credentialId, salt) pair, distinct across pairs.
function deterministicPrfOutput(credentialIdB64u, saltB64u) {
  const seed = `${credentialIdB64u}|${saltB64u}`;
  const output = new Uint8Array(32);
  let hash = 0x811c9dc5;
  for (let index = 0; index < output.length; index += 1) {
    hash ^= seed.charCodeAt(index % seed.length);
    hash = Math.imul(hash, 0x01000193) >>> 0;
    hash ^= hash >>> 15;
    output[index] = hash & 0xff;
  }
  return output;
}

function createStubCredentialsApi({
  behavior = "success",
  createExtensionResults = { prf: { enabled: true } },
} = {}) {
  const calls = { create: [], get: [] };

  const buildAssertion = (publicKey) => {
    const allowEntry = publicKey.allowCredentials?.[0];
    const credentialIdB64u = toB64u(new Uint8Array(allowEntry.id));
    const prfInput = publicKey.extensions?.prf ?? {};
    const saltEntry = prfInput.evalByCredential?.[credentialIdB64u] ?? prfInput.eval;
    const saltB64u = saltEntry?.first ? toB64u(new Uint8Array(saltEntry.first)) : "";
    const first = deterministicPrfOutput(credentialIdB64u, saltB64u);
    return {
      rawId: new Uint8Array(allowEntry.id),
      getClientExtensionResults: () => ({ prf: { results: { first } } }),
    };
  };

  return {
    calls,
    async create(options) {
      calls.create.push(options);
      return {
        rawId: webcrypto.getRandomValues(new Uint8Array(16)),
        getClientExtensionResults: () => createExtensionResults,
      };
    },
    async get(options) {
      calls.get.push(options);
      const publicKey = options.publicKey;
      if (behavior === "notAllowed") {
        throw new DOMException("The user cancelled the ceremony", "NotAllowedError");
      }
      if (behavior === "notSupportedThenEval" && publicKey.extensions?.prf?.evalByCredential) {
        throw new DOMException("evalByCredential is not supported", "NotSupportedError");
      }
      if (behavior === "nonPrf") {
        // Authenticator without prf support: { prf: {} } per the spec.
        return {
          rawId: new Uint8Array(publicKey.allowCredentials[0].id),
          getClientExtensionResults: () => ({ prf: {} }),
        };
      }
      return buildAssertion(publicKey);
    },
  };
}

describe("base64url helpers", () => {
  it("round-trips RFC 4648 base64url vectors", () => {
    const vectors = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ];

    for (const [plain, encoded] of vectors) {
      const bytes = new TextEncoder().encode(plain);
      expect(toB64u(bytes)).toBe(encoded);
      expect(new TextDecoder().decode(fromB64u(encoded))).toBe(plain);
    }
  });

  it("round-trips random 32-byte values using only base64url characters", () => {
    const bytes = webcrypto.getRandomValues(new Uint8Array(32));
    const encoded = toB64u(bytes);

    expect(encoded).not.toMatch(/[+/=]/);
    expect(fromB64u(encoded)).toEqual(bytes);
  });

  it("rejects values that are not canonical base64url", () => {
    expect(() => fromB64u("not valid!!")).toThrow();
    expect(() => fromB64u("Zm9vYg==")).toThrow(); // canonical form drops padding
    expect(() => fromB64u(42)).toThrow();
  });
});

describe("prfCapable", () => {
  const stubCredentialsApi = { create: async () => {}, get: async () => {} };

  // PublicKeyCredential is a constructor with statics in browsers, so the
  // stub mirrors that shape.
  function stubPublicKeyCredential({ platformAuthenticator = true, capabilities, omitCapabilities = false } = {}) {
    class FakePublicKeyCredential {}
    FakePublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => platformAuthenticator;
    if (!omitCapabilities) {
      FakePublicKeyCredential.getClientCapabilities = async () => capabilities;
    }
    return FakePublicKeyCredential;
  }

  it("returns false in Node where the credentials API is undefined", async () => {
    await expect(prfCapable()).resolves.toBe(false);
    await expect(prfCapable({ credentialsApi: undefined })).resolves.toBe(false);
  });

  it("returns false when PublicKeyCredential is unavailable", async () => {
    await expect(prfCapable({ credentialsApi: stubCredentialsApi, publicKeyCredential: undefined }))
      .resolves.toBe(false);
  });

  it("reports prf capability via getClientCapabilities", async () => {
    await expect(prfCapable({
      credentialsApi: stubCredentialsApi,
      publicKeyCredential: stubPublicKeyCredential({ capabilities: { prf: true } }),
    })).resolves.toBe(true);
  });

  it("returns false when the capabilities probe excludes prf", async () => {
    await expect(prfCapable({
      credentialsApi: stubCredentialsApi,
      publicKeyCredential: stubPublicKeyCredential({ capabilities: { prf: false } }),
    })).resolves.toBe(false);
  });

  it("returns false when no platform authenticator is available", async () => {
    await expect(prfCapable({
      credentialsApi: stubCredentialsApi,
      publicKeyCredential: stubPublicKeyCredential({ platformAuthenticator: false, capabilities: { prf: true } }),
    })).resolves.toBe(false);
  });

  it("falls back to true on engines without a capabilities probe", async () => {
    await expect(prfCapable({
      credentialsApi: stubCredentialsApi,
      publicKeyCredential: stubPublicKeyCredential({ omitCapabilities: true }),
    })).resolves.toBe(true);
  });
});

describe("runCreateCeremony", () => {
  it("issues a create ceremony with the prf extension and pinned rp id", async () => {
    const credentialsApi = createStubCredentialsApi();
    const { credentialId } = await runCreateCeremony({ rpId: RP_ID, credentialsApi, cryptoApi });

    expect(credentialId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(credentialsApi.calls.create).toHaveLength(1);

    const publicKey = credentialsApi.calls.create[0].publicKey;
    expect(publicKey.rp).toEqual({ name: "Personal OTP Vault", id: RP_ID });
    expect(publicKey.user.name).toBe("otp-vault");
    expect(publicKey.user.id).toBeInstanceOf(Uint8Array);
    expect(publicKey.user.id).toHaveLength(16);
    expect(publicKey.challenge).toBeInstanceOf(Uint8Array);
    expect(publicKey.challenge).toHaveLength(32);
    expect(publicKey.pubKeyCredParams).toEqual([
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ]);
    expect(publicKey.authenticatorSelection).toEqual({
      userVerification: "required",
      residentKey: "preferred",
    });
    expect(publicKey.extensions).toEqual({ prf: {} });
  });

  it("rejects with BIOMETRIC_UNSUPPORTED when create reports no prf extension", async () => {
    const credentialsApi = createStubCredentialsApi({ createExtensionResults: {} });

    await expect(runCreateCeremony({ rpId: RP_ID, credentialsApi, cryptoApi }))
      .rejects.toMatchObject({ code: "BIOMETRIC_UNSUPPORTED" });
  });

  it("rejects with BIOMETRIC_UNSUPPORTED when prf is not enabled", async () => {
    const credentialsApi = createStubCredentialsApi({ createExtensionResults: { prf: { enabled: false } } });

    await expect(runCreateCeremony({ rpId: RP_ID, credentialsApi, cryptoApi }))
      .rejects.toMatchObject({ code: "BIOMETRIC_UNSUPPORTED" });
  });

  it("maps NotAllowedError during creation to BIOMETRIC_NOT_ALLOWED", async () => {
    const credentialsApi = {
      create: async () => {
        throw new DOMException("denied", "NotAllowedError");
      },
    };

    await expect(runCreateCeremony({ rpId: RP_ID, credentialsApi, cryptoApi }))
      .rejects.toMatchObject({ code: "BIOMETRIC_NOT_ALLOWED" });
  });

  it("maps InvalidStateError during creation to BIOMETRIC_INVALID_STATE", async () => {
    const credentialsApi = {
      create: async () => {
        throw new DOMException("credential excluded", "InvalidStateError");
      },
    };

    await expect(runCreateCeremony({ rpId: RP_ID, credentialsApi, cryptoApi }))
      .rejects.toMatchObject({ code: "BIOMETRIC_INVALID_STATE" });
  });
});

describe("runAssertCeremony", () => {
  const storedCredentialId = toB64u(webcrypto.getRandomValues(new Uint8Array(16)));
  const freshSalt = () => webcrypto.getRandomValues(new Uint8Array(32));

  it("pins the stored credential and mirrors it in evalByCredential", async () => {
    const credentialsApi = createStubCredentialsApi();
    const prfSalt = freshSalt();
    const { credentialId, prfOutput } = await runAssertCeremony({
      credentialId: storedCredentialId,
      prfSalt,
      credentialsApi,
      rpId: RP_ID,
      cryptoApi,
    });

    expect(credentialsApi.calls.get).toHaveLength(1);
    const publicKey = credentialsApi.calls.get[0].publicKey;
    expect(publicKey.allowCredentials).toHaveLength(1);
    expect(publicKey.allowCredentials[0].type).toBe("public-key");
    expect(toB64u(publicKey.allowCredentials[0].id)).toBe(storedCredentialId);
    expect(publicKey.userVerification).toBe("required");
    expect(publicKey.rpId).toBe(RP_ID);

    const evalByCredential = publicKey.extensions.prf.evalByCredential;
    const evalKeys = Object.keys(evalByCredential);
    expect(evalKeys).toEqual([storedCredentialId]);
    expect(evalKeys[0]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(evalKeys[0]).toBe(toB64u(publicKey.allowCredentials[0].id));
    expect(evalByCredential[storedCredentialId].first).toBe(prfSalt);

    expect(credentialId).toBe(storedCredentialId);
    expect(toB64u(prfOutput))
      .toBe(toB64u(deterministicPrfOutput(storedCredentialId, toB64u(prfSalt))));
  });

  it("retries with the prf eval extension after NotSupportedError", async () => {
    const credentialsApi = createStubCredentialsApi({ behavior: "notSupportedThenEval" });
    const prfSalt = freshSalt();
    const { prfOutput } = await runAssertCeremony({
      credentialId: storedCredentialId,
      prfSalt,
      credentialsApi,
      cryptoApi,
    });

    expect(credentialsApi.calls.get).toHaveLength(2);
    expect(credentialsApi.calls.get[0].publicKey.extensions.prf.evalByCredential).toBeDefined();

    const retryPublicKey = credentialsApi.calls.get[1].publicKey;
    expect(retryPublicKey.extensions.prf.eval.first).toBe(prfSalt);
    expect(toB64u(retryPublicKey.allowCredentials[0].id)).toBe(storedCredentialId);
    expect(retryPublicKey.userVerification).toBe("required");
    expect(toB64u(prfOutput))
      .toBe(toB64u(deterministicPrfOutput(storedCredentialId, toB64u(prfSalt))));
  });

  it("does not retry when the eval fallback is disabled", async () => {
    const credentialsApi = createStubCredentialsApi({ behavior: "notSupportedThenEval" });

    await expect(runAssertCeremony({
      credentialId: storedCredentialId,
      prfSalt: freshSalt(),
      credentialsApi,
      cryptoApi,
      allowEvalFallback: false,
    })).rejects.toMatchObject({ code: "BIOMETRIC_UNSUPPORTED" });
    expect(credentialsApi.calls.get).toHaveLength(1);
  });

  it("maps NotAllowedError to BIOMETRIC_NOT_ALLOWED without retrying", async () => {
    const credentialsApi = createStubCredentialsApi({ behavior: "notAllowed" });

    await expect(runAssertCeremony({
      credentialId: storedCredentialId,
      prfSalt: freshSalt(),
      credentialsApi,
      cryptoApi,
    })).rejects.toMatchObject({ code: "BIOMETRIC_NOT_ALLOWED" });
    expect(credentialsApi.calls.get).toHaveLength(1);
  });

  it("rejects with BIOMETRIC_UNSUPPORTED for a non-prf authenticator", async () => {
    const credentialsApi = createStubCredentialsApi({ behavior: "nonPrf" });

    await expect(runAssertCeremony({
      credentialId: storedCredentialId,
      prfSalt: freshSalt(),
      credentialsApi,
      cryptoApi,
    })).rejects.toMatchObject({ code: "BIOMETRIC_UNSUPPORTED" });
  });

  it("rejects with BIOMETRIC_INVALID_STATE without calling get() when no credential is enrolled", async () => {
    const credentialsApi = createStubCredentialsApi();

    await expect(runAssertCeremony({
      credentialId: "",
      prfSalt: freshSalt(),
      credentialsApi,
      cryptoApi,
    })).rejects.toMatchObject({ code: "BIOMETRIC_INVALID_STATE" });
    expect(credentialsApi.calls.get).toHaveLength(0);
  });
});

describe("enrollBiometricUnlock", () => {
  it("runs one create and one assert and returns the enrollment record", async () => {
    const credentialsApi = createStubCredentialsApi();
    const enrollment = await enrollBiometricUnlock({ rpId: RP_ID, credentialsApi, cryptoApi });

    expect(credentialsApi.calls.create).toHaveLength(1);
    expect(credentialsApi.calls.get).toHaveLength(1);
    expect(enrollment.credentialId).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(enrollment.prfSalt).toBeInstanceOf(Uint8Array);
    expect(enrollment.prfSalt).toHaveLength(32);
    expect(enrollment.firstPrfOutput).toBeInstanceOf(Uint8Array);
    expect(enrollment.firstPrfOutput).toHaveLength(32);
    expect(toB64u(enrollment.firstPrfOutput))
      .toBe(toB64u(deterministicPrfOutput(enrollment.credentialId, toB64u(enrollment.prfSalt))));

    const publicKey = credentialsApi.calls.get[0].publicKey;
    expect(Object.keys(publicKey.extensions.prf.evalByCredential)[0]).toBe(enrollment.credentialId);
  });

  it("generates a fresh prf salt for every enrollment", async () => {
    const first = await enrollBiometricUnlock({ rpId: RP_ID, credentialsApi: createStubCredentialsApi(), cryptoApi });
    const second = await enrollBiometricUnlock({ rpId: RP_ID, credentialsApi: createStubCredentialsApi(), cryptoApi });

    expect(toB64u(first.prfSalt)).not.toBe(toB64u(second.prfSalt));
  });
});

describe("KEK derivation and DEK wrap/unwrap", () => {
  const prfOutput = webcrypto.getRandomValues(new Uint8Array(32));
  const prfSalt = webcrypto.getRandomValues(new Uint8Array(32));
  const dek = webcrypto.getRandomValues(new Uint8Array(32));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));

  it("derives a non-extractable AES-GCM KEK with wrap and unwrap usages", async () => {
    const kek = await deriveKek(prfOutput, prfSalt, cryptoApi);

    expect(kek.algorithm.name).toBe("AES-GCM");
    expect(kek.algorithm.length).toBe(256);
    expect(kek.extractable).toBe(false);
    expect(kek.usages).toEqual(expect.arrayContaining(["wrapKey", "unwrapKey"]));
  });

  it("derives deterministically for identical prf inputs", async () => {
    const kekA = await deriveKek(prfOutput, prfSalt, cryptoApi);
    const kekB = await deriveKek(prfOutput, prfSalt, cryptoApi);

    const wrappedA = await wrapDek(dek, kekA, iv, cryptoApi);
    const wrappedB = await wrapDek(dek, kekB, iv, cryptoApi);
    expect(toB64u(wrappedA)).toBe(toB64u(wrappedB));
  });

  it("wraps and unwraps a random 256-bit DEK", async () => {
    const kek = await deriveKek(prfOutput, prfSalt, cryptoApi);
    const wrapped = await wrapDek(dek, kek, iv, cryptoApi);

    expect(wrapped).toBeInstanceOf(Uint8Array);
    expect(wrapped).toHaveLength(48); // 32-byte DEK + 16-byte GCM tag

    const unwrapped = await unwrapDek(wrapped, iv, kek, cryptoApi);
    expect(unwrapped.algorithm.name).toBe("AES-GCM");
    expect(unwrapped.algorithm.length).toBe(256);

    // Prove the unwrapped key material matches the original DEK functionally.
    const message = webcrypto.getRandomValues(new Uint8Array(64));
    const messageIv = webcrypto.getRandomValues(new Uint8Array(12));
    const originalKey = await cryptoApi.subtle.importKey("raw", dek, { name: "AES-GCM" }, false, ["encrypt"]);
    const ciphertext = await cryptoApi.subtle.encrypt({ name: "AES-GCM", iv: messageIv }, originalKey, message);
    const plaintext = await cryptoApi.subtle.decrypt({ name: "AES-GCM", iv: messageIv }, unwrapped, ciphertext);
    expect(new Uint8Array(plaintext)).toEqual(message);
  });

  it("fails closed when the wrapped DEK is tampered with", async () => {
    const kek = await deriveKek(prfOutput, prfSalt, cryptoApi);
    const wrapped = await wrapDek(dek, kek, iv, cryptoApi);
    const tampered = new Uint8Array(wrapped);
    tampered[0] ^= 0xff;

    await expect(unwrapDek(tampered, iv, kek, cryptoApi))
      .rejects.toMatchObject({ code: "BIOMETRIC_KEY_DERIVATION_FAILED" });
  });

  it("fails closed when the wrong iv is used", async () => {
    const kek = await deriveKek(prfOutput, prfSalt, cryptoApi);
    const wrapped = await wrapDek(dek, kek, iv, cryptoApi);
    const wrongIv = webcrypto.getRandomValues(new Uint8Array(12));

    await expect(unwrapDek(wrapped, wrongIv, kek, cryptoApi))
      .rejects.toMatchObject({ code: "BIOMETRIC_KEY_DERIVATION_FAILED" });
  });

  it("cannot unwrap under a KEK derived from different prf inputs", async () => {
    const kek = await deriveKek(prfOutput, prfSalt, cryptoApi);
    const otherPrfOutput = webcrypto.getRandomValues(new Uint8Array(32));
    const otherKek = await deriveKek(otherPrfOutput, prfSalt, cryptoApi);
    const wrapped = await wrapDek(dek, kek, iv, cryptoApi);

    await expect(unwrapDek(wrapped, iv, otherKek, cryptoApi))
      .rejects.toMatchObject({ code: "BIOMETRIC_KEY_DERIVATION_FAILED" });
  });

  it("maps derivation failures to BIOMETRIC_KEY_DERIVATION_FAILED", async () => {
    await expect(deriveKek(webcrypto.getRandomValues(new Uint8Array(8)), prfSalt, cryptoApi))
      .rejects.toMatchObject({ code: "BIOMETRIC_KEY_DERIVATION_FAILED" });
  });
});

describe("biometric key hierarchy flow", () => {
  it("supports enroll → wrap → unlock ceremony → unwrap with the same DEK", async () => {
    const enrollment = await enrollBiometricUnlock({
      rpId: RP_ID,
      credentialsApi: createStubCredentialsApi(),
      cryptoApi,
    });

    const kek = await deriveKek(enrollment.firstPrfOutput, enrollment.prfSalt, cryptoApi);
    const dek = webcrypto.getRandomValues(new Uint8Array(32));
    const wrappedIv = webcrypto.getRandomValues(new Uint8Array(12));
    const wrappedDek = await wrapDek(dek, kek, wrappedIv, cryptoApi);

    // Unlock: fresh ceremony with the stored record, then unwrap via the KEK.
    const { prfOutput } = await runAssertCeremony({
      credentialId: enrollment.credentialId,
      prfSalt: enrollment.prfSalt,
      credentialsApi: createStubCredentialsApi(),
      cryptoApi,
    });
    const unlockKek = await deriveKek(prfOutput, enrollment.prfSalt, cryptoApi);
    const unwrappedDek = await unwrapDek(wrappedDek, wrappedIv, unlockKek, cryptoApi);

    const vaultPayload = new TextEncoder().encode(JSON.stringify([{ id: "entry_1" }]));
    const dataIv = webcrypto.getRandomValues(new Uint8Array(12));
    const dataKey = await cryptoApi.subtle.importKey("raw", dek, { name: "AES-GCM" }, false, ["encrypt"]);
    const encrypted = await cryptoApi.subtle.encrypt({ name: "AES-GCM", iv: dataIv }, dataKey, vaultPayload);
    const decrypted = await cryptoApi.subtle.decrypt({ name: "AES-GCM", iv: dataIv }, unwrappedDek, encrypted);

    expect(JSON.parse(new TextDecoder().decode(decrypted))).toEqual([{ id: "entry_1" }]);
  });
});
