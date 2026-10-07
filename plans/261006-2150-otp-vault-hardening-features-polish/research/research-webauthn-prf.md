# Research: WebAuthn `prf` extension for biometric vault unlock

Date: 2026-10-07. Context: local-first TOTP vault, vanilla JS, PBKDF2+AES-256-GCM passphrase unlock; PWA (HTTPS) + Chrome MV3 popup. Baseline Chrome 114+/Safari 16+/Firefox 115+, feature-detect OK.

---

## 1. API surface and sequence

Spec: [W3C WebAuthn L3, §10.1.4 prf extension](https://w3c.github.io/webauthn/#prf-extension) ([TR version](https://www.w3.org/TR/webauthn-3/#prf-extension)), [MDN: WebAuthn extensions / prf](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions).

IDL (from spec):

```webidl
dictionary AuthenticationExtensionsPRFValues {
  required BufferSource first;
  BufferSource second;
};
dictionary AuthenticationExtensionsPRFInputs {
  AuthenticationExtensionsPRFValues eval;
  record<DOMString, AuthenticationExtensionsPRFValues> evalByCredential; // note: singular "Credential"
};
partial dictionary AuthenticationExtensionsClientInputs { AuthenticationExtensionsPRFInputs prf; };
```

Output: `AuthenticationExtensionsPRFOutputs { boolean enabled; AuthenticationExtensionsPRFValues results; }`. `results.first`/`results.second` are **32-byte** buffers ("The PRFs provided by this extension map from BufferSources of any length to 32-byte BufferSources" — spec). On `get()` results, `enabled` is **omitted**; if the authenticator does not support prf at all you get `{ prf: {} }` (empty object) from `getClientExtensionResults()`.

Key processing facts (spec):
- Inputs are internally salted: `salt1 = SHA-256(UTF8("WebAuthn PRF") || 0x00 || eval.first)` — mapped onto CTAP2 [hmac-secret](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#hmac-secret-extension).
- When implemented over hmac-secret, the PRF **MUST be the CredRandomWithUV variant** ("overrides the UserVerificationRequirement if necessary") → always request `userVerification: "required"`; without UV you may get no results or the wrong-slot secret.
- Registration: `prf: { eval }` or `prf: {}`; `evalByCredential` in `create()` throws `NotSupportedError`. Nearly no authenticator can evaluate at creation (CTAP has no make-time hmac-secret eval), so expect `enabled: true/false` and **no results**; the first real output comes from an assertion. `enabled: false` means the authenticator cannot do prf → unusable.
- Authentication: `evalByCredential` keys must be valid base64url AND match an entry in `allowCredentials`, else `SyntaxError`; `evalByCredential` with empty `allowCredentials` throws `NotSupportedError`.
- Spec/MDN discrepancy on `eval` in `get()`: current editor's draft processes `eval` in assertions (applies to whatever credential is returned), but [MDN documents](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions) `NotSupportedError` "if `eval` is the prf object" in `get()`. Cross-browser-safe path: prefer `evalByCredential` with `allowCredentials: [storedId]`; catch `NotSupportedError` and retry with `eval`. Test both in the compat smoke test.
- Discoverable credential: **not required.** hmac-secret/prf "MUST support it for both discoverable and non-discoverable credentials" (CTAP 2.1 §12.5). Discoverability is only needed for usernameless flows; this vault stores its own `credentialId` and sends `allowCredentials: [id]`, so a non-discoverable credential works. `residentKey: "preferred"` is fine for passkey-style sync.
- No evaluation happens without a **valid assertion** — every unlock is a full user-verification ceremony (biometric/PIN). This is the actual "unlock" UX.

### Flow pseudocode

```js
const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));

// ---- one-time enrollment (must run from a user gesture) ----
async function enrollBiometricUnlock() {
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "2FA Vault", id: RP_ID },          // web app: location.hostname; ext popup: omit or extension ID
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "vault", displayName: "Vault unlock key" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 },    // ES256
                         { type: "public-key", alg: -257 }], // RS256 fallback
      authenticatorSelection: {
        residentKey: "preferred",        // prf does NOT require discoverable; harmless to prefer
        userVerification: "required",    // mandatory: prf maps to CredRandomWithUV
      },
      timeout: 60_000,
      attestation: "none",
      extensions: { prf: {} },           // ask; evaluation at create() rarely supported
    },
  });
  const prf = cred.getClientExtensionResults().prf;
  if (!prf || prf.enabled !== true) throw new Error("PRF unsupported on this authenticator");
  const credentialId = b64u(cred.rawId);            // persist
  const prfSalt = crypto.getRandomValues(new Uint8Array(32)); // persist (non-secret)
  // Next: run a first assertion to get results.first, derive KEK, wrap DEK (below).
  return { credentialId, prfSalt };
}

// ---- every unlock ----
async function unlockWithBiometrics({ credentialId, prfSalt, wrappedDEK }) {
  const allow = [{ id: fromB64u(credentialId), type: "public-key" }];
  const salts = { first: prfSalt };                 // optionally second: rotationSalt
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID,
      allowCredentials: allow,
      userVerification: "required",
      timeout: 60_000,
      extensions: { prf: { evalByCredential: { [credentialId]: salts } } },
    }});
  } catch (e) {                                     // NotSupportedError in some engines
    assertion = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: RP_ID, allowCredentials: allow, userVerification: "required",
      extensions: { prf: { eval: salts } },
    }});
  }
  const results = assertion.getClientExtensionResults().prf && assertion.getClientExtensionResults().prf.results;
  if (!results || !results.first) throw new Error("no PRF results");

  // HKDF over PRF output; salt+info are public, stored alongside
  const ikm = await crypto.subtle.importKey("raw", results.first, "HKDF", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: prfSalt,
      info: enc.encode("2fa-vault-kek-v1") },       // version + purpose tag
    ikm, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  // unwrap stored DEK with kek; same DEK as passphrase unlock path
  const dek = await crypto.subtle.unwrapKey("raw", wrappedDEK, kek,
    { name: "AES-GCM", iv: wrappedIV }, { name: "AES-GCM", length: 256 }, false, ["encrypt","decrypt"]);
  return dek;
}
```

## 2. Browser / authenticator support (late 2026)

From [MDN browser-compat-data](https://github.com/mdn/browser-compat-data) (`api.CredentialsContainer.create/get.publicKey_option.extensions.prf`, dataset dated 2026-10-01), [chromestatus "WebAuthn PRF extension"](https://chromestatus.com/feature/5138422207348736), [Safari 18 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-18-release-notes) ("Added support for the WebAuthn PRF extension"), [WebKit bug 259934](https://bugs.webkit.org/show_bug.cgi?id=259934), [Mozilla bug 1958716](https://bugzilla.mozilla.org/show_bug.cgi?id=1958716):

| Environment | create-side prf | get-side prf (assertion eval) |
|---|---|---|
| Chrome / Edge desktop | 116+ | 116+ |
| Chrome Android | 116+ | 116+ |
| Safari / iOS Safari | 18+ | listed `false` in BCD; platform-authenticator prf reported working in released Safari, hardware-key hmac-secret path fixed Jan 2026 ([WebKit 259934, RESOLVED FIXED](https://bugs.webkit.org/show_bug.cgi?id=259934)). **Treat as unreliable; runtime-detect.** |
| Firefox desktop | 139+ (135-139 partial: not macOS) | 139+ (same partial) |
| Firefox Android | 149+ | **no** ([bug 1958716](https://bugzilla.mozilla.org/show_bug.cgi?id=1958716)) |
| Android WebView | no | no |

`PublicKeyCredential.getClientCapabilities()`: Chrome/Edge 133+, Safari 17.4+, Firefox 135+ (BCD) — gives `await getClientCapabilities()` -> `{ prf: true }`, but ground truth is the `enabled` flag after `create()`.

Platform authenticators: Windows Hello (TPM-backed hmac-secret) and Touch ID (Secure Enclave; iCloud Keychain prf since Safari 18 / iOS 18) work in Chromium + WebKit; Google Password Manager on Android has the client API since Chrome 116 with prf-capable passkeys in later GPM updates (authenticator-side rollout; verify at runtime). Security keys: YubiKey 5.7+ firmware supports hmac-secret/prf (the hardware path is exactly what WebKit fixed in 2026).

### Chrome MV3 extension popup

- Extension pages (popup/options/offscreen) are secure contexts and can call `navigator.credentials`. **rp.id must equal the caller origin's effective domain or a registrable suffix** ([spec §5.4](https://w3c.github.io/webauthn/#rp-id)): a popup **cannot** use the PWA's web origin — Chromium maps extension origin `chrome-extension://<id>` to `<id>.chromiumapp.org` (the same mapping documented for [chrome.identity getRedirectURL](https://developer.chrome.com/docs/extensions/reference/api/identity)). Practical rule: omit `rp.id` (defaults to extension origin) or use the extension ID; cross-context credentials are impossible by design.
- Consequence: PWA and extension get **separate PRF credentials and separate vault keys**. Shared `lib/` code, separate enrollment state (extension already persists in `chrome.storage.local`).
- Call inside a click handler (transient activation). Practitioner caveat: the native UV dialog takes focus; MV3 popups can tear down mid-promise — tolerate restart or run the ceremony from an options/tab page. No extra manifest permission needed for extension-page calls (`publickey-credentials-get` applies to iframes/content-script contexts).

## 3. Key-management design

Decision: **PRF output is a KEK that unwraps the existing DEK; never persisted, re-derived on every unlock.**

- Per-credential secret: the authenticator generates two random 32-byte `CredRandomWithUV`/`CredRandomWithoutUV` values **at `makeCredential` time and associates them with the credential** (CTAP 2.1 §12.5). Output is stable for the credential's lifetime and independent of biometric enrollment: **re-enrolling fingerprints/face does NOT change PRF output; deleting the credential, resetting the authenticator, or losing the synced passkey destroys it permanently.**
- Losing the credential = losing the KEK = losing that envelope only. **Passphrase envelope must remain** the recovery path — both envelopes wrap the same DEK (envelope pattern; `lib/vault.js` PBKDF2 path untouched).
- `localStorage` (PWA) / `chrome.storage.local` (ext) may hold: `credentialId` (b64u), `prfSalt` (random 32B), wrapped DEK, IV, key version. All non-secret; useless to an attacker without the authenticator. Never store the PRF output or the derived KEK.
- Multi-credential: enroll exactly one dedicated credential and pin it — always send `allowCredentials: [storedId]` + `evalByCredential` so a stray passkey cannot be selected and silently produce a different key. Re-enrollment flow: enroll new credential -> assert -> re-wrap DEK under new KEK -> swap storage entry -> (optionally) roll DEK.
- Key rotation: request `second` with a fresh salt in the same assertion (free second output) to rotate the KEK without a second ceremony; or simply re-wrap on next unlock.
- Simplest correct variant (KISS): PRF output is already 256-bit random, so `results.first` could be used directly as an AES-256 key; still run HKDF with an `info` label so the same output can serve other purposes later without cross-protocol key reuse.

## 4. Security caveats

- Entropy: PRF output is a random 32-byte per-credential secret (256-bit). The RP-supplied salt is public — it needs no protection, only stability (spec notes unpredictable inputs also defend against an attacker with time-limited authenticator access).
- Biometric templates never leave the device (Secure Enclave / TPM / GPM); the PRF secret is **not** biometric-derived — biometrics only gate user verification. PWA requires an HTTPS secure context (already satisfied).
- Rate limiting is enforced by the platform (Hello/Touch ID lockout; CTAP UV retries per assertion) and every unlock requires a live ceremony — no new offline brute-force surface beyond the existing AES-GCM envelope. Wrong rp.id fails fast with SecurityError.
- Multi-device nuance: synced passkeys (iCloud Keychain, GPM) carry the prf secret across that ecosystem's devices; a *different* credential produces a different key — another reason to pin one credentialId.

## 5. Feature detection + fallback UX

```js
export async function prfCapable() {
  if (!window.PublicKeyCredential) return false;
  const uv = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(() => false);
  if (!uv) return false;
  try { return (await PublicKeyCredential.getClientCapabilities()).prf === true; }
  catch { return true; } // older engine: rely on enabled-flag check at enrollment
}
```

UX rules: passphrase unlock stays the primary, always-present path; the biometric option appears only when `prfCapable()` **and** a stored `credentialId` exists; enrollment is opt-in with an explicit warning that removing the browser credential/profile requires the passphrase (recovery safety net); on `NotAllowedError`/`InvalidStateError` during unlock, surface "use passphrase" instead of retry loops; treat Safari/iOS assertion-side prf as unknown — capability is proven by `results.first`, never by version sniffing.

## Sources

- [W3C WebAuthn L3 editor's draft, §10.1.4 prf extension](https://w3c.github.io/webauthn/#prf-extension) and [§5.4 RP ID](https://w3c.github.io/webauthn/#rp-id); [W3C TR snapshot](https://www.w3.org/TR/webauthn-3/#prf-extension)
- [FIDO CTAP 2.1 §12.5 hmac-secret (CredRandom semantics)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#hmac-secret-extension)
- [MDN: WebAuthn extensions (prf)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/WebAuthn_extensions) and [MDN browser-compat-data](https://github.com/mdn/browser-compat-data)
- [Chrome Platform Status: WebAuthn PRF extension](https://chromestatus.com/feature/5138422207348736)
- [Apple Safari 18 release notes](https://developer.apple.com/documentation/safari-release-notes/safari-18-release-notes); [WebKit bug 259934](https://bugs.webkit.org/show_bug.cgi?id=259934); [Mozilla bug 1958716](https://bugzilla.mozilla.org/show_bug.cgi?id=1958716)
- [developer.chrome.com: chrome.identity (chromiumapp.org extension-origin mapping)](https://developer.chrome.com/docs/extensions/reference/api/identity)
- [MDN: WebAuthn](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) and [webauthn.guide](https://webauthn.guide/) for ceremony basics

## Limitations / unresolved questions

1. No official developer.chrome.com page on WebAuthn-in-extensions was reachable (candidate paths 404/timeout); extension rp.id behavior is derived from the spec + Chromium's chromiumapp.org convention + practitioner consensus — verify with a minimal popup prototype before implementation.
2. Safari assertion-side prf conflicts: BCD says unsupported, the WebKit bug thread says platform-authenticator prf works in released Safari (bug fixed 2026-01-08 for hardware keys). Needs a live-device smoke test; ship runtime detection regardless.
3. Android GPM prf capability varies by GPM/Chrome version; not verifiable offline — gate on `enabled`/`results` at runtime.
4. Live web-search quota was exhausted during research; versions were pinned via the MDN BCD dataset (2026-10-01) plus primary vendor docs fetched directly (spec HTML, Apple release notes JSON, WebKit/Mozilla trackers). No single-source conclusions.
