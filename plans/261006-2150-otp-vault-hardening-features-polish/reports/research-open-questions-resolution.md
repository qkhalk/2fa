# Research Addendum — Open Questions Resolution (exa)

- **Date:** 2026-10-07
- **Method:** exa MCP web search (WebSearch was rate-limited). Three searches: PRF vault key-wrapping prior art; `chrome.storage.session` for sensitive state; CDP/Playwright prf emulation status + minimal i18n patterns.
- **Purpose:** Evidence base for the four Validation Session 2 decisions (plan.md → Validation Log).

## Q1 — DEK two-envelope vs KEK-wraps-passphrase → **DEK ADOPTED**

Prior art is consistent across independent sources:

- **Bitwarden**: PRF output decrypts a *wrapped copy of the account encryption key* — i.e., a DEK pattern, not a wrapped passphrase ([research paper surveying existing systems](https://www.researchsquare.com/article/rs-10270948/latest.pdf), [lilting.ch analysis](https://lilting.ch/en/articles/passkeys-prf-extension-encryption-risk)).
- **Envelope-encryption guidance** (article citing WebAuthn L3 spec co-editor Cappalli's talk): recommended pattern is `DEK encrypts data → one KEK per authenticator wraps the DEK → PRF output → HKDF → KEK`. Losing one authenticator never cuts off access; the passphrase is simply another KEK. Anti-patterns called out: using raw PRF output as a key (always HKDF with an `info` label), designing around a single authenticator.
- **webauthn-prf-zktv reference implementation**: wraps the SAME 256-bit vault key under two scheme records — `prf-v1` (HKDF-from-PRF) and `pw-v1` (memory-hard password KDF) — with scheme tags and frozen domain-separation labels; migration between labels never mutates v1. This is exactly the plan's `dek` + `kdf.mode: "dek-v1"` marker design.
- **1Password** ships a PRF passkey library for E2EE; **Dashlane+Yubico** use PRF for vault unlock — both DEK-style.

Platform-support updates relevant to phase-06 (all still runtime-detect, never version-sniff):
- **Windows Hello**: prf supported from Windows 11 **25H2+** (WebAuthn API v8); older builds only external keys.
- **Chrome/Edge**: prf can be evaluated **at registration** from Chrome 147 → single-ceremony enrollment possible (keep the `enabled`-flag + assertion fallback for everything older).
- **iOS/iPadOS 18.0–18.3**: prf data-loss bug, fixed in 18.4+.
- **Firefox**: prf from 139+ desktop (147/148 per one source), no Android.

## Q2 — chrome.storage.session cache → **ADOPT**

- [Chrome storage docs](https://developer.chrome.com/docs/extensions/reference/api/storage): *"If you are working with sensitive user data, instead use `storage.session`"* — items are in-memory, never persisted to disk, cleared when the browser closes or the extension is disabled/reloaded/updated; default access level is trusted contexts only (popup/options/SW), which is what we want — never call `setAccessLevel`.
- Lifetime nuance: session storage **survives SW eviction** (it lives in the browser process, ~10 MB quota) but is cleared on extension **update** — treat an update like a browser restart.
- **Bitwarden's pattern** (documented in extension-security guidance): store the unlocked vault state in `chrome.storage.session`, clear on lock/browser close — described as "the right balance for most extensions"; threat model "someone with disk access" is mitigated, "compromised SW" already implies live-RAM access.
- **Auto-lock**: `chrome.alarms` (periodic tick) + `chrome.idle.queryState` enforce idle-lock and clear session state even with no popup open — standard pattern in shipping vault extensions; the `storage` + `alarms` + `idle` permissions are the required set.

## Q3 — CDP/Playwright prf emulation → **NOT available; manual matrix confirmed**

- CDP `WebAuthn.addVirtualAuthenticator` (ctap2/ctap2_1, `hasUserVerification`, `automaticPresenceSimulation`) works via Playwright `CDPSession` on Chromium ([Playwright #7276](https://github.com/microsoft/playwright/issues/7276), [working example](https://github.com/microsoft/playwright/issues/32112)).
- Playwright merged `context.credentials` (PR #40849, May 2026) — WebAuthn seeding/ceremony interception across Chromium/Firefox/WebKit — but **no source documents prf/hmac-secret output emulation**; the DevTools WebAuthn panel options (protocol, transport, resident keys, user verification, large blob) contain no prf switch.
- Conclusion stands: e2e covers feature-detection negative paths and UI gating; real prf ceremonies need a real authenticator — **requester confirmed availability (Windows Hello / Touch ID) for the manual matrix**, and a real GA export QR for phase-04 manual acceptance.

## Q4 — i18n depth → **unlock + settings only**

Minimal dependency-free patterns found are 20–70 lines (flat dictionary object + `t(key, params)` with `{param}` interpolation + fallback to key), confirming the phase-07 framework estimate is cheap. Scope decision: migrate only unlock + settings surfaces this release (pattern proof), reserve toast/import keys.

## Sources

- [WebAuthn PRF-Based Vault Key Wrapping (research paper)](https://www.researchsquare.com/article/rs-10270948/latest.pdf)
- [webauthn-prf-zktv (reference implementation)](https://github.com/ghopnsrcntrbtr/webauthn-prf-zktv)
- [PRF risks & envelope-encryption recommendation — lilting.ch](https://lilting.ch/en/articles/passkeys-prf-extension-encryption-risk)
- [Yubico: PRF extension concepts](https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/index.html)
- [web-auth/webauthn-framework prf demo](https://github.com/web-auth/webauthn-framework/tree/5.4.x/docs/examples/prf-demo)
- [Chrome for Developers: browser.storage](https://developer.chrome.com/docs/extensions/reference/api/storage)
- [chrome.storage.session vs local — MV3 Extension Dev Hub](https://mv3-extension.com/core-apis-cross-browser-data-management/chrome-storage-api-sync/chrome-storage-session-vs-local/)
- [Extension key-storage security guidance (Bitwarden pattern)](https://github.com/harry-harish/chrome-extension-builder/blob/main/skills/extension-security/references/key-storage.md)
- [Playwright WebAuthn support thread #7276](https://github.com/microsoft/playwright/issues/7276) · [context.credentials PR #40849](https://github.com/microsoft/playwright/pull/40849)
- [Chrome DevTools WebAuthn tab](https://developer.chrome.com/docs/identity/webauthn-tab)
