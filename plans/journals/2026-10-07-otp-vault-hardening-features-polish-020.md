---
title: "OTP Vault Hardening, Features & Polish — 0.2.0"
date: 2026-10-07
summary: "8-phase plan executed end to end: KDF envelope, session hardening, HOTP engine, GA import, data-safety UX, WebAuthn PRF biometric unlock, dark mode/DnD/ring/a11y/i18n polish, docs + 0.2.0 release"
---

# OTP Vault Hardening, Features & Polish — 0.2.0

## What shipped

All 8 phases of plans/261006-2150-otp-vault-hardening-features-polish landed, both platforms (PWA + MV3 extension), released as 0.2.0.

- Phase 1: parameterized PBKDF2 KDF envelope (600k default, 150k legacy floor, silent post-unlock upgrade), passphrase strength meter, app.js de-duplication into lib/.
- Phase 2: CSP meta with vendored fonts + bundled jsqr, auto-lock, unlock throttling with backoff, chrome.storage.session CryptoKey cache, crypto-random entry ids.
- Phase 3: HOTP + SHA-256/512 engine, entries v3 storage (v2 read-only fallback), counter increment on reveal/copy.
- Phase 4: Google Authenticator otpauth-migration import with preview UI (batch stitching, percent-encoding traps handled).
- Phase 5: undo-delete tombstone (10 min), backup reminder (30 days), extension export, time-drift check.
- Phase 6: WebAuthn PRF biometric unlock — DEK two-envelope design (lib/biometric.js + vault DEK mode); passphrase recovery central; passphrase-encrypted backups (FR10); requirePassphrase gate; e2e via injected fake PRF authenticator.
- Phase 7: tokenized styles + dark mode (System/Light/Dark), pointer drag & drop (computeDropIndex in lib), per-entry countdown rings, copy haptics, axe pass (0 criticals), i18n framework + unlock/settings t() refactor, dual-theme snapshots.
- Phase 8: docs synced (README, docs/*, CHANGELOG with 8 caveats), releases prepared via release script, plan closed.

## Notable bugs found on the way

- generateVaultDek needed extractable=true + wrapKey/unwrapKey usages for wrapKey("raw") envelope wrapping; same for the recovered DEK after reload (FR11 re-wrap).
- The popup unlock handler read unlockPassphraseInput.value twice with a ~400ms KDF await between reads — retyping mid-derivation let derive and decrypt see DIFFERENT passphrases (derive fail-open + decrypt success). Fixed with a single consistent read.
- Playwright's default colorScheme is light — pinned dark in config + extension launches so existing snapshots stay valid.
- Drag & drop: entryNodes map reuses cards across renders, so handle visibility must be re-derived in the render loop; computeDropIndex needed an inclusive midpoint rule to make drop-on-center meaningful.
- Manual mouse drags need scrollIntoViewIfNeeded + measured-in-final-layout coordinates; off-screen pointers clamp to nothing.

## Test state

124 unit tests, 96 e2e across 10 suites — all green at final gate. Visual snapshots regenerated dual-theme (web + extension) and eyeballed.

## Open manual items

- Real GA export QR round-trip on a device.
- Real platform-authenticator matrix (Windows Hello / Touch ID) — requester confirmed availability.
- Live cloudflare-trace CORS check from the extension popup.

> Historical work record — not durable authority. Prefer docs/specs/ADRs for current decisions.
