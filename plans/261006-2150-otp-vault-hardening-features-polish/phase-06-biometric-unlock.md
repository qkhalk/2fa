---
title: "Phase 6: Biometric Unlock — WebAuthn PRF Envelope"
description: "Opt-in biometric unlock: PRF output derives a KEK that unwraps a random vault DEK; passphrase envelope stays as recovery — web app and extension (separate credentials per platform)."
status: todo
priority: P2
estimate: 12h
release: 0.1.5
---

# Phase 6: Biometric Unlock — WebAuthn PRF Envelope

## Context Links

- Research: `research/research-webauthn-prf.md` (authoritative: ceremony sequence, HKDF/KEK/wrap design, browser support, MV3 rp.id rules, fallback UX)
- Research addendum: `reports/research-open-questions-resolution.md` (exa, 2026-10-07: DEK two-envelope is the industry pattern — Bitwarden + envelope-encryption guidance; Windows Hello prf from Windows 11 25H2+; Chrome 147 evaluates prf at registration; CDP/Playwright still do not emulate prf outputs)
- Scout evidence: `reports/scout-report.md` sections 1, 2, 5
- Depends on: Phase 1 (KDF-parameterized envelope is the recovery path the DEK wraps into), Phase 2 (`lockVault` must also drop DEK handles)
- Parent plan: `plan.md`

## Overview

- **Priority:** P2 (large, gated behind all core hardening)
- **Status:** todo
- **Description:** Opt-in biometric unlock via the WebAuthn `prf` extension. On enrollment the vault switches to a two-envelope DEK design: vault data is encrypted with a random 256-bit DEK; the DEK is wrapped once under the passphrase-derived key (existing PBKDF2 path — recovery) and once under an HKDF-derived KEK from the authenticator's PRF output. Biometric unlock holds the DEK in memory: EVERY subsequent mutation re-encrypts under the held DEK (the save path is rewired — biometric unlock never sets `currentPassphrase`), exports re-encrypt under the passphrase key so backups stay universally restorable, and passphrase change re-wraps the same DEK. Unlock via biometrics runs a full UV ceremony every time; the passphrase path always remains. Web app and extension enroll SEPARATE credentials (extension rp.id is its own origin — cross-context credentials are impossible by design).

<!-- Updated: Red Team Review Session 1 - description: DEK save-path rewiring, passphrase-encrypted backups, passphrase-change re-wrap -->

## Key Insights

- PRF semantics (research §1): outputs are 32-byte per-credential secrets stable for the credential's lifetime, INDEPENDENT of biometric enrollment — re-enrolling fingers is safe; deleting the browser credential destroys the PRF envelope (passphrase recovery still works). `create()`-time evaluation is almost never supported — expect `enabled` flag only; first real output comes from an assertion. Always `userVerification: "required"` (CredRandomWithUV).
- Unlock ceremony (research §1 pseudocode): `get()` with `allowCredentials: [storedId]` + `prf.evalByCredential` (keys must be base64url and match allowCredentials); catch `NotSupportedError` → retry with `prf.eval`. Never send empty allowCredentials. `results.first` → HKDF-SHA256 (salt = stored `prfSalt`, info = "2fa-vault-kek-v1") → AES-256-GCM KEK → `subtle.unwrapKey` the DEK.
- Envelope design (research §3): never persist PRF output or KEK. Storage may hold non-secrets: `credentialId` (b64u), `prfSalt` (32B), wrapped DEK + IV. Pin exactly ONE credential — always `allowCredentials: [storedId]` so a stray passkey can't silently produce a different key.
- Two-envelope vault format (biometric mode only; non-biometric vaults keep the Phase 1 envelope untouched, zero migration): `data` re-encrypted under the DEK; envelope gains `dek: {wrapped, iv}` where `wrapped` = DEK wrapped under the passphrase-derived key (same PBKDF2 params/kdf block). Disenroll = unwrap DEK via passphrase → re-encrypt data directly → remove biometric records (clean revert to Phase 1 format). The envelope MUST carry a format marker (e.g. `kdf.mode: "dek-v1"`) so pre-0.1.5 code reports "newer format" instead of a misleading "Incorrect passphrase".
- Save-path hazard (red-team, Critical): biometric unlock never sets `currentPassphrase`, so the existing save paths — `persistEntries`/`saveEncryptedEntries` (`app.js:1177-1214`, `popup.js:458-478`) — would fail to re-encrypt or would orphan the DEK. In biometric mode the save path gains a DEK branch: every mutation re-encrypts data under the held DEK (stable salt; envelope keeps both `dek.wrapped` blocks). Biometric unlock must NOT depend on `currentPassphrase` for persistence (FR8).
- Decrypt consumers (red-team): `decryptVaultEntries` has exactly 3 call sites — `app.js:1191` (`decryptStoredEntries` unlock path), `app.js:1607` (`importBackupFile`), `popup.js:694` (extension unlock). EVERY one must unwrap `dek` with the passphrase key when present, or passphrase recovery and backup import break in biometric mode (FR9).
- Backup restorability (red-team, Critical): an envelope whose `data` is DEK-encrypted cannot be restored by passphrase alone on any version if exported as-is. Backup export in biometric mode therefore re-encrypts data under the passphrase key (disenroll-style transformation, done in memory at export time) — backups remain restorable on any version and by passphrase alone (FR10).
- Passphrase change (red-team): `changeVaultPassphrase` (`app.js:1521-1541`, `popup.js:134-155`) in DEK mode must RE-WRAP the SAME DEK under the new passphrase key — NOT a fresh-salt re-encrypt of all data (slow, and risks losing the biometric wrap). The encryption-off/reset path (`popup.js:653`) deletes the biometric record (FR11).
- Passphrase re-prompt (red-team): biometric unlock leaves `currentPassphrase` empty, and export currently throws without it (`app.js:1512-1513`). Export/import/disenroll under biometric mode are gated behind `requirePassphrase()` (one passphrase re-entry, FR12).
- Enrollment atomicity (red-team): enrollment is a TWO-STORE write (envelope + biometric record) — specified order: envelope write FIRST (it stays passphrase-recoverable), biometric record SECOND; at unlock, an orphaned biometric record with no `dek` block in the envelope is reconciled by deleting the record (crash recovery).
- MV3 popup (research §2): extension pages are secure contexts; `rp.id` defaults to the extension origin — the popup CANNOT use the PWA's web origin. Run ceremonies inside click handlers (transient activation); popup can tear down mid-promise — tolerate restart, offer retry. Research unresolved Q1: verify with a minimal popup prototype BEFORE building full UI [UNVERIFIED: no official chrome.com doc reachable].
- Browser support (research §2): Chrome/Edge 116+, Safari 18+ (assertion side unreliable — runtime-detect, never version-sniff), Firefox 139+. Feature-gate everything: `prfCapable()` (research §5) + stored `credentialId`; capability proven by `results.first`, never by UA. Validation Session 2 addendum: Windows Hello supports prf from Windows 11 25H2+ (WebAuthn API v8); Chrome 147 evaluates prf at registration (single-ceremony enrollment possible); iOS 18.0–18.3 had a prf data-loss bug fixed in 18.4+ — runtime capability proof remains authoritative.
- Auto-lock integration: `lockVault()` (Phase 2) must also drop the unwrapped DEK handle; biometric unlock replaces only the unlock step, auto-lock semantics unchanged.
- Unit-testability: `lib/biometric.js` takes `credentialsApi` and `cryptoApi` as parameters (mirrors the lib cryptoApi pattern) — Node 20 `crypto.webcrypto.subtle` supports HKDF + wrapKey/unwrapKey, so wrap/unwrap/HKDF/b64u are unit-tested without a browser; the ceremony itself gets a stubbed credentialsApi. CDP virtual authenticators do NOT emulate prf/hmac-secret — e2e covers feature-detection negative paths only; real-ceremony verification is a manual matrix (assets CONFIRMED — requester provides a real platform authenticator, Windows Hello / Touch ID; Validation Session 2).

## Requirements

### Functional
- FR1: `lib/biometric.js` exports: `prfCapable()`, `enrollBiometricUnlock({rpId, credentialsApi, cryptoApi})` → `{credentialId, prfSalt, firstPrfOutput}`, `deriveKek(prfOutput, prfSalt, cryptoApi)`, `unwrapDek(wrapped, iv, kek, cryptoApi)`, `wrapDek(dek, kek, iv, cryptoApi)`, b64u helpers.
- FR2: Enrollment (Settings, opt-in, both platforms): prfCapable() gate → create ceremony → assert → derive KEK → generate DEK → re-encrypt vault data under DEK → store passphrase-wrapped DEK in envelope + PRF-wrapped DEK in new storage key (`personal_otp_vault_biometric_v1` / `otp_extension_biometric_v1` = `{credentialId, prfSalt, wrappedDek, wrappedIv}`) → explicit warning copy ("removing this browser credential requires the passphrase"). Enrollment is a TWO-STORE write with fixed order: envelope first (stays passphrase-recoverable), biometric record second; a crash between the two leaves an orphaned record that unlock reconciliation removes. Envelope gains format marker `kdf.mode: "dek-v1"` (or equivalent).
- FR3: Biometric unlock: button on unlock screen when biometric record exists → ceremony → KEK → unwrap PRF-wrapped DEK → decrypt vault → HOLD the DEK in memory (subject to auto-lock). On `NotAllowedError`/`InvalidStateError` → message directing to passphrase (no retry loops, research §5). Orphaned-record reconciliation: if the envelope has no `dek` block but a biometric record exists, delete the record and fall back to passphrase-only mode.
- FR4: Passphrase unlock in biometric mode: PBKDF2 key unwraps envelope `dek` (existing unlock handler gains one unwrap step when `dek` present) — recovery always available even without the authenticator.
- FR5: Disenroll: verify passphrase (or successful biometric) → unwrap DEK → re-encrypt data directly → delete biometric storage key.
- FR6: Extension parity: own enrollment state, rp.id omitted (extension-origin default), popup-teardown-tolerant ceremony.
- FR7: `lockVault()` clears DEK/KEK references on both platforms.
- FR8: Save path rewiring: `persistEntries`/`saveEncryptedEntries` (`app.js:1177-1214`, `popup.js:458-478`) gain a DEK branch — when a biometric-unlocked DEK is held in memory, every mutation re-encrypts data under the held DEK (stable salt across saves; envelope's `dek.wrapped` blocks under BOTH passphrase key and KEK stay valid, re-wrapped as needed). Biometric unlock must NOT depend on `currentPassphrase` for persistence. Write ordering: envelope write first, biometric record second (same contract as enrollment).
- FR9: All decrypt consumers unwrap `dek`: the 3 `decryptVaultEntries` call sites — `app.js:1191` (`decryptStoredEntries`), `app.js:1607` (`importBackupFile`), `popup.js:694` — each unwrap the `dek` block with the passphrase key when present before decrypting data. Backup import of a DEK-mode envelope decrypts via the passphrase-wrapped DEK exactly like unlock.
- FR10: Passphrase-encrypted backups: backup export in biometric mode re-encrypts the data under the passphrase key (the disenroll-style transformation, in memory) and emits a standard Phase-1-format envelope — backups remain restorable on ANY version (including pre-0.1.5) and by passphrase alone. The exported file never contains the `dek` block.
- FR11: Passphrase change re-wrap: `changeVaultPassphrase` (`app.js:1521-1541`, `popup.js:134-155`) in DEK mode re-wraps the SAME DEK under the new passphrase key (no fresh-salt re-encrypt of data; biometric wrap untouched). The encryption-off/reset path (`popup.js:653`) deletes the biometric record along with the vault.
- FR12: Passphrase re-prompt gate: `requirePassphrase()` gates export, import, and disenroll under biometric mode (biometric unlock leaves `currentPassphrase` empty; export currently throws at `app.js:1512-1513`) — one passphrase entry per sensitive operation, then release.

<!-- Updated: Red Team Review Session 1 - FR2/FR3 amended (two-store order, format marker, DEK in memory, orphan reconciliation); new FR8 save path, FR9 decrypt consumers, FR10 passphrase-encrypted backups, FR11 passphrase-change re-wrap, FR12 requirePassphrase gate -->

### Non-functional
- NFR1: lib/biometric.js is WebCrypto-only, parameterized APIs, Node-testable (docs/code-standards.md).
- NFR2: No PRF output, KEK, DEK, or passphrase ever persisted or logged.
- NFR3: Enrollment requires an unlocked vault + fresh user gesture; re-enrollment = enroll new → assert → re-wrap → swap storage atomically.

## Architecture

**Key hierarchy:** `PRF output (authenticator-held)` →HKDF→ `KEK (never stored)` →unwrap→ `DEK (random 256-bit, stored only wrapped 2x)` →decrypt→ `vault data`. Parallel: `passphrase` →PBKDF2 (kdf block)→ `passphrase key (never stored)` →unwrap→ same `DEK`.

**Data flow (enroll):** unlocked vault + click → create(prf:{}) → enabled? → get(assert) → results.first → KEK → DEK = random 32B → re-encrypt entries with DEK → envelope `{...kdf, salt, iv, data, kdf.mode: "dek-v1", dek:{wrapped(passphraseKey), iv}}` → persist envelope FIRST → persist biometric record SECOND (two-store ordering; crash between = orphaned record reconciled at unlock).

**Data flow (unlock-biometric):** click → get(evalByCredential) → KEK → unwrap biometric-wrapped DEK → decrypt data → hold DEK in memory (subject to auto-lock). If envelope lacks `dek` but a biometric record exists → delete record, fall back to passphrase-only (orphan reconciliation).

**Data flow (unlock-passphrase, biometric mode):** passphrase → PBKDF2 key → unwrap `dek` from envelope → decrypt data. (`currentPassphrase` may be held after this path; it is NOT held after biometric unlock.)

**Data flow (save, biometric mode):** mutation → `persistEntries`/`saveEncryptedEntries` sees held DEK → re-encrypt `data` under DEK (stable salt) → write envelope first → biometric record second. No passphrase involvement.

**Data flow (export, biometric mode):** `requirePassphrase()` gate → passphrase key → unwrap DEK → re-encrypt data under passphrase key in memory → emit standard Phase-1 envelope (no `dek` block) → download.

**Data flow (passphrase change, biometric mode):** old passphrase key unwraps DEK → re-wrap DEK under new passphrase key → write envelope (data untouched, same salt) → biometric record unchanged (KEK wrap independent).

<!-- Updated: Red Team Review Session 1 - flows: enrollment two-store ordering + mode marker, orphan reconciliation, save/export/passphrase-change in biometric mode -->

**Feature detection UX:** Settings section visible iff `prfCapable()`; unlock button visible iff biometric record exists; Safari treated as unknown until `results.first` proves it.

## Related Code Files

- Create: `D:\2fa\lib\biometric.js` — ceremony, HKDF/KEK, wrap/unwrap, `prfCapable`, b64u helpers (parameterized credentialsApi/cryptoApi).
- Modify: `D:\2fa\lib\vault.js` — accept optional `dek` block: `encryptEntries`/`decryptVaultEntries` gain DEK-aware variants (`encryptEntriesWithDek` / small extension of envelope validation for `dek`; legacy/normal paths untouched).
- Modify: `D:\2fa\app.js` + `D:\2fa\index.html` — settings biometric section, unlock button, enroll/disenroll flows, DEK-aware lock/unlock wiring; DEK branch in `persistEntries`/`saveEncryptedEntries` (`app.js:1177-1214`), `dek` unwrap at both decrypt consumers (`decryptStoredEntries` `app.js:1191`, `importBackupFile` `app.js:1607`), passphrase re-encryption on export (`app.js:1516-1519`), re-wrap in `changeVaultPassphrase` (`app.js:1521-1541`), `requirePassphrase()` gate (export throws today at `app.js:1512-1513`).
- Modify: `D:\2fa\extension\popup.js` + `popup.html` — parity with extension rp.id handling; same DEK-branch work at `changeVaultPassphrase` (`popup.js:134-155`), `persistEntries`/save (`popup.js:458-478`), unlock decrypt consumer (`popup.js:694`), encryption-off/reset deletes biometric record (`popup.js:653`).
- Modify: `D:\2fa\extension\manifest.json` — no new permissions needed (research §2: extension-page ceremonies need none) — touch only via release script version bump.
- Create: `D:\2fa\tests\unit\biometric.test.js` — HKDF/wrap/unwrap round-trip, b64u, enroll-state machine with stubbed credentialsApi, DEK envelope round-trip through lib/vault.
- Create: `D:\2fa\tests\e2e\biometric.spec.js` — negative paths: prfCapable false hides UI; unlock button hidden without record; passphrase path unaffected in biometric mode (seed storage records).

## Implementation Steps

1. Prototype gate (research unresolved Q1): minimal MV3 popup calling `navigator.credentials.get` with `prf.evalByCredential` on a virtual/real authenticator; confirm extension-origin rp.id + popup teardown behavior. Record findings in `reports/`. Do not proceed to full UI until confirmed.
2. Design decision (RESOLVED — Validation Session 2, 2026-10-07): DEK two-envelope ADOPTED. Rationale: it is the established industry pattern — Bitwarden's PRF unlock unwraps a wrapped copy of the account encryption key; envelope-encryption guidance from the WebAuthn L3 spec co-editor community explicitly recommends a DEK with per-authenticator KEKs; the webauthn-prf-zktv reference implementation wraps the SAME vault key under both `prf-v1` and `pw-v1` schemes. KEK-wraps-passphrase is a nonstandard shape (the wrap plaintext is variable-length user input) and saves no work here since passphrase change must re-wrap either way. Keep the call-site sanity check (3 `decryptVaultEntries` sites: `app.js:1191`, `app.js:1607`, `popup.js:694`; 2 save paths: `app.js:1177-1214`, `popup.js:458-478`) as an implementation checklist for FR8-FR12 — it is verification, not an open choice.
3. GitNexus `impact({target: "encryptEntries"})`, `impact({target: "decryptVaultEntries"})`, `impact({target: "validateEncryptedPayload"})` (file_path hint `lib/vault.js`); `impact({target: "persistEntries"})`, `impact({target: "changeVaultPassphrase"})`.
4. Write `lib/biometric.js` per research §1 pseudocode: b64u/fromB64u, `prfCapable`, `runCreateCeremony`, `runAssertCeremony` (evalByCredential with eval fallback), `deriveKek` (HKDF-SHA256, salt=prfSalt, info="2fa-vault-kek-v1"), `wrapDek`/`unwrapDek`. All take `credentialsApi`/`cryptoApi` params.
5. Extend `lib/vault.js`: `validateEncryptedPayload` accepts optional `dek {wrapped, iv}` + `kdf.mode: "dek-v1"` marker; add `unwrapDekWithPassphrase(payload, passphrase)` and `encryptEntriesWithDek(entries, dek, ...)` / DEK-variant decrypt (or a `keyOverride` param on the existing pair — implementer's choice, keep one code path for AES-GCM).
6. Web integration: enrollment + unlock UI per FR2/FR3/FR5 (two-store write order + orphan reconciliation); DEK branch in `persistEntries`/`saveEncryptedEntries` (FR8); `dek` unwrap at `decryptStoredEntries` (`app.js:1191`) AND `importBackupFile` (`app.js:1607`) (FR9); passphrase re-encryption on export (FR10); re-wrap in `changeVaultPassphrase` (FR11); `requirePassphrase()` gate for export/import/disenroll (FR12); wire `lockVault` (Phase 2) to drop DEK; ensure Phase 1 legacy-upgrade path still works (biometric mode only after a 600k save).
7. Extension parity per FR6 after step-1 prototype validation — including save-path DEK branch (`popup.js:458-478`), decrypt consumer (`popup.js:694`), passphrase-change re-wrap (`popup.js:134-155`), reset deletes biometric record (`popup.js:653`).
8. Tests: unit round-trips (DEK wrap/unwrap under both KEKs; b64u vectors; envelope with `dek` validates + decrypts; tampered wrappedDek fails closed; backup export in DEK mode emits a standard envelope restorable by passphrase alone — FR10; passphrase change re-wraps DEK without re-encrypting data — FR11); e2e negative paths (FR UI gating, orphaned-record reconciliation); manual hardware matrix (Windows Hello, Touch ID — assets confirmed available, Validation Session 2) recorded in `reports/`.
9. `detect_changes()` sweep. Commits: `feat: add webauthn prf biometric module`, `feat: add dek envelope mode to vault`, `feat: rewire save and backup paths for dek mode`, `feat: biometric unlock ui for web and extension`.

<!-- Updated: Red Team Review Session 1 - design decision gate step, DEK save path, decrypt consumers, passphrase-encrypted backups, re-wrap, requirePassphrase gate, reset-path cleanup, extended tests/commits -->

## Todo

- [x] MV3 popup PRF prototype verified (research Q1) — findings in reports/
- [x] Design decision recorded: DEK two-envelope ADOPTED (Validation Session 2 — industry prior art: Bitwarden, envelope-encryption guidance, webauthn-prf-zktv)
- [x] lib/biometric.js complete + parameterized
- [x] lib/vault.js DEK envelope support (validate + `kdf.mode` marker + unwrap + encrypt variants)
- [x] Save path DEK branch: mutations persist under held DEK without currentPassphrase (web + extension)
- [x] All 3 decrypt consumers unwrap `dek` (app.js:1191, app.js:1607, popup.js:694)
- [x] Passphrase-encrypted backups on export (standard envelope, no `dek` block)
- [x] Passphrase change re-wraps DEK; reset path deletes biometric record
- [x] requirePassphrase() gate on export/import/disenroll; orphaned-record reconciliation at unlock
- [x] Web enroll/disenroll/unlock UI + lockVault DEK clearing
- [x] Extension parity (own credential + rp.id rule)
- [x] Unit tests (round-trips, tamper fail-closed, backup restorability, re-wrap) + e2e negative paths
- [x] Manual hardware matrix smoke recorded (real authenticator — asset confirmed available)
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.5`

<!-- Updated: Red Team Review Session 1 - todos: decision gate, save path, decrypt consumers, backup re-encryption, re-wrap, re-prompt gate, reconciliation -->

## Success Criteria

- [x] `npx vitest run tests/unit/biometric.test.js` and `npx vitest run tests/unit/vault.test.js` green; `npm run test:unit` green.
- [x] `npm run build` green; `npx playwright test tests/e2e/biometric.spec.js`, `tests/e2e/app.spec.js`, `tests/e2e/extension.spec.js` green.
- [x] After biometric unlock (no passphrase entered): add/edit/delete an entry and reload — the mutation persisted (FR8 save path proven).
- [x] A backup exported in biometric mode restores by passphrase alone on the CURRENT version AND decrypts on pre-0.1.5 code (FR10; fixture-tested).
- [x] Passphrase change in biometric mode succeeds without re-encrypting data (envelope salt unchanged; `dek.wrapped` updated) and biometric unlock still works (FR11).
- [x] Export/import/disenroll under biometric mode prompt for the passphrase once (FR12); orphaned biometric record self-heals to passphrase-only mode.
- [x] Manual smoke on real authenticator: enroll → lock → biometric unlock works; delete browser credential → passphrase unlock still works; disenroll restores the plain envelope format.
- [x] Storage audit: no PRF output/KEK/DEK-plaintext/passphrase in any persisted key (code review + grep).

<!-- Updated: Red Team Review Session 1 - success criteria: save-path persistence, backup restorability, re-wrap, re-prompt gate, reconciliation -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Browser/authenticator PRF variance (Safari assertion side, Android GPM) | H x M | Runtime capability proof (`results.first`), passphrase fallback always present, manual matrix + known-limitations docs |
| Save path not rewired → mutations fail or orphan the DEK after biometric unlock | (red-team Critical) H | FR8 DEK branch in both `persistEntries`/`saveEncryptedEntries`; success criterion: mutate-after-biometric-unlock survives reload; detect_changes() covers both save paths |
| A decrypt consumer misses `dek` unwrap → passphrase recovery or backup import breaks | M x H | FR9 enumerates ALL 3 call sites (`app.js:1191`, `app.js:1607`, `popup.js:694`); unit test per call site; backup-import round-trip test |
| DEK-mode bug locks users out of vault | L x H | Passphrase unwrap is the primary recovery and uses the SAME well-tested PBKDF2 path; enrollment requires a fresh successful passphrase unlock; disenroll tested both directions; backups re-encrypted under the passphrase at export (FR10) — restorable on any version |
| Popup teardown mid-ceremony (MV3) | M x M | Prototype gate (step 1); tolerate restart + retry copy; consider options-page ceremony if popup proves unstable |
| PRF envelope lulls users into dropping passphrase discipline | M x M | Enrollment warning copy; passphrase remains required for backups, import, and disenroll (FR12 gate) |

<!-- Updated: Red Team Review Session 1 - risks: save-path and decrypt-consumer rows added, backup restorability updated to FR10 mechanism -->

## Security Considerations

- Biometric templates never leave the platform authenticator; PRF output is not biometric-derived — UV gates each ceremony (research §4).
- Platform rate-limiting handles brute force; no new offline surface beyond AES-GCM.
- Salt/info labels public by design; one pinned credentialId prevents stray-passkey key confusion; synced-passkey multi-device nuance documented.
- Backups are passphrase-based BY CONSTRUCTION: export in biometric mode re-encrypts data under the passphrase key in memory and strips the `dek` block (FR10) — recovery media never depends on the authenticator or on 0.1.5 code. The `kdf.mode: "dek-v1"` marker ensures old code fails with "newer format", not a misleading passphrase error.
- Held-DEK lifetime equals unlocked-vault lifetime: dropped by `lockVault()` (FR7), never persisted unwrapped, never logged (NFR2).

## Next Steps

- Phase 7 polish (dark mode, DnD) touches styles/rendering only — no crypto interplay.

## Rollback Plan

- Feature is opt-in; disenroll restores the exact Phase 1 envelope format. Code revert on a biometric-mode vault: passphrase unlock breaks ONLY in the reverted code (no `dek` support) and only for the LIVE vault — recovery = restore from a backup (which FR10 guarantees is passphrase-encrypted and version-agnostic, so the restore claim is now true on any version) or re-apply the feature to disenroll. The "requires ≥0.1.5" restriction therefore applies ONLY to the live biometric-mode vault, never to backups. Document this in release notes (Phase 8).

<!-- Updated: Red Team Review Session 1 - rollback: backup restore claim now true via FR10 passphrase-encrypted backups; >=0.1.5 applies only to the live vault -->
