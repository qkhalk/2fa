---
title: "Phase 1: Crypto Hardening — KDF Envelope & Passphrase Strength"
description: "Store KDF params inside the encrypted envelope, raise PBKDF2 to 600k iterations with silent legacy upgrade, add passphrase strength heuristic."
status: todo
priority: P1
estimate: 8h
release: 0.1.2
---

# Phase 1: Crypto Hardening — KDF Envelope & Passphrase Strength

## Context Links

- Research: `research/` (none needed — OWASP PBKDF2 guidance in `plans/2026-10-07-improvement-ideas-research.md` H2/H5)
- Scout evidence: `reports/scout-report.md` sections 2, 7
- Parent plan: `plan.md`
- Branch: `qkhalk/feat/vault-hardening` (cut from `main`)

## Overview

- **Priority:** P1 (security first, blocks Phases 2 and 6)
- **Status:** todo
- **Description:** Harden `lib/vault.js` crypto: write `kdf: {algorithm, iterations, hash, saltBytes}` into the encrypted envelope so future parameter changes never break decryption again; default new encrypts to PBKDF2-SHA-256 600,000 iterations (OWASP 2023+); legacy `{salt, iv, data}` payloads decrypt with 150k defaults and silently re-encrypt at 600k on next save. Add a pure local passphrase-strength heuristic consumed by both UIs. Includes a one-time de-duplication refactor: `app.js` currently embeds hand-maintained copies of `lib/otp.js` + `lib/vault.js` (`app.js:1` and `app.js:266` section markers, no imports) while `extension/popup.js:1-22` properly imports from `lib/` — replace the inline sections with ESM imports so every later lib change propagates through the esbuild bundle from a single source. **This refactor is NOT behavior-neutral:** the inline copies have drifted from `lib/` (known deltas documented in Key Insights) — semantics must be reconciled into `lib/` FIRST, in its own non-`refactor:` commit, before the inline block is deleted.

<!-- Updated: Red Team Review Session 1 - de-dup refactor is not behavior-neutral; inline copies drifted from lib (lenient vs strict decrypt, invalidItemCount, migrateBackup fallback) -->

## Key Insights

- `deriveVaultKey` hardcodes `iterations: 150000, hash: "SHA-256"` (`lib/vault.js:46-56`); envelope is only `{salt, iv, data}` (`lib/vault.js:67-71`) — any parameter change today breaks old vaults.
- `decryptVaultEntries` (`lib/vault.js:123-148`) derives from `payload.salt` only; it is the single seam to read stored KDF params.
- `validateEncryptedPayload` (`lib/vault.js:74-84`) checks only `salt/iv/data` string presence — an extra `kdf` field is backward-compatible with it, but it must be extended to validate `kdf` shape when present.
- Upgrade-on-save is nearly free: `persistEntries` (`app.js:1192-1215`, popup `extension/popup.js:458`) already calls `encryptEntries`, which will use the new 600k default; snapshot/rollback on save failure already exists (`app.js:1193-1214`).
- The inline `app.js:1-465` copies have DRIFTED from `lib/` — the de-dup is NOT a clean delete + import. Known deltas (red-team verified):
  - (a) inline `decryptVaultEntries` returns lenient `normalizeEntries(parsed)` while lib throws strict `VAULT_ENTRIES_INVALID` (`lib/vault.js:110-146`);
  - (b) inline `parseBackupFile` reports `invalidItemCount` and skips invalid entries (`app.js:450-463`); the e2e suite `tests/e2e/app-destructive-backup.spec.js:159-214` PINS this lenient behavior, so deleting the inline copy naively breaks e2e;
  - (c) inline `migrateBackup` lacks lib's v1 `payload.vault` fallback branch (`lib/vault.js:192-203`).
- `app.js` application code (line 466+) calls ONLY exported lib symbols — verified usage: otp: `getEntryGroup, extractOtpAuthUri, extractOtpAuthUris, hasDuplicateEntry, normalizeEntries, normalizeEntry, formatCode, compareEntries, parseLabelParts, generateTotp, entryMatchesQuery, getIssuerInitials, normalizeTags, reportError, toUserMessage`; vault: `encryptEntries, decryptVaultEntries, normalizePassphrase, createPlainBackup, createEncryptedBackup, parseBackupFile`. `extractOtpAuthUris` is used at `app.js:1402, 1755, 1806` and is missing from the original import list — it must be imported too. EXCEPTION: `nextOrderValue` (`app.js:212`) is an app-state closure over the module-level `entries` (default param `items = entries`), used at `app.js:1236, 1350, 1375`, and does NOT exist in lib — either move a pure `nextOrderValueFrom(items)` into `lib/otp.js` (recommended) or narrow the deletion zone to keep it; re-audit the zone symbol-by-symbol before deleting.
- `normalizeEntry` divergence on `order`: the web inline copy (`app.js:76-88`) preserves the `order` field, but lib `normalizeEntry` currently strips it — extension ordering survives only via resequence hacks (`popup.js:696`, `app.js:1409`). Lib must preserve `order` (FR7) so both platforms share one semantic.
- `normalizePassphrase` (`lib/vault.js:38-44`) enforces min 8 — stays; strength is advisory UI, not a new gate.
- KDF downgrade surface: the backup checksum is unkeyed (`lib/vault.js:155`), so envelope `kdf` params are attacker-tamperable — a present-but-weak `kdf` (e.g. `iterations: 1000`) must NEVER be honored (FR6 floor).
- GitNexus scout impact: `encryptEntries` upstream 6 (LOW), index contains duplicate symbols from `app.js` inline copies — always pass `file_path` hints pointing at `lib/`.

<!-- Updated: Red Team Review Session 1 - documented inline-vs-lib drift deltas, corrected import list (extractOtpAuthUris, nextOrderValue), order-field divergence, KDF downgrade surface -->

## Requirements

### Functional
- FR1: New encrypted envelopes carry `kdf: {algorithm: "PBKDF2", iterations: 600000, hash: "SHA-256", saltBytes: 16}`.
- FR2: Decrypt reads `payload.kdf` when present; when absent, falls back to legacy params `{PBKDF2, 150000, SHA-256, 16}` — old vaults keep working with zero user action. When `kdf` IS present, `iterations >= 150000` (KDF_PARAMS_LEGACY) is required: a sub-floor `kdf` is treated as legacy → force-upgraded, never honored (the checksum is unkeyed, so `kdf` is tamperable — an attacker-chosen weak work factor must not weaken derivation).
- FR3: Vaults encrypted with legacy params upgrade automatically: next save (and opportunistically right after a successful legacy unlock) re-encrypts at 600k. The auto-upgrade persist fires at most once per payload hash (multi-tab guard, FR8).
- FR4: `assessPassphraseStrength(passphrase)` exported from `lib/vault.js`: pure function returning `{score: 0-4, label, warnings[]}` scoring length (>=12 recommended, >=8 accepted), character classes, and a small common-pattern blacklist.
- FR5: Unlock / set-passphrase forms in web app and extension popup show the strength meter and a soft warning below 12 chars; min length stays 8.
- FR6: KDF floor enforcement (detail of FR2): unit test proves `kdf.iterations = 1000` is upgraded or rejected — never honored.
- FR7: `order` field preservation: `lib/otp.js` `normalizeEntry` preserves the `order` field (matching the web inline copy at `app.js:76-88`); round-trip unit test proves order survives `normalizeEntries`. The resequence hacks (`popup.js:696`, `app.js:1409`) become redundant-but-harmless.
- FR8: Multi-tab guard: a `storage` event listener marks a tab whose vault payload changed underneath it read-only, with a dismissible "vault changed in another tab — reload" banner; writes from the stale tab are blocked. Legacy auto-upgrade persists are scoped to fire once per payload hash so every open tab does not stampede a re-encrypt.

<!-- Updated: Red Team Review Session 1 - added KDF floor (FR6), order preservation (FR7), multi-tab guard (FR8); FR2/FR3 hardened against tampered kdf + multi-tab stampede -->

### Non-functional
- NFR1: `lib/` stays browser/extension agnostic, Web Crypto only, named exports (docs/code-standards.md).
- NFR2: 600k derivation must stay under ~1s on mid-range hardware (PBKDF2-SHA-256 600k is ~300-600ms in Chromium; acceptable for unlock).
- NFR3: No new storage keys; envelope versioning rides the existing `personal_otp_vault_encrypted_v1` / `otp_extension_encrypted_v1` payloads.

## Architecture

**Data flow (encrypt):** `encryptEntries(entries, passphrase)` → generate salt(16B) + iv(12B) → `deriveVaultKey(passphrase, salt, params=KDF_PARAMS_DEFAULT)` → AES-GCM encrypt → return `{salt, iv, data, kdf: {algorithm, iterations, hash, saltBytes}}`.

**Data flow (decrypt):** `decryptVaultEntries(payload, passphrase)` → `validateEncryptedPayload` (now also validates `kdf` object shape when present) → `params = payload.kdf` with floor check (`kdf.iterations < KDF_PARAMS_LEGACY` → treat as legacy) else `KDF_PARAMS_LEGACY` when absent → derive → decrypt → normalize entries.

**Upgrade path:** the hook targets the `decryptStoredEntries` call sites — manual unlock AND unlock-on-load (`decryptVaultEntries` at `app.js:1191` web, `extension/popup.js:694` extension). After successful decrypt, callers invoke new export `isLegacyEncryptedPayload(payload)` (or sub-floor `kdf`); if true, immediately persist via existing `saveEncryptedEntries` (web) / re-encrypt + chrome.storage write (popup). Save-failure leaves the old legacy envelope intact (existing snapshot/rollback). **Backup import (`importBackupFile`, `app.js:1607`) must NOT auto-upgrade mid-import** — it is a decrypt consumer, not an unlock path.

**Multi-tab flow:** `window.addEventListener("storage", ...)` compares the vault key's new value hash; a mismatching tab flips to read-only mode (mutation handlers gated) + banner. Auto-upgrade persist keys off the just-decrypted payload hash (`sessionStorage` sentinel) so only the first tab to unlock performs it.

**De-dup refactor (two commits, semantics first):** the inline block is NOT behavior-identical to lib — (a) inline decrypt is lenient vs lib strict, (b) inline `parseBackupFile` reports `invalidItemCount` and skips invalid entries (pinned by `tests/e2e/app-destructive-backup.spec.js:159-214`), (c) inline `migrateBackup` lacks lib's v1 `payload.vault` fallback. Order of work: FIRST diff every inline function vs its lib counterpart and decide semantics — recommended resolution: port the lenient skip-and-report semantics (`invalidItemCount`) INTO `lib/vault.js` so lib becomes the single source of truth, updating lib unit tests and extension behavior deliberately in its own `feat:`/`fix:` commit (relabeling a semantic change as `refactor:` is explicitly forbidden); THEN delete the `app.js:1-465` inline block, replace it with one import block from `../lib/otp.js` and `../lib/vault.js` (list in Key Insights, including `extractOtpAuthUris` and a pure `nextOrderValueFrom(items)` moved into `lib/otp.js`), and verify with a MECHANICAL post-refactor check — `npm run build` + grep the bundle/source for undefined references (or `eslint no-undef`) — instead of trusting a hand audit.

<!-- Updated: Red Team Review Session 1 - decrypt floor check, upgrade hook retargeted to decryptStoredEntries sites (not app.js:1607), multi-tab flow, two-commit semantics-first de-dup with mechanical verification -->

## Related Code Files

- Modify: `D:\2fa\lib\vault.js` — KDF params constant + floor, envelope write, decrypt param read, `validateEncryptedPayload`, new exports `isLegacyEncryptedPayload`, `assessPassphraseStrength`, `KDF_PARAMS_DEFAULT`; receive the lenient `invalidItemCount` skip-and-report semantics from the inline `parseBackupFile`.
- Modify: `D:\2fa\lib\otp.js` — `normalizeEntry` preserves `order` (FR7); new pure `nextOrderValueFrom(items)` (home for the `app.js:212` closure).
- Modify: `D:\2fa\app.js` — delete inline lib sections (lines 1-465), add corrected imports; wire strength meter + legacy-upgrade-on-unlock; multi-tab storage listener + read-only banner.
- Modify: `D:\2fa\extension\popup.js` — strength meter + legacy-upgrade-on-unlock (`extension/popup.js:694` unlock path); adopt lenient `invalidItemCount` backup semantics once lib is source of truth.
- Modify: `D:\2fa\tests\unit\vault.test.js` — legacy fixture, upgrade detection, KDF floor, strength heuristic tests.
- Modify: `D:\2fa\tests\unit\otp.test.js` — `order` round-trip through `normalizeEntries`; `nextOrderValueFrom` unit test.
- Create: none (no new files required).
- Delete: nothing on disk (app.js inline lib code only).

<!-- Updated: Red Team Review Session 1 - added lib/otp.js order/nextOrderValueFrom work, lenient parse semantics into lib/vault.js, otp.test.js round-trip tests -->

## Implementation Steps

1. Semantic reconciliation FIRST: diff every inline function in `app.js:1-465` against its `lib/` counterpart symbol-by-symbol (GitNexus `context({name: "decryptVaultEntries"})` etc. with `file_path` hints) and record the deltas. Known starting points: (a) inline `decryptVaultEntries` lenient vs lib strict (`lib/vault.js:110-146`); (b) inline `parseBackupFile` `invalidItemCount` skip-and-report (`app.js:450-463`, pinned by `tests/e2e/app-destructive-backup.spec.js:159-214`); (c) inline `migrateBackup` missing lib's v1 `payload.vault` fallback (`lib/vault.js:192-203`). Recommended resolution: port the lenient skip-and-report semantics (`invalidItemCount`) INTO `lib/vault.js` so lib becomes source of truth; update lib unit tests and extension behavior deliberately. Commit `feat: align vault backup parsing on lenient invalidItemCount semantics` (NEVER label this `refactor:`).
2. Mechanical de-dup: run GitNexus `impact({target: "encryptEntries", direction: "upstream"})` to confirm the duplicate-symbol picture; add the corrected import list (Key Insights — including `extractOtpAuthUris`; move `nextOrderValueFrom(items)` into `lib/otp.js` for the `app.js:212` closure or narrow the deletion zone accordingly); delete `app.js:1-465` inline lib sections; verify with a MECHANICAL check — `npm run build` + grep for undefined references (or `eslint no-undef`) — not a hand audit. Run `npm run test:e2e` (`app.spec.js` + `app-destructive-backup.spec.js`). Commit `refactor: import shared lib modules in web app`.
3. In `lib/vault.js`: `impact()` on `deriveVaultKey`, `encryptEntries`, `decryptVaultEntries`, `validateEncryptedPayload`. Add `KDF_PARAMS_DEFAULT` (600000) and `KDF_PARAMS_LEGACY` (150000) constants; parameterize `deriveVaultKey(passphrase, salt, params, cryptoApi)`; write `kdf` into `encryptEntries` return; read `payload.kdf` in `decryptVaultEntries` with the FR2 floor check (absent → legacy; present but `iterations < 150000` → treated as legacy → force-upgrade; never honored); extend `validateEncryptedPayload` to type-check `kdf` fields when present (reject non-positive iterations, unknown hash — fail closed on malformed `kdf`, fall back only on absence).
4. Add exports `isLegacyEncryptedPayload(payload)` (true iff `kdf` missing OR `kdf.iterations < KDF_PARAMS_LEGACY`) and `assessPassphraseStrength(passphrase)` (pure, no crypto, ≤30 lines).
5. In `lib/otp.js`: extend `normalizeEntry` to preserve `order` (FR7); add pure `nextOrderValueFrom(items)`; unit tests in `tests/unit/otp.test.js` (order round-trip through `normalizeEntries`).
6. Web app: hook the upgrade check at the `decryptStoredEntries` call sites — manual unlock AND unlock-on-load (`decryptVaultEntries` at `app.js:1191`) — NOT the backup-import path at `app.js:1607` (`importBackupFile` must not auto-upgrade mid-import); if legacy or sub-floor, re-persist immediately via `persistEntries` (snapshot/rollback already guards failure), gated once-per-payload-hash (FR8). Add strength meter markup + logic to the set-passphrase/unlock form.
7. Extension: same upgrade check at `extension/popup.js:694`; add strength meter to `extension/popup.html` + `popup.js` (mirror web wording).
8. Multi-tab guard: `storage` event listener on the vault keys → read-only mode + "vault changed in another tab — reload" banner; scope the FR3 auto-upgrade persist to fire once per payload hash.
9. Tests (`tests/unit/vault.test.js`): (a) legacy fixture — build an envelope by calling `encryptEntries` against a 150k-parameterized path or hardcode a fixture envelope `{salt, iv, data}` generated once with 150k in a test helper, assert `decryptVaultEntries` succeeds; (b) new envelope contains `kdf` with 600000; (c) `isLegacyEncryptedPayload` true/false cases; (d) malformed `kdf` rejects with `VAULT_FIELDS`; (e) `assessPassphraseStrength` scoring table (8-char weak, 12-char mixed good, common-pattern penalty); (f) `kdf.iterations = 1000` → upgraded or rejected, NEVER honored; (g) lenient `parseBackupFile` parity — invalid entries skipped + `invalidItemCount` reported.
10. Run `detect_changes()` (GitNexus) and confirm only expected symbols/flows changed. Commits: `refactor: import shared lib modules in web app`, `feat: store kdf params in vault envelope and raise pbkdf2 to 600k`, `feat: add passphrase strength heuristic`, `feat: guard vault against multi-tab writes`.

<!-- Updated: Red Team Review Session 1 - reordered steps: semantic reconciliation first, mechanical no-undef check, KDF floor, order preservation, corrected hook lines (app.js:1191 not 1607), multi-tab step, floor/leniency tests -->

## Todo

- [x] Inline-vs-lib drift reconciled into lib (lenient `invalidItemCount` semantics) in its own non-refactor commit
- [x] GitNexus impact on all edited vault symbols; mechanical de-dup of app.js (build + no-undef check) committed
- [x] KDF constants + parameterized deriveVaultKey + envelope kdf field
- [x] KDF floor enforced (sub-floor `kdf` upgraded/rejected, never honored) + unit test
- [x] validateEncryptedPayload kdf validation (fail closed on malformed)
- [x] `order` preserved by normalizeEntry + round-trip test; `nextOrderValueFrom` in lib
- [x] isLegacyEncryptedPayload + assessPassphraseStrength exports
- [x] Web unlock upgrade hook (app.js:1191 sites) + strength meter
- [x] Extension unlock upgrade hook + strength meter (popup.html + popup.js)
- [x] Multi-tab storage listener + read-only banner + once-per-payload-hash upgrade
- [x] Unit tests: legacy fixture, upgrade, malformed kdf, KDF floor, strength scoring, order round-trip
- [x] detect_changes() sweep + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.2` (package.json + extension/manifest.json lockstep)

<!-- Updated: Red Team Review Session 1 - todo list expanded for semantic reconciliation, KDF floor, order preservation, multi-tab guard -->

## Success Criteria

- [x] Legacy `{salt, iv, data}` fixture decrypts successfully; new envelope round-trips and carries `kdf.iterations === 600000`.
- [x] `kdf.iterations = 1000` envelope is upgraded or rejected — never honored (unit test green).
- [x] `order` survives `normalizeEntries` round-trip (unit test green); backup import reports `invalidItemCount` with lib semantics (`app-destructive-backup.spec.js` green).
- [x] `npx vitest run tests/unit/vault.test.js` green; `npm run test:unit` green.
- [x] `npm run build` succeeds; `npx playwright test tests/e2e/app.spec.js` and `npx playwright test tests/e2e/extension.spec.js` green (unlock/save flows unchanged for fresh vaults).
- [x] Unlocking a legacy vault triggers one re-encrypt at 600k (verify stored payload gains `kdf`); a second tab open on the same vault shows the read-only banner instead of double-writing.
- [x] `detect_changes()` shows changes limited to `lib/vault.js`, `lib/otp.js`, `app.js`, `extension/popup.js`, tests.
- [x] Release 0.1.2 prepared after Phase 2 also lands (shared gate).

<!-- Updated: Red Team Review Session 1 - success criteria extended: KDF floor, order round-trip, lenient backup parity, multi-tab banner -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| app.js refactor breaks web app (inline copies have DRIFTED from lib — lenient vs strict decrypt, `invalidItemCount`, migrateBackup fallback) | H x H | Semantics reconciled into lib FIRST in its own `feat:` commit (step 1); then mechanical de-dup with build + no-undef verification (step 2); `app.spec.js` + `app-destructive-backup.spec.js` run before proceeding |
| Multi-tab lost updates: two tabs write, last-writer-wins silently drops the other tab's entries | M x H | FR8 `storage` listener → read-only banner; auto-upgrade persist fires once per payload hash |
| Tampered/sub-floor `kdf` (unkeyed checksum, `lib/vault.js:155`) tricks the app into weak derivation | M x H | FR2/FR6 floor: sub-floor `kdf` treated as legacy → force-upgrade; unit test proves iterations=1000 never honored |
| 600k unlock latency felt as regression on low-end devices | M x M | NFR2 budget ~1s; if exceeded, keep 600k but surface no UI change (one-time cost per unlock); OWASP floor is non-negotiable |
| Downgrade trap: vault re-encrypted at 600k is unreadable by app < 0.1.2 | H x M | Document in README (Phase 8); rollback plan = restore from backup; note in release notes |
| Malformed `kdf` bricks vault | L x H | Fail-closed validation rejects only clearly invalid shapes; absence = legacy fallback, so partial writes can't lock out |

<!-- Updated: Red Team Review Session 1 - risk table: drift risk raised to H x H, added multi-tab lost-update and KDF-downgrade rows -->

## Security Considerations

- OWASP Password Storage CS: PBKDF2-HMAC-SHA256 600k minimum — met by default.
- Salt stays random 16B per encrypt; `saltBytes` recorded for future salt-length changes.
- Strength meter is advisory and fully local (no network, no zxcvbn dependency).
- No secret material (passphrase, key) ever persisted; `kdf` params are non-secret.

## Next Steps

- Phase 2 wraps auto-lock + throttling around this unlock path and adds CSP/jsQR vendoring.

## Rollback Plan

- Revert commits; legacy vaults unaffected (they were never rewritten until a save). Already-upgraded vaults: restore from backup or hand-decrypt (params are readable from the envelope).
