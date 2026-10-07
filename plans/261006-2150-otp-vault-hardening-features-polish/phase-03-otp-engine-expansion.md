---
title: "Phase 3: OTP Engine Expansion — HOTP, SHA-256/512"
description: "Full HOTP support (type/counter fields, generateHotp, counter-on-reveal semantics) and TOTP SHA-256/512 via a parameterized HMAC seam, validated against RFC 4226/6238 vectors."
status: todo
priority: P1
estimate: 8h
release: 0.1.3
---

# Phase 3: OTP Engine Expansion — HOTP, SHA-256/512

## Context Links

- Research: `research/research-ga-migration-hotp.md` sections 3, 4, 5 (authoritative: RFC vectors, counter semantics, URI params)
- Scout evidence: `reports/scout-report.md` section 3
- Depends on: Phase 1 (app.js imports lib — lib edits propagate via bundle)
- Parent plan: `plan.md`

## Overview

- **Priority:** P1 (prerequisite for GA migration import in Phase 4 — GA exports contain HOTP entries)
- **Status:** todo
- **Description:** Expand `lib/otp.js` into a full OTP engine: entries gain `type` ('totp' | 'hotp'), per-entry `counter`, and `algorithm` ('SHA1' | 'SHA256' | 'SHA512'); add `generateHotp` sharing the existing HMAC + dynamic-truncation path; parameterize the hash in the single HMAC seam; teach `parseOtpAuthUri` to accept `otpauth://hotp` and SHA-256/512. Wire counter-increment-on-reveal/copy into both UIs. All validated against RFC 4226 Appendix D (10 vectors) and RFC 6238 Appendix B (3 distinct seeds).

## Key Insights

- `generateTotp` (`lib/otp.js:307-319`) already does 8-byte BE counter + RFC 6238 truncation; `hmacSha1` (`lib/otp.js:297-305`) is the single hash seam — parameterizing `hash` on `importKey`/`sign` is the entire SHA-256/512 delta. Truncation/digits/T math are hash-agnostic.
- HOTP(K,C) = Truncate(HMAC-SHA-1(K, 8-byte BE C)) — byte-identical to the TOTP path except the counter input (research §3). Zero new crypto.
- `normalizeEntry` (`lib/otp.js:91-103`) is the shape gate for every entry (import, backup, manual) — new fields land here with defaults: `type: 'totp'`, `counter: 0`, `algorithm: 'SHA1'`.
- `hasRequiredBackupEntryShape` (`lib/vault.js:96-108`) requires `digits` and `period` integers — keep `period: 30` stored for HOTP entries (shape stays valid; period is meaningless for HOTP but harmless).
- `parseOtpAuthUri` rejects at `lib/otp.js:162` (host ≠ totp) and `:167` (algorithm ≠ SHA1) — both gates extend, not replace. Per research §5: `counter` defaults 0 when absent, reject negatives and > Number.MAX_SAFE_INTEGER; `period` ignored silently for HOTP; unknown query params ignored; digits ∉ {6,8} rejects.
- Counter semantics (research §3): increment the PERSISTED counter once per reveal and once per copy; never on list render or timer; never decrement; survives restart. Counter goes through the same encrypted vault persistence as secrets.
- RFC 6238 tests need THREE distinct seeds — ASCII "1234567890..." extended to 20B (SHA-1), 32B (SHA-256), 64B (SHA-512). The SHA-256/512 columns are NOT reproducible with a 20-byte secret. T = 20000000000 exceeds 32-bit — JS Number math (existing) is correct; do not use int32.
- Code standards "Adding New Entry Fields" mandate a storage-key version bump + migration: plaintext entries key `personal_otp_vault_entries_v2` (`app.js:467`) → `_v3` with read-old/write-new migration; extension `otp_extension_entries_v2` → `_v3`. Encrypted envelope key stays `_v1` (envelope format is self-describing JSON + additive kdf field from Phase 1; legacy fallback keeps old envelopes readable).
- v2 RETENTION (red-team): v2 is NEVER removed in this phase — it stays as a read-only fallback indefinitely. Load path: read v3, else v2, merge newer-wins. Removing v2 while stale tabs/older bundles may still write to it risks deleted-vault resurrection and divergent data. Every STORAGE_KEY touchpoint must handle BOTH keys during the migration window — web `app.js:467, 751, 761, 765, 771, 773, 782, 1205`; extension `popup.js:21, 86, 99, 434, 436, 445, 447, 461, 472, 652` (clear-on-reset, snapshot-restore, encrypt-switch operations included).
- Service worker rollout: the web app is served cache-first (`sw.js:50-62`); a release that changes `app.bundle.js` MUST bump `CACHE_NAME` (`sw.js:1`) or already-installed shells keep serving the stale bundle. Existing `skipWaiting`/`clients.claim` do not reload already-open tabs (no page-side `controllerchange` reload exists), so a stale-tab window is real — destructive storage-key removal is forbidden while stale tabs may write (reinforces v2 retention).
- Render loop hazard: `generateTotp` production callers `app.js:1150` and `popup.js:405` run every second inside the render loop. HOTP entries entering that loop would display rolling TOTP-style codes unless the branch is explicit (FR8).
- Counter regression hazard: when a counter-increment persist fails, `replaceEntries` rollback (`app.js:1224-1229`) silently restores the persisted counter while the user already holds the consumed code — the code and stored counter diverge with no repair affordance (FR9).
- Forward-compat degradation, accepted: a new backup imported into an old app version silently drops type/counter/algorithm (old `normalizeEntry` copies only known fields) — HOTP entry degrades to TOTP. Document in Phase 8.
- GitNexus scout impact: `generateTotp` upstream 5 (LOW), `parseOtpAuthUri` upstream 6 (LOW).

<!-- Updated: Red Team Review Session 1 - v2 key retention + full STORAGE_KEY touchpoint enumeration, CACHE_NAME bump rule with stale-bundle window, render-loop and counter-regression hazards -->

## Requirements

### Functional
- FR1: Entry model: optional `type` (default 'totp'), `counter` (integer >= 0, HOTP only, default 0), `algorithm` (default 'SHA1') — normalized in `normalizeEntry`, persisted, and preserved by backup export/import.
- FR2: `generateHotp(secret, counter, digits, algorithm, cryptoApi)` exported; `generateTotp(secret, digits, period, now, algorithm, cryptoApi)` delegates to a shared internal truncation path.
- FR3: `parseOtpAuthUri` accepts `otpauth://hotp/...?counter=N` (default 0) and `algorithm=SHA256|SHA512`; `period` ignored for HOTP; MD5 still rejected (`URI_ALGORITHM`); HOTP+SHA256/512 supported as a documented non-RFC extension.
- FR4: HOTP UI: entry card shows current code + counter badge; generating (reveal) increments the persisted counter; copy increments again. Manual-add form gains type/counter/algorithm fields (web + popup).
- FR5: TOTP entries with SHA-256/512 show an algorithm badge on the card (per brainstorm F3).
- FR6: Plaintext storage migration entries_v2 → v3 on both platforms (read v2 when v3 absent, normalize, write v3). **v2 is retained as a read-only fallback indefinitely — never deleted in this phase.** Load: read v3, else v2, merge newer-wins. ALL STORAGE_KEY touchpoints handle BOTH keys during the migration window (clear-on-reset, snapshot-restore, encrypt-switch): web `app.js:467, 751, 761, 765, 771, 773, 782, 1205`; extension `popup.js:21, 86, 99, 434, 436, 445, 447, 461, 472, 652`.
- FR7: Extension parity for all UI deltas.
- FR8: Render-loop branch: the 1s render loop (`generateTotp` at `app.js:1150`, `popup.js:405`) gains an explicit type branch — TOTP → timed regeneration as today; HOTP → render the cached code for the persisted counter, regenerate only on reveal/copy. Without this, HOTP cards display rolling TOTP codes.
- FR9: Counter regression repair: a visible toast fires when a counter-increment persist fails (today the `replaceEntries` rollback at `app.js:1224-1229` silently restores the counter while the user holds the consumed code); HOTP cards gain a "counter out of sync — set counter" edit affordance (the edit dialog already exists) so users can re-sync manually.

<!-- Updated: Red Team Review Session 1 - FR6 rewritten for v2 retention + touchpoint enumeration; new FR8 render-loop branch, FR9 counter regression repair -->

### Non-functional
- NFR1: lib/ stays dependency-free, Web Crypto only, Node-testable (docs/code-standards.md).
- NFR2: TOTP time math stays in Number space (correct past 2038; never int32).
- NFR3: One shared truncation helper — no duplicated dynamic-truncation code (DRY).

## Architecture

**Engine layering (lib/otp.js):** `hmac(keyBytes, msgBytes, hash, cryptoApi)` (renamed/parameterized seam) → `hotpDigest(secretBytes, counter, digits, hash, cryptoApi)` internal (8-byte BE counter encode + dynamic truncation + mod 10^digits) → `generateHotp` (exported, counter input) and `generateTotp` (exported, computes `counter = floor(now/period)` then delegates).

**Data flow (HOTP reveal/copy):** UI action → `generateHotp(entry.secret, entry.counter, ...)` → display/copy → `entry.counter += 1` → `persistEntries()` (encrypted path if enabled) → re-render counter badge.

**Backup compat:** old backup (no type fields) → `normalizeEntries` fills defaults → works. New backup → optional fields pass `hasRequiredBackupEntryShape` untouched (it checks only the original required set).

## Related Code Files

- Modify: `D:\2fa\lib\otp.js` — seam parameterization, `hotpDigest`/`generateHotp`, `normalizeEntry` fields, `parseOtpAuthUri` type/counter/algorithm, `ensureCounter` helper.
- Modify: `D:\2fa\lib\vault.js` — nothing structural; verify `hasRequiredBackupEntryShape` still passes (test-only confirmation).
- Modify: `D:\2fa\app.js` — entries_v3 migration, add-form fields, card badges, counter increment in reveal/copy flow (`app.js:988-1007` copy path).
- Modify: `D:\2fa\extension\popup.js` + `popup.html` — same parity (copy flow, badges, form, entries_v3 migration).
- Modify: `D:\2fa\tests\unit\otp.test.js` — RFC 4226 vectors, RFC 6238 3-seed vectors, parse cases, normalizeEntry defaults.
- Create: none.

## Implementation Steps

1. GitNexus `impact({target: "generateTotp"})`, `impact({target: "parseOtpAuthUri"})`, `impact({target: "normalizeEntry"})` (all with `file_path` hint at `lib/otp.js`).
2. Refactor `lib/otp.js`: rename `hmacSha1` → `hmac(keyBytes, messageBytes, hash, cryptoApi)`; extract internal `hotpDigest(secretBytes, counter, digits, hash, cryptoApi)`; rewire `generateTotp`; add exported `generateHotp`. Existing SHA-1 TOTP behavior must be byte-identical (existing tests prove it).
3. Extend `normalizeEntry` with `type` (whitelist totp/hotp, default totp), `counter` (non-negative safe integer, default 0, forced 0 for totp), `algorithm` (whitelist SHA1/SHA256/SHA512, default SHA1). Add `ensureCounter` + `ensureAlgorithm` validators near `ensureDigits`/`ensurePeriod`.
4. Extend `parseOtpAuthUri`: host totp|hotp (case-insensitive); read `counter` for HOTP (default 0, reject invalid); ignore `period` for HOTP; accept SHA256/512 in the algorithm gate; update error copy at `lib/otp.js:162/167`.
5. Storage migration with v2 RETENTION: web — entries_v2 → v3 in the load path (`app.js:467` key block); extension — `otp_extension_entries_v2` → v3 in `extension/popup.js` load path. Migration = normalize-through-lib, never hand-rolled field copying. Load reads v3 first, falls back to v2, merges newer-wins; v2 is never deleted this phase. Audit EVERY touchpoint from the Key Insights list (web `app.js:467, 751, 761, 765, 771, 773, 782, 1205`; extension `popup.js:21, 86, 99, 434, 436, 445, 447, 461, 472, 652`) and make clear-vault, snapshot-restore, and encrypt-switch operations handle BOTH keys — a v2-only clear would resurrect deleted entries from v2.
6. Service worker release rule: bump `CACHE_NAME` (`sw.js:1`) in this and every future release that changes `app.bundle.js` (cache-first serving at `sw.js:50-62`; already-open tabs keep the stale bundle — no page-side `controllerchange` reload). While stale tabs may still be open and writing, destructive plaintext-key removal is forbidden (reinforces FR6). Add the CACHE_NAME bump to the per-release checklist consumed by Phase 8.
7. UI (web): add-form gains type select, counter input (HOTP only, shown/hidden), algorithm select; card badge for algorithm; HOTP counter badge; increment-on-reveal and increment-on-copy wiring in the copy flow (`app.js:988-1007`); persist after each increment; explicit TOTP/HOTP branch in the render loop (`app.js:1150` — HOTP renders the cached code for the persisted counter, FR8); visible toast on counter-persist failure + "counter out of sync — set counter" edit affordance on HOTP cards (FR9).
8. UI (extension): mirror step 7 in `popup.js`/`popup.html` (render-loop branch at `popup.js:405` included).
9. Tests in `tests/unit/otp.test.js`:
   - RFC 4226 Appendix D: secret ASCII "12345678901234567890", counters 0-9 → `755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489`.
   - RFC 6238 Appendix B (8-digit, X=30, T0=0), three seeds 20B/32B/64B: T=59 → `94287082 / 46119246 / 90693936`; T=1111111109 → `07081804 / 68084774 / 25091201`; T=1111111111 → `14050471 / 67062674 / 99943326`; T=1234567890 → `89005924 / 91819424 / 93441116`; T=2000000000 → `69279037 / 90698825 / 38618901`; T=20000000000 → `65353130 / 77737706 / 47863826`.
   - parseOtpAuthUri: hotp with/without counter; counter=-1 and counter>MAX_SAFE_INTEGER reject; SHA256/SHA512 TOTP parse; MD5 rejects; period ignored for hotp; digits=7 rejects.
   - normalizeEntry defaults for legacy entries missing all three fields; round-trip through backup export/import preserves type/counter/algorithm.
10. `detect_changes()` sweep. Commits: `feat: add hotp support to otp engine`, `feat: support sha-256 and sha-512 totp`, `feat: hotp and algorithm ui in web app and extension`, `feat: migrate entries storage to v3 with v2 fallback retained`, `chore: bump service worker cache name`.

<!-- Updated: Red Team Review Session 1 - renumbered steps, v2-retention migration, CACHE_NAME bump step, render-branch + counter-repair wiring -->

## Todo

- [x] impact() on generateTotp / parseOtpAuthUri / normalizeEntry
- [x] hmac seam parameterized; hotpDigest shared; generateHotp exported
- [x] normalizeEntry + validators for type/counter/algorithm
- [x] parseOtpAuthUri hotp + SHA-256/512 + counter rules
- [x] entries_v2 → v3 migration (web + extension); BOTH keys handled at every touchpoint; v2 retained as read-only fallback
- [x] CACHE_NAME bumped in sw.js (and added to per-release checklist)
- [x] Web UI: form fields, badges, counter increment on reveal/copy, TOTP/HOTP render-loop branch
- [x] Counter persist-failure toast + "counter out of sync" edit affordance
- [x] Extension UI parity
- [x] RFC 4226 + RFC 6238 vector tests green; backup round-trip test
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.3` (with Phase 4)

<!-- Updated: Red Team Review Session 1 - todos: both-key touchpoints, v2 retention, CACHE_NAME bump, render branch, counter repair -->

## Success Criteria

- [x] `npx vitest run tests/unit/otp.test.js` green including all 10 RFC 4226 vectors and all 18 RFC 6238 values (6 T values x 3 hashes).
- [x] `npm run test:unit` green; `npm run build` green.
- [x] `npx playwright test tests/e2e/app.spec.js` and `npx playwright test tests/e2e/extension.spec.js` green (existing TOTP flows unchanged).
- [x] Manual smoke: add HOTP entry via otpauth URI, reveal twice → counter advanced by 2, persisted across reload; SHA-256 TOTP entry generates RFC-matching code.
- [x] v2 storage data auto-migrates to v3 on first load; v2 remains on disk untouched (read-only fallback verified).

<!-- Updated: Red Team Review Session 1 - success criterion: v2 retained, not removed -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Refactor of generateTotp changes existing codes | L x H | Existing TOTP tests are the regression net; run them after every seam change |
| Stale bundle served after release (cache-first SW, already-open tabs) | M x M | CACHE_NAME bumped every bundle-changing release; no destructive key removal while stale tabs may write |
| HOTP cards render rolling TOTP codes in the 1s loop | H x L (if missed) | FR8 explicit type branch at both `generateTotp` call sites (`app.js:1150`, `popup.js:405`); manual HOTP smoke |
| Counter increment races (double-click copy) | M x L | Idempotent per-action guard; worst case counter +1 extra — server-side look-ahead windows tolerate drift (research §3); FR9 toast + re-sync affordance covers persist failures |
| Both-key mishandling resurrects deleted entries (clear touches only one key) | M x H | FR6 touchpoint enumeration (web 8 sites, extension 11 sites) audited one-by-one; v2 retained so no data loss either way |
| Old app versions degrade HOTP entries to TOTP silently | H x M | Accepted + documented (Phase 8 release notes); backups retain the fields |

<!-- Updated: Red Team Review Session 1 - risks: stale bundle, HOTP render branch, both-key mishandling rows; counter race mitigation extended -->

## Security Considerations

- Counter is non-secret but must persist through the encrypted path (it leaks usage count otherwise).
- MD5 rejection stays fail-closed; unknown algorithms never silently accepted.
- HOTP+SHA256/512 flagged in code comments as non-RFC extension (research §5).

## Next Steps

- Phase 4 consumes type/counter/algorithm for GA migration import.

## Rollback Plan

- Revert commits; entries_v3 key is additive and v2 is never deleted, so restored old code always keeps working from v2 (no window where v2 was removed). Encrypted vaults unaffected.

<!-- Updated: Red Team Review Session 1 - rollback: v2 permanently retained, simplifies recovery claim -->
