---
title: "Phase 2: Session & Shell Hardening — CSP, jsQR, Auto-Lock, Throttling"
description: "Vendor jsQR off the CDN, add CSP, idle auto-lock, unlock backoff, optional clipboardRead permission, and crypto-random entry IDs — web and extension."
status: todo
priority: P1
estimate: 10h
release: 0.1.2
---

# Phase 2: Session & Shell Hardening — CSP, jsQR, Auto-Lock, Throttling

## Context Links

- Research: `plans/2026-10-07-improvement-ideas-research.md` H1, H3, H4, H6, H8
- Scout evidence: `reports/scout-report.md` sections 1, 4, 5
- Depends on: Phase 1 (de-duped app.js imports lib; unlock path carries legacy-upgrade)
- Parent plan: `plan.md`

## Overview

- **Priority:** P1 (closes the supply-chain and session-lifetime holes)
- **Status:** todo
- **Description:** Remove the unsandboxed CDN script (`index.html:467`, jsQR 1.4.0 without SRI) by bundling `jsqr` from npm through esbuild; add a Content-Security-Policy meta to `index.html`; implement idle auto-lock (default 15 min, settings 5/15/30/off) that clears `currentPassphrase` on both platforms — unified with the EXISTING manual "Lock Vault" button into one `lockVault()` path; add exponential-backoff throttling on failed unlocks; move `clipboardRead` to `optional_permissions` requested at first clipboard-import use; switch entry IDs to `crypto.getRandomValues`; cache the passphrase/DEK in `chrome.storage.session` (DECIDED: adopt — Validation Session 2) so a popup open does not pay the 600k KDF every time.

<!-- Updated: Red Team Review Session 1 - overview: lock unification with existing manual Lock Vault button, extension KDF-cost decision added -->

## Key Insights

- jsQR is referenced only by the web app: `window.jsQR` at `app.js:1383, 1394, 1671, 1676` (clipboard-image decode + camera loop). `extension/popup.js` never calls it — extension keeps zero new deps.
- CSP safety: app code assigns handlers via JS properties (`removeBtn.onclick`, `app.js:1051`) and clones `<template>` nodes with `textContent` — property assignment and programmatic handlers are CSP-safe; only inline HTML `onclick=` attributes and inline `<style>`/`style=` attributes would break. Audit `index.html` for inline styles before pinning `style-src`.
- No IDLE/THROTTLE logic exists anywhere (scout grep: 0 hits) — but a MANUAL lock DOES: a "Lock Vault" button (`index.html:35`, `id="lock-app"`) with handler at `app.js:1951-1959` calling `setLocked` (`app.js:737-738`). It clears `entries` and re-renders but does NOT clear `currentPassphrase` (declared `app.js:583`, never nulled on lock) — a latent bug this phase fixes by unifying both paths into one `lockVault()` (FR3). `currentPassphrase` is a plain module var in `app.js` and `extension/popup.js:79`. Closing the extension popup already destroys its JS context — popup auto-lock only matters while the popup stays open.
- CSP vs QR-URL import conflict: the existing QR-URL import feature fetches arbitrary user-supplied hosts (`app.js:1777-1792` fetch of pasted URLs; UI wiring at `index.html:135-136`), which `connect-src 'self'` would kill. Decision (locked): use `connect-src 'self' https:` to KEEP the feature, with the trade-off documented in the changelog and covered by a new e2e (see FR2). Meta CSP cannot deliver framing protection — `frame-ancestors` is IGNORED inside `<meta>` per CSP3; host-header framing protection (X-Frame-Options/CSP header) is documented for hosting in Phase 8 instead.
- Extension KDF cost: the popup re-locks on every open (`extension/popup.js:91-101` runs `setLocked(true)` when an encrypted vault exists), so each popup open pays the full 600k PBKDF2 (~300-600ms). Decision gate (FR7): evaluate caching the passphrase/DEK in `chrome.storage.session` (MV3 service worker, memory-only, cleared on browser exit) vs re-deriving per open — DECIDED: ADOPT (Validation Session 2; Chrome storage docs recommend `storage.session` for sensitive session data; Bitwarden caches unlock state the same way).

<!-- Updated: Red Team Review Session 1 - corrected "no lock logic" claim (manual Lock Vault exists, app.js:1951-1959), CSP connect-src vs QR-URL import decision, meta frame-ancestors ignored, extension KDF cost decision gate -->
- `tick()` (`app.js:1171-1176`) runs every second and already skips work while the unlock panel is visible — natural hook point for the idle check (web). Popup needs its own timer.
- Settings render lives at `app.js:622-643`; settings persisted under `personal_otp_vault_settings_v3` (`app.js:468`) / `otp_extension_settings_v1` (`extension/popup.js:19`). New fields ride these objects — no key migration needed (absent field = default 15).
- Clipboard import reads `navigator.clipboard.readText()` at `app.js:1805` (web needs no permission beyond user gesture) and `extension/popup.js:564` (needs `clipboardRead`). MV3 `optional_permissions` + `chrome.permissions.request({permissions: ["clipboardRead"]})` inside the import click handler satisfies the user-gesture requirement.
- `generateEntryId` (`lib/otp.js:36-38`) uses `Math.random()`; IDs are not secret but `crypto.getRandomValues` removes the security-review smell. `globalThis.crypto.getRandomValues` exists in Node 18+, so unit tests stay mock-free.

## Requirements

### Functional
- FR1: `index.html` loads zero third-party origins: jsQR imported in `app.js` (`import jsQR from "jsqr"`), CDN `<script>` deleted.
- FR2: CSP meta in `index.html`: `default-src 'self'; script-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self' https:; base-uri 'none'; form-action 'none'` (final directive list after inline-style audit; `style-src` per audit findings). `connect-src 'self' https:` is a locked decision that keeps the QR-URL import feature (it fetches arbitrary user-supplied hosts, `app.js:1777-1792`); the relaxed-origin trade-off gets a changelog note and a dedicated e2e. `frame-ancestors 'none'` is deliberately OMITTED — it is ignored inside a meta CSP (CSP3); framing protection moves to hosting headers documented in Phase 8.
- FR3: Auto-lock: setting `autoLockMinutes` ∈ {5, 15, 30, 0=off}, default 15, exposed in Settings UI on both platforms. On idle expiry: clear `currentPassphrase`, clear in-memory sensitive UI state, show the unlock panel, cancel timers. The idle path and the EXISTING manual "Lock Vault" button (`app.js:1951-1959`) unify into ONE `lockVault()` per platform that clears passphrase + undo/delete buffers + camera preview — the manual button currently leaves `currentPassphrase` in memory (`app.js:583`), which this fixes.
- FR4: Unlock throttling: after 3 consecutive failed unlocks, backoff starts at 1s and doubles per failure, capped at 60s; counter and `lockedUntil` persist in new keys `personal_otp_vault_unlock_guard_v1` / `otp_extension_unlock_guard_v1`; reset on success; unlock button disabled with countdown while backing off.
- FR5: Extension: `clipboardRead` moves from `permissions` to `optional_permissions` in `extension/manifest.json`; `chrome.permissions.request()` fires on first clipboard-import click; graceful failure message if denied.
- FR6: `generateEntryId()` uses `crypto.getRandomValues` with ≥6 random bytes (e.g. `new Uint8Array(6)` rendered as base36/hex) — NOT a single Uint16 (65k space is collision-prone; IDs collide → the delete-by-id filter at `app.js:1058` would delete multiple entries at once). Format stays `entry_<base36 time>_<random>` so sortability and dedupe logic are unchanged; collision test mints 10k IDs and asserts uniqueness.
- FR7: Extension session cache (DECIDED: ADOPT — Validation Session 2, 2026-10-07): cache the unlocked passphrase/DEK in `chrome.storage.session` (MV3 in-memory storage, never written to disk, cleared on browser close/update; Chrome docs recommend it for sensitive session data — Bitwarden ships this exact pattern). Implementation: the session key holds the passphrase (pre-Phase 6) or DEK (post-Phase 6) while unlocked; `lockVault()` clears it; `chrome.alarms` + `chrome.idle` enforce auto-lock by clearing the session key even with the popup closed; default access level only (never call `setAccessLevel`). Consequence: a popup open no longer pays the 600k KDF (`popup.js:91-101` re-locks per open), and Phase 6 reuses the same mechanism for its DEK cache.

<!-- Updated: Red Team Review Session 1 - FR2 CSP (connect-src https:, frame-ancestors dropped), FR3 lock unification, FR6 >=6 random bytes + collision test, new FR7 session-cache decision -->

### Non-functional
- NFR1: `jsqr` is a build-time dependency only (bundled by esbuild); no runtime network fetch remains in the web app — offline camera scan works.
- NFR2: Auto-lock timers must not fire while an unlock ceremony or save is in flight (defer lock until the operation settles).
- NFR3: Both platforms get identical setting labels/values (extension parity).

## Architecture

**Auto-lock flow:** user activity (`pointermove`/`keydown` throttled to 1/s) resets `lastActivity`; `visibilitychange` handles HIDE/SHOW asymmetrically — on `hidden`, freeze `lastActivity` (or lock outright after a short grace period on mobile where timers throttle); NEVER reset the idle timer on `visible` (that would make auto-lock ineffective exactly when the app is backgrounded on mobile). Every `tick()` (web) or 1s interval (popup) compares `Date.now() - lastActivity` vs `autoLockMinutes * 60_000`; on expiry → `lockVault()`: the single shared lock function per platform (also wired to the existing manual "Lock Vault" button, `app.js:1951-1959`) that clears passphrase, clears undo/delete buffers and copy history if `clearClipboard` setting is on, re-renders locked UI, cancels camera preview if running.

<!-- Updated: Red Team Review Session 1 - visibilitychange direction fixed (freeze on hidden, never reset on visible), lockVault unified with manual button -->

**Throttle flow:** unlock submit → if `guard.lockedUntil > now`, reject with countdown; on decrypt failure → `attempts+1`, compute backoff, persist guard; on success → clear guard. Guard key lives in platform storage (localStorage / chrome.storage.local), so reload does not reset backoff.

**jsQR flow:** camera/clipboard decode paths call the imported `jsQR(imageData.data, width, height, {inversionAttempts: "attemptBoth"})` — same signature as the global it replaces.

## Related Code Files

- Modify: `D:\2fa\index.html` — remove CDN script (line 467), add CSP meta, audit inline styles.
- Modify: `D:\2fa\app.js` — jsQR import + 4 call sites, auto-lock timer + settings UI, unlock throttle, activity listeners.
- Modify: `D:\2fa\lib\otp.js` — `generateEntryId` crypto randomness.
- Modify: `D:\2fa\extension\manifest.json` — permissions split, version 0.1.2 (via release script).
- Modify: `D:\2fa\extension\popup.js` + `D:\2fa\extension\popup.html` — auto-lock timer, throttle, permission request at `popup.js:564`.
- Modify: `D:\2fa\package.json` — add `jsqr` dependency (via `npm i jsqr`).
- Modify: `D:\2fa\tests\unit\otp.test.js` — entry ID format/randomness test.
- Create: `D:\2fa\tests\e2e\autolock.spec.js` — web auto-lock + throttle e2e (short lock setting; Playwright clock manipulation where supported).

## Implementation Steps

1. GitNexus `impact({target: "generateEntryId", direction: "upstream"})`. Patch `lib/otp.js:36-38` to draw ≥6 random bytes via `crypto.getRandomValues(new Uint8Array(6))` rendered base36/hex — NOT a single `Uint16Array(1)` (65k space; a colliding id makes the delete-by-id filter at `app.js:1058` delete multiple entries). Unit test: ID matches `/^entry_[0-9a-z]+_[0-9a-z]+$/`, two consecutive calls differ, and a 10k-ID mint loop finds zero collisions.
2. `npm i jsqr`; in `app.js` add `import jsQR from "jsqr"`; replace the four `window.jsQR` sites (`app.js:1383, 1394, 1671, 1676`); delete the CDN `<script>` at `index.html:467`. Run `npm run build`; `npx playwright test tests/e2e/app.spec.js` (QR/clipboard import flows must stay green).
3. Audit `index.html` for inline styles/handlers (`grep -n 'style=\|onclick=' index.html`); add the CSP meta to `<head>` with `connect-src 'self' https:` (locked decision: keeps QR-URL import, which fetches arbitrary hosts at `app.js:1777-1792` / `index.html:135-136`) and WITHOUT `frame-ancestors` (ignored in meta CSP); write the trade-off into the changelog/release notes (Phase 8 carries the note); add an e2e case covering QR-URL import (fetch a routed URL end-to-end) so the relaxed directive is actually exercised by the suite; re-run full e2e — CSP violations surface as console errors caught by Playwright.
4. Auto-lock (web): add `autoLockMinutes` to settings defaults + `<select>` in the settings block (`app.js:622-643` render area); add activity listeners (`pointermove`/`keydown`; `visibilitychange` freezes `lastActivity` on `hidden`, NEVER resets it on `visible`) and the `lockVault()` path hooked into `tick()`. Implement `lockVault()` as the single lock path and rewire the existing manual "Lock Vault" handler (`app.js:1951-1959`) through it so `currentPassphrase` (`app.js:583`), undo buffers, and camera preview are always cleared. Respect NFR2 (defer during in-flight save/unlock).
5. Auto-lock (extension): same setting + timer in `extension/popup.js`/`popup.html`; UI copy notes that closing the popup always locks.
6. Extension session cache (DECIDED: adopt — Validation Session 2): implement the `chrome.storage.session` passphrase/DEK cache — write on unlock, invalidate on `lockVault()`/passphrase change/biometric state change, default access level only. Extend auto-lock to clear the session key via `chrome.alarms` + `chrome.idle` so an idle browser locks even without the popup open (pattern per Chrome docs + Bitwarden). Phase 6 reuses this mechanism for its DEK cache.
7. Throttle: new guard helpers in `app.js` and `extension/popup.js` writing `*_unlock_guard_v1`; wire into both unlock submit handlers; add countdown on the unlock button.
8. Extension clipboard permission: move `clipboardRead` to `optional_permissions` in `manifest.json`; at `popup.js:564` wrap import with `chrome.permissions.request`; handle `false` result with an explanatory message.
9. Tests: unit for entry ID (format + 10k collision mint); `tests/e2e/autolock.spec.js` covering (a) lock after idle with short setting, (b) backoff countdown after 3 bad passphrases, (c) successful unlock clears guard, (d) `visibilitychange` → `hidden` then expiry locks (timer not reset by returning visible), (e) manual "Lock Vault" click → unlock panel shows AND a subsequent correct-passphrase unlock is still required (proves `currentPassphrase` was cleared). Extension side: extend `tests/e2e/extension.spec.js` with throttle + clipboard-permission denial path.
10. `detect_changes()` sweep. Commits: `feat: vendor jsqr and add csp`, `feat: add idle auto-lock`, `feat: unify lock vault path and clear passphrase`, `feat: throttle unlock attempts`, `feat: request clipboardread permission on demand`, `feat: use crypto random entry ids`.

<!-- Updated: Red Team Review Session 1 - steps: >=6-byte IDs + collision test, CSP connect-src decision + QR-URL e2e, lockVault unification, session-cache decision step, visibilitychange/manual-lock e2e cases -->

## Todo

- [x] Entry ID crypto randomness (≥6 bytes) + 10k collision unit test
- [x] jsqr vendored, CDN script removed, 4 call sites migrated
- [x] CSP meta added (`connect-src 'self' https:`, no frame-ancestors), inline-style audit done, QR-URL import e2e green under CSP, changelog note written
- [x] Web auto-lock (setting, timer, lockVault) + e2e
- [x] lockVault() unified with manual "Lock Vault" button; passphrase cleared (e2e proves re-unlock required)
- [x] Extension auto-lock parity
- [x] chrome.storage.session cache implemented: write-on-unlock, lockVault invalidation, alarm/idle-based clearing (DECIDED: adopt)
- [x] Unlock throttling both platforms + guard storage keys
- [x] clipboardRead → optional_permissions + on-demand request
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.2` (with Phase 1)

<!-- Updated: Red Team Review Session 1 - todos: lock unification, session-cache decision, collision test, CSP trade-off note -->

## Success Criteria

- [x] Built app makes zero third-party script/style/origin loads (grep `https://` in `index.html` returns no CDN URLs).
- [x] `npx vitest run tests/unit/otp.test.js` green (10k-ID collision mint included); `npm run test:unit` green.
- [x] `npx playwright test tests/e2e/app.spec.js`, `npx playwright test tests/e2e/autolock.spec.js`, `npx playwright test tests/e2e/extension.spec.js` all green — including the QR-URL import case and the manual-lock-passphrase-cleared case.
- [x] Manual smoke: vault locks after idle in both platforms; failed unlocks show visible countdown; hidden-tab expiry locks on return.
- [x] chrome.storage.session cache implemented — a popup open with a live session key performs NO KDF derivation (verified by timing/manual check); the key is cleared by lockVault, the idle alarm, and browser exit.
- [x] `npm run release:prepare -- 0.1.2` passes `npm run verify:version`.

<!-- Updated: Red Team Review Session 1 - success criteria: collision test, QR-URL + manual-lock e2e, decision record -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| CSP breaks camera (gUM) or blob image flows | M x H | gUM is not CSP-gated; `blob:` in img-src/media-src covers preview + decoded frames; full e2e + manual camera smoke before release |
| `connect-src 'self' https:` keeps a broad fetch surface (any https host reachable from app context) | M x M | Locked trade-off to preserve QR-URL import (feature predates CSP); documented in changelog; dedicated e2e keeps the feature honest; script/img origins stay locked to 'self' |
| Manual lock path left un-unified → passphrase survives "Lock Vault" | (pre-existing) H | Fixed by FR3 unification; e2e asserts unlock panel requires the passphrase again after manual lock |
| Auto-lock fires mid-save corrupting state | L x H | NFR2 defer rule; `persistEntries` already snapshots/rolls back (`app.js:1193-1214`) |
| Client-side throttle false-locks a legit user who forgot the passphrase | M x M | Cap backoff at 60s; KDF (Phase 1) is the real defense — UI copy explains it |
| jsqr npm package API differs from CDN global | L x M | Same package/version (1.4.0); identical signature; e2e covers decode paths |

<!-- Updated: Red Team Review Session 1 - risk table: connect-src trade-off and manual-lock unification rows added -->

## Security Considerations

- CSP eliminates remote script injection risk; SRI becomes moot once nothing is remote. `connect-src 'self' https:` is the one deliberate relaxation (QR-URL import) — scripts, images, and frames stay locked down; framing protection is a hosting-header concern (Phase 8), not deliverable via meta CSP.
- Throttle is defense-in-depth only — honest limitation vs. devtools-savvy local attacker; KDF remains primary.
- `clipboardRead` on demand shrinks install-time permission warnings.
- Auto-lock bounds plaintext-passphrase lifetime in memory.

## Next Steps

- Phase 3 extends `lib/otp.js` (same file as FR6 edit — sequential phases, no file conflict).

## Rollback Plan

- Revert commits; guard storage keys are additive and inert on old code. Removing CSP/jsQR import restores prior behavior; no data format changes in this phase.
