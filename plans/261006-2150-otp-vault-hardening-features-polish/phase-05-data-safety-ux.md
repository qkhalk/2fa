---
title: "Phase 5: Data-Safety UX — Undo Delete, Backup Reminder, Time Drift"
description: "Undo-delete toast (10s), backup staleness reminder (>30 days via lastBackupAt), and opt-in time-skew check — web and extension."
status: todo
priority: P2
estimate: 8h
release: 0.1.4
---

# Phase 5: Data-Safety UX — Undo Delete, Backup Reminder, Time Drift

## Context Links

- Research: `plans/2026-10-07-improvement-ideas-research.md` F5, F6, F8
- Scout evidence: `reports/scout-report.md` sections 1, 4
- Depends on: Phases 1-4 (entry model settled; undo hooks the existing mutation flow)
- Parent plan: `plan.md`

## Overview

- **Priority:** P2
- **Status:** todo
- **Description:** Protect users from the two real data-loss paths of a local vault — accidental deletion and never-made backups — plus wrong TOTP codes from a drifted clock: a 10-second Undo toast after deletion (with a storage-backed tombstone so Undo survives popup close/reload), a "last export > 30 days" reminder driven by a persisted `lastBackupAt` timestamp (stamped honestly: download success is not verifiable, so the stamp reflects export completion + envelope hash), an extension backup-export feature (today the extension has NO export at all — required for the reminder to be actionable), and an opt-in time-drift check comparing device time against a server Date.

<!-- Updated: Red Team Review Session 1 - description: honest lastBackupAt semantics, extension export deliverable, undo tombstone -->

## Key Insights

- Single-delete is inline in `removeBtn.onclick` (`app.js:1051-1066`): confirm dialog → `entries.filter(...)` → `replaceEntries(nextEntries)`. Undo = capture the removed entry + its index before filter; on Undo, re-insert at the original index via `replaceEntries`. There is no separate `removeEntry` function — the hook point is this handler and the bulk-delete path in the bulk bar.
- Extension mirror: `showRemoveConfirmation` (`extension/popup.js:298`) + its delete handler + `replaceEntries` (`extension/popup.js:484`).
- Undo tombstone (red-team): closing the extension popup destroys its JS context, so an in-memory undo buffer dies with the toast — the user can close the popup and lose the undo. Mitigation: a pending-purge tombstone — the deleted entry (+index) is held in a storage key with a timestamp and auto-purged after 10 minutes; extension Undo reads the tombstone on next open; web keeps the in-memory toast AND writes the same tombstone so undo also survives an accidental reload. Tombstone rides the vault's own persistence helpers (encrypted when encryption is on).
- Backup export reality (red-team): `downloadJson` (`app.js:1501-1509`) is fire-and-forget — a blocked or cancelled download is indistinguishable from success, so "stamped on download" overstates what we know. Honest mechanism: stamp `lastBackupAt` when the export ENVELOPE is built (completion of `createEncryptedBackup`/`createPlainBackup`) and store the exported envelope's hash; UI wording becomes "Last export" (+ hash suffix for verification); the limitation (we cannot confirm the file landed on disk; verify-on-import is out of scope) is documented in this phase and Phase 8. Extension has NO backup export at all (grep `popup.js`/`popup.html` for export/backup/download = 0 hits) — export is a real deliverable of this phase (user-locked decision: full parity), else the reminder is unactionable on extension.
- Reminder rule (KISS): warn when `Date.now() - lastBackupAt > 30d`; when `lastBackupAt` is absent AND the vault holds ≥1 entry, warn too (data at risk from day 31 at the latest). Reminder surfaces as a dismissible banner on the entries view + "Last export: N days ago" line in Settings. Per-session dismissal only (a permanently dismissed state would defeat the purpose).
- Time-drift CORS reality check: `Date` is NOT a CORS-safelisted response header — cross-origin readers need `Access-Control-Expose-Headers`. Therefore: web app checks by HEAD-requesting its OWN origin (`location.href`, `cache: "no-store"`) — same-origin `Date` is readable and reflects the serving CDN/host clock; extension popup has no HTTP origin, so it must call a remote time endpoint: `https://www.cloudflare.com/cdn-cgi/trace` (parse `ts=` unix seconds; NOTE the `www.` apex — the apex host redirects). Red-team live-check observed `Access-Control-Allow-Origin: *` on the trace GET; live re-verification remains an implementation step. `host_permissions` in the manifest change ONLY if the live check fails — the named fallback is `optional_host_permissions: ["https://www.cloudflare.com/cdn-cgi/trace"]` + `chrome.permissions.request()` in the "Check now" handler.
- TOTP codes fail server-side when device skew > ~30s window edges; 5s warning threshold (locked decision) gives lead time. Skew display only — never touch device clock.
- Drift check is opt-in (default off), runs at app load and via a "Check now" button; network errors are silent-success (skip check), per local-first respect.

<!-- Updated: Red Team Review Session 1 - honest lastBackupAt (fire-and-forget downloadJson, envelope hash, "Last export"), extension export deliverable, undo tombstone, corrected trace endpoint + CORS live-check notes + optional_host_permissions fallback -->

## Requirements

### Functional
- FR1: Undo delete: after single or bulk delete, toast "Entry removed — Undo" visible ~10s; Undo restores entry/entries at original position(s); toast expires → deletion final; new deletion during an active toast replaces the pending one (single undo buffer). Deleted payloads are ALSO written to a pending-purge tombstone key (entry + index + timestamp; auto-purged after 10 min) so Undo survives popup close (extension) and page reload (web).
- FR2: Backup reminder: `lastBackupAt` stamped in settings on export completion (both platforms) TOGETHER with the exported envelope hash; banner + settings line per Key Insights rule; wording is "Last export" (not "Last backup") to honestly reflect that download delivery is not verifiable; export UI otherwise unchanged.
- FR2a: Extension backup export (new deliverable — user-locked decision: full parity): add an export action to the extension popup reusing `createEncryptedBackup`/`createPlainBackup` from lib + an `<a download>` anchor click from the popup context; same modal/flow as web (passphrase prompt for encrypted export). Without this the FR2 reminder is unactionable on the extension (no export exists today).
- FR3: Time-drift check: opt-in setting `timeDriftCheck` (default off); when on: at load (if `navigator.onLine`) and via "Check now", perform one HEAD (web, same-origin) / one trace fetch (extension, `https://www.cloudflare.com/cdn-cgi/trace`), compute `|serverTime - deviceTime|`, warn via banner if > 5s showing measured skew; offline or fetch failure = no warning. Manifest `host_permissions` changes ONLY if the live CORS check fails; the named fallback is `optional_host_permissions: ["https://www.cloudflare.com/cdn-cgi/trace"]` with `chrome.permissions.request()` in the "Check now" handler.
- FR4: Extension parity for all features (popup toast, reminder, drift check, export).

<!-- Updated: Red Team Review Session 1 - FR1 tombstone, FR2 honest stamping + envelope hash, new FR2a extension export, FR3 corrected endpoint + permission fallback -->

### Non-functional
- NFR1: Undo holds entries in memory (toast lifetime) AND a tombstone persisted via the vault's own persistence helpers (encrypted when encryption is on); the tombstone auto-purges after 10 minutes — no long-lived sensitive residue.
- NFR2: Toast is keyboard-reachable (focus moves to it, Escape dismisses) — groundwork for Phase 7 a11y pass.
- NFR3: One new storage key per platform (`*_undo_tombstone_v1`); additive settings fields (`lastBackupAt`, `lastBackupHash`, `timeDriftCheck`).

<!-- Updated: Red Team Review Session 1 - NFRs: tombstone storage + purge window, new tombstone key + lastBackupHash field -->

## Architecture

**Undo flow:** delete handler → snapshot `{entry, index}` (single) or `[...]` (bulk) → `replaceEntries` → write pending-purge tombstone (entry + index + timestamp) → `showUndoToast(payload)` → timer 10s → on expiry drop buffer + purge tombstone; on Undo → splice entries back → `replaceEntries` → persist → purge tombstone. On the extension, a freshly opened popup checks the tombstone first: if a live one exists, offer Undo before purging. Works encrypted (passphrase still held since deletion requires unlocked vault).

**Backup reminder flow:** app/popup load → read settings → `shouldWarnBackup(settings, entryCount)` (pure helper) → banner render. Export completion (envelope built) → `settings.lastBackupAt = Date.now()` + `settings.lastBackupHash = <envelope hash>` → persist settings → hide banner. Honest-limitation note lives in the settings copy: a cancelled/blocked download cannot be detected (`downloadJson` is fire-and-forget); verify-on-import is out of scope for this plan.

**Drift flow:** setting on → `checkTimeDrift()` → fetch per platform → parse server epoch (web: `Date` header via `response.headers.get("date")`; extension: `ts=` from `https://www.cloudflare.com/cdn-cgi/trace` text) → `skewMs = Math.abs(Date.now() - serverMs)` → if > 5000 warn banner "Device clock off by Xs — TOTP codes may be rejected". Pure helpers (`parseHttpDateHeader`, `parseTraceTimestamp`, `computeSkewMs`) kept as small named functions for e2e/unit reuse.

**Extension export flow (FR2a):** popup settings → "Export backup" → (encrypted vault: passphrase already held or re-prompt) → `createEncryptedBackup`/`createPlainBackup` → anchor download (`<a download="otp-vault-backup.json">`) → stamp reminder.

<!-- Updated: Red Team Review Session 1 - flows: tombstone undo, honest export stamping with hash, corrected trace URL, extension export flow -->

## Related Code Files

- Modify: `D:\2fa\app.js` — undo toast + tombstone in delete/bulk handlers, honest export stamping with envelope hash at export (`app.js:1516-1519`, `downloadJson` at `app.js:1501-1509` unchanged), reminder + drift banners, settings additions (`app.js:622-643` area), drift helpers.
- Modify: `D:\2fa\index.html` — toast container, banner slots, "Check now" button.
- Modify: `D:\2fa\extension\popup.js` + `popup.html` — parity for all features PLUS the new export action (createEncryptedBackup/createPlainBackup + anchor download; none exists today) and tombstone-backed undo.
- Modify: `D:\2fa\extension\manifest.json` — ONLY if the live trace CORS check fails: `optional_host_permissions: ["https://www.cloudflare.com/cdn-cgi/trace"]`.
- Modify: `D:\2fa\styles.css` — toast/banner styles (Phase 7 will theme them; keep CSS-variable-ready).
- Create: `D:\2fa\tests\e2e\data-safety.spec.js` — undo (incl. reload-with-tombstone), reminder, drift (Playwright `page.route` mocks the HEAD with a controlled `Date` header; no real network); extension drift covered via `page.route` on the exact `https://www.cloudflare.com/cdn-cgi/trace` URL in `tests/e2e/extension.spec.js`.

<!-- Updated: Red Team Review Session 1 - files: export action + tombstone in popup, optional_host_permissions fallback, extension drift e2e via page.route on exact URL -->

## Implementation Steps

1. GitNexus `impact({target: "replaceEntries"})` (both app.js and popup.js have local copies — post-Phase-1 the web one is app-level), `impact({target: "createEncryptedBackup"})` upstream check for stamping points.
2. Web undo toast + tombstone: capture-and-restore logic around `removeBtn.onclick` (`app.js:1051`) and the bulk-delete handler; 10s toast with Undo; single-buffer semantics; write the pending-purge tombstone (entry + index + timestamp) through the vault's persistence helpers, purge at toast expiry/undo; persist via `persistEntries` on both delete and restore.
3. Extension undo toast + tombstone: same in `popup.js` delete handler (10s stands); on popup open, check for a live tombstone and offer Undo before its 10-min auto-purge — this is what makes undo survive popup close.
4. Honest backup stamping + reminder + extension export: stamp `lastBackupAt` + `lastBackupHash` when the export envelope completes (`app.js:1516-1519`; `downloadJson` itself is fire-and-forget — cannot detect blocked downloads); `shouldWarnBackup` helper; banner + settings "Last export: N days ago" line; NEW extension export action (FR2a: createEncryptedBackup/createPlainBackup + anchor download, +2h) so the reminder works on both platforms.
5. Time drift (web): opt-in checkbox in settings; same-origin HEAD `fetch(location.href, {method: "HEAD", cache: "no-store"})` → `Date` header → skew; load-time + "Check now" execution; >5s banner.
6. Time drift (extension): `timeDriftCheck` setting; `fetch("https://www.cloudflare.com/cdn-cgi/trace")` → `ts=` parse; re-verify live CORS first (red-team observed `Access-Control-Allow-Origin: *` on the trace GET, live re-check stays an implementation step); add `optional_host_permissions` fallback + `chrome.permissions.request()` ONLY if the live check fails; on both failures — silent skip + hint in settings.
7. Styles: toast + banner styles in `styles.css` using existing CSS variables (no theme hardcoding).
8. E2E (`tests/e2e/data-safety.spec.js`): (a) delete → toast visible → click Undo → entry restored at original index; (b) toast expiry → entry gone; (c) seed `lastBackupAt` 31 days back → banner visible → export → banner clears; (d) `page.route` same-origin HEAD with `Date` header +6s → skew banner; with +3s → no banner; (e) delete → reload page → Undo offer from tombstone restores the entry. Extension: undo survives popup close/reopen (tombstone), export produces a download, and drift check mocked via `page.route` on the exact `https://www.cloudflare.com/cdn-cgi/trace` URL in `tests/e2e/extension.spec.js`.
9. `detect_changes()` sweep. Commits: `feat: add undo delete toast`, `feat: add extension backup export`, `feat: add backup reminder with honest export stamping`, `feat: add opt-in time drift check`.

<!-- Updated: Red Team Review Session 1 - steps: tombstone undo both platforms, honest stamping, extension export step, corrected trace URL + permission fallback, reload-undo + extension route e2e -->

## Todo

- [x] Web undo toast (single + bulk, single buffer) + tombstone
- [x] Extension undo toast parity + tombstone survives popup close
- [x] Extension backup export action (FR2a — new deliverable)
- [x] Honest lastBackupAt/lastBackupHash stamping + "Last export" reminder (both)
- [x] Time-drift setting + check (web same-origin HEAD; extension www.cloudflare.com/cdn-cgi/trace, CORS re-verified live, optional_host_permissions fallback if needed)
- [x] Toast/banner styles (variable-ready)
- [x] data-safety e2e + extension.spec addition (incl. trace page.route)
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.4`

<!-- Updated: Red Team Review Session 1 - todos: tombstones, extension export, honest stamping, corrected endpoint -->

## Success Criteria

- [x] `npx playwright test tests/e2e/data-safety.spec.js` green; `npx playwright test tests/e2e/app.spec.js` and `npx playwright test tests/e2e/extension.spec.js` green (no regressions in delete/export flows).
- [x] Extension popup exports a backup (encrypted + plain) via anchor download; reminder clears after extension export.
- [x] Undo survives page reload (web) and popup close/reopen (extension) within the 10-minute tombstone window.
- [x] `npm run build` + `npm run test:unit` green.
- [x] Manual smoke: encrypted vault undo works; reminder appears at 31 days; drift banner shows measured skew with mocked header.

<!-- Updated: Red Team Review Session 1 - success criteria: extension export, tombstone undo survival -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Undo restore collides with concurrent edit (entry re-added meanwhile) | L x M | Restore re-inserts by id if absent; if id exists, no-op + info toast |
| `lastBackupAt` false confidence (fire-and-forget download; blocked/cancelled download indistinguishable from success) | M x M | Honest semantics: stamp = export envelope completion + stored envelope hash; UI says "Last export"; limitation documented here and in Phase 8 (verify-on-import out of scope) |
| Tombstone retains a deleted entry in storage beyond the toast | L x M | Rides vault persistence helpers (encrypted when vault encrypted); 10-minute auto-purge; purged on undo/lock |
| Extension time endpoint unreliable/blocked (CORS) | M x M | Feature is opt-in with silent failure; red-team live-check saw `Access-Control-Allow-Origin: *` on the trace GET (live re-verify in step 6); `optional_host_permissions` fallback named; web path is CORS-free by design |
| Toast z-index/overlap with existing status area | L x L | Dedicated container; visual check in e2e |

<!-- Updated: Red Team Review Session 1 - risks: honest lastBackupAt row, tombstone row, trace CORS row updated -->

## Security Considerations

- Undo buffer holds plaintext entries in memory — same exposure as the open vault itself; cleared on toast expiry and lock. The tombstone briefly persists the deleted entry via the vault's own encrypted-when-encrypted helpers and auto-purges after 10 minutes (or immediately on undo/lock).
- Drift check sends no vault data; same-origin HEAD leaks nothing beyond a normal page load. Extension trace call reveals IP to Cloudflare — disclosed in the opt-in copy (local-first respect, per brainstorm F8).

## Next Steps

- Phase 6 (biometric) builds its envelope on the Phase 1 KDF work; no dependency on this phase's files beyond `styles.css` theming.

## Rollback Plan

- Revert commits; additive settings fields are ignored by old code; no storage-key or data-format changes.
