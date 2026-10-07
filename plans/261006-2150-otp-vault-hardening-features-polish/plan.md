---
title: "OTP Vault Hardening, Features & Polish"
description: "Security-first upgrade of the local-first TOTP vault: KDF envelope + 600k iterations, session hardening, HOTP/SHA-256/512 engine, GA migration import, WebAuthn PRF biometric unlock, UX polish — full parity in web app and extension."
status: pending
priority: P1
effort: 78h
branch: qkhalk/feat/vault-hardening
tags: [security, feature, frontend, auth]
blockedBy: []
blocks: []
created: 2026-10-07
---

# OTP Vault Hardening, Features & Polish

## Overview

Transform the 2FA vault (v0.1.1) from a working TOTP app into a hardened, feature-complete authenticator: PBKDF2 params move inside the encrypted envelope (600k default, silent legacy upgrade), the app shell gets CSP + vendored jsQR + auto-lock + unlock throttling, the OTP engine gains full HOTP and SHA-256/512 support, Google Authenticator exports import natively, biometric unlock ships via WebAuthn PRF (passphrase stays as recovery), and the UI gets dark mode, drag & drop, undo-delete, backup reminders, and an i18n framework. Every user-facing feature lands in BOTH web app and extension popup. Releases gate progress: 0.1.2 → 0.1.3 → 0.1.4 → 0.1.5 → 0.2.0.

## Cross-Plan Dependencies

| Plan | Relationship |
|------|--------------|
| (none) | This plan has no cross-plan blockers. |

## Phases

| # | Phase | Release | Status |
|---|-------|---------|--------|
| 1 | [Phase 1: Crypto Hardening — KDF Envelope & Passphrase Strength](./phase-01-start.md) | 0.1.2 | Pending |
| 2 | [Phase 2: Session & Shell Hardening — CSP, jsQR, Auto-Lock, Throttling](./phase-02-session-shell-hardening.md) | 0.1.2 | Pending |
| 3 | [Phase 3: OTP Engine Expansion — HOTP, SHA-256/512](./phase-03-otp-engine-expansion.md) | 0.1.3 | Pending |
| 4 | [Phase 4: Google Authenticator Import — Migration Parser & Preview](./phase-04-google-authenticator-import.md) | 0.1.3 | Pending |
| 5 | [Phase 5: Data-Safety UX — Undo Delete, Backup Reminder, Time Drift](./phase-05-data-safety-ux.md) | 0.1.4 | Pending |
| 6 | [Phase 6: Biometric Unlock — WebAuthn PRF Envelope](./phase-06-biometric-unlock.md) | 0.1.5 | Pending |
| 7 | [Phase 7: Polish — Dark Mode, Drag & Drop, Ring, A11y, i18n](./phase-07-polish.md) | 0.2.0 | Pending |
| 8 | [Phase 8: Docs & Release Consistency — 0.2.0 Final](./phase-08-docs-release.md) | 0.2.0 | Pending |

## Dependencies

- Phase 2 depends on Phase 1 (auto-lock/throttle wrap the new envelope unlock path; passphrase meter UI consumes lib export).
- Phase 4 depends on Phase 3 (migration import maps HOTP entries; requires `type`/`counter` fields from Phase 3).
- Phase 6 depends on Phase 1 (PRF KEK wraps the same DEK the passphrase envelope uses; both envelopes must share key semantics).
- Phases 5 and 7 depend on Phases 1-4 (build on the hardened shell and expanded entry model).
- Phase 8 depends on all phases (docs sync + final release gate).

## Success Criteria

- [ ] All 8 phases completed with their release gates cut (`npm run release:prepare -- <version>`).
- [ ] `npm run build`, `npm run test:unit`, `npm test` green at every phase boundary.
- [ ] Legacy 150k vaults decrypt and auto-upgrade to 600k without user action (fixture-tested).
- [ ] HOTP + SHA-256/512 pass RFC 4226/6238 vectors; GA migration parser passes real export fixtures.
- [ ] Biometric unlock works on web + extension with passphrase fallback intact.
- [ ] Every user-facing feature verified in both `app.spec.js` and `extension.spec.js` e2e paths.

<!-- slug: otp-vault-hardening-features-polish -->

## Red Team Review

### Session — 2026-10-07
**Findings:** 16 raw, deduplicated to 15 accepted groups (1 rejected: "research files missing" — false positive, paths resolved against repo root instead of plan dir; Contract Verifier confirmed all referenced artifacts exist)
**Severity breakdown:** 4 Critical, 8 High, 3 Medium — all accepted and applied

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | Phase 1 de-dup drift: inline copies differ from lib (lenient vs strict decrypt, invalidItemCount), missing imports (extractOtpAuthUris, nextOrderValue), order field stripped by lib normalizeEntry | Critical | Accept | Phase 1 |
| 2 | Phase 6 save path not rewired: biometric unlock never sets currentPassphrase → mutations fail or orphan the DEK | Critical | Accept | Phase 6 |
| 3 | Phase 6 backup import path does not unwrap DEK; biometric backups unrestorable; Phase 8 caveat false | Critical | Accept | Phase 6, Phase 8 |
| 4 | Phase 3 deletes v2 key (breaks rollback, divergent data) + SW CACHE_NAME never bumped while serving cache-first | Critical | Accept | Phase 3 |
| 5 | KDF downgrade: kdf.iterations < floor accepted as modern, never upgraded; unkeyed checksum enables tampering | High | Accept | Phase 1 |
| 6 | Multi-tab lost updates: no storage listener; auto-upgrade writes from every tab | High | Accept | Phase 1 |
| 7 | Backup reminder stamps fire-and-forget download; extension has no export feature at all | High | Accept | Phase 5 |
| 8 | CSP connect-src 'self' kills QR-URL import; frame-ancestors ignored in meta CSP | High | Accept | Phase 2 |
| 9 | Entry ID entropy: Uint16 = 65k space; id collision turns delete-one into delete-two | High | Accept | Phase 2 |
| 10 | Manual "Lock Vault" button exists (app.js:1951) and never clears currentPassphrase; must unify | High | Accept | Phase 2 |
| 11 | visibilitychange resets idle timer on show → mobile auto-lock ineffective | High | Accept | Phase 2 |
| 12 | HOTP render loop unhandled (generateTotp at app.js:1150, popup.js:405); counter regression has no repair path | High | Accept | Phase 3 |
| 13 | Phase 6 design: DEK vs KEK-wraps-passphrase comparison, envelope format marker, enrollment atomicity, passphrase re-prompt, passphrase-change re-wrap | Medium | Accept | Phase 6 |
| 14 | Extension realities: undo toast killed by popup teardown (tombstone), time-drift endpoint/permissions undecided, popup-open KDF cost (session cache decision) | Medium | Accept | Phase 5, Phase 2 |
| 15 | GA batch bounds missing; Phase 7 10h estimate not credible (→18h); legacy-upgrade hook cited wrong line (app.js:1607 is backup import) | Medium | Accept | Phase 4, Phase 7, Phase 1 |

### Whole-Plan Consistency Sweep
- Files reread: plan.md + all 8 phase files after edits
- Decision deltas checked: strict-decrypt reconciliation, v2-key retention, biometric backup re-encryption, effort re-budget, lock unification
- Reconciled stale references: 46 marker-tagged section updates across the 8 phase files (~30 distinct stale claims), including: "no behavior change"/"clean delete + import" de-dup claims (phase-01 ×4), missing `extractOtpAuthUris`/`nextOrderValue` imports (×2), wrong upgrade-hook line app.js:1607 (×2), normalizeEntry `order` strip (×1), "no lock logic / 0 hits" (×1), CSP `connect-src` + meta `frame-ancestors` (×4), Uint16 entry IDs (×2), visibilitychange direction (×2), "remove v2 after successful write"/"old key removed" (×4), missing CACHE_NAME bump rule (×3), HOTP render loop + counter repair (×4), GA batch bounds (×4), fire-and-forget `lastBackupAt` + apex cloudflare URL (×7), missing extension export (×3), undo tombstone (×5), biometric save path / decrypt consumers / backup re-encryption / re-wrap / re-prompt / format marker / enrollment atomicity (×13), 10h estimate (×1), Phase 8 biometric caveat + framing/CSP/CACHE_NAME doc items (×3)
- Unresolved contradictions: 0. Note on the effort re-budget: plan.md's Phases table lists no estimate column, so the conditional "5→12h / 6→14h" updates had no target; only phase-07's explicit 10h→18h re-budget was applied to frontmatter, which makes the mandated 78h total exactly consistent (8+10+8+10+8+12+18+4 = 78h). The extra scope added to phases 5/6 by findings 7/13/14 is absorbed within their existing budgets.

<!-- Updated: Red Team Review Session 1 - added Red Team Review section (15 accepted finding groups, sweep results) and re-budgeted effort 70h -> 78h -->

## Validation Log

### Session — 2026-10-07
**Mode:** Verification pass executed at Full tier via the Red Team session (4 roles, 8 phases); interactive interview deferred — requester was unavailable, open decisions are recorded below as unresolved questions instead of being guessed.

### Verification Results
- **Tier:** Full (all 4 verification roles active)
- **Claims checked:** 43 (Fact Checker) + 12 behavioral traces (Flow Tracer) + full caller enumeration for 10 symbols (Contract Verifier) + state-lifetime table for 8 proposed state additions (Scope Auditor)
- **Verified:** 38 fact-check claims, 9 traces | **Failed:** 4 claims, 3 traces | **Unverified:** 1 (time-drift endpoint CORS — resolved to a live-check implementation step)
- All failures were converted into accepted Red Team findings and applied to the phase files before this log was written; no plan edit bypassed user-visible adjudication.

### Unresolved Questions → RESOLVED (Validation Session 2 — 2026-10-07)

All four open questions were researched via exa (addendum: `reports/research-open-questions-resolution.md`) and decided with the requester; decisions are propagated to the phase files with `<!-- Updated: Validation Session 2 -->` markers:

1. **Phase 6 design gate: RESOLVED — DEK two-envelope ADOPTED.** Industry prior art is unambiguous: Bitwarden's PRF unlock unwraps a wrapped copy of the account encryption key; envelope-encryption guidance associated with the WebAuthn L3 spec co-editor recommends a DEK with per-authenticator KEKs; webauthn-prf-zktv wraps the same vault key under both `prf-v1` and `pw-v1`. Propagated to phase-06 (step 2 recorded as decided, `[x]` todo; FR8-FR12 unchanged — they already assumed DEK). Bonus platform intel recorded: Windows Hello prf from Windows 11 25H2+, Chrome 147 registration-time eval, iOS 18.0–18.3 data-loss bug fixed in 18.4+.
2. **Phase 2 session cache: RESOLVED — ADOPT.** Chrome's storage docs recommend `storage.session` for sensitive session data (in-memory, never on disk, cleared on browser close/update); Bitwarden caches unlock state exactly this way. Propagated to phase-02 (description, Key Insights, FR7, step 6, todo, success criterion) — includes `chrome.alarms` + `chrome.idle` clearing so an idle browser locks without the popup open.
3. **Manual test assets: RESOLVED — requester has BOTH.** A real Google Authenticator export QR (phase-04 manual acceptance) and a real platform authenticator (phase-06 manual matrix, Windows Hello / Touch ID) are confirmed available; `[UNVERIFIED: hardware availability]` markers removed and success criteria tightened.
4. **i18n depth: RESOLVED — t() refactor covers unlock + settings areas only.** Toast/import strings stay hardcoded this release; their dictionary keys are reserved. Propagated to phase-07 (Key Insights, FR7, step 7).

