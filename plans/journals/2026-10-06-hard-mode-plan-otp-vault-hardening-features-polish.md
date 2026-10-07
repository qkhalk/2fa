---
title: "hard-mode plan: OTP vault hardening, features & polish"
date: 2026-10-06
summary: "16 locked intake decisions -> 2 research agents + scout -> 8-phase/78h plan via ak CLI -> 4-persona red team (15/16 accepted) -> fixes applied with 47 markers, validate+parse green"
---

# hard-mode plan: OTP vault hardening, features & polish

## What happened
- Ran ak:plan --hard for D:\2fa (local-first TOTP vault, PWA + MV3 extension).
- Intake: 4 AskUserQuestion rounds produced 16 locked decisions (full scope, extension parity, security-first, PBKDF2 auto-upgrade 150k->600k with KDF params in envelope, jsQR via npm + CSP, auto-lock 15min, FULL HOTP support, GA otpauth-migration import, undo toast+tombstone, backup reminder >30d, dark mode 3-state, i18n framework-only, WebAuthn PRF in scope, clipboardRead optional, time-drift check, crypto entry IDs, drag & drop, releases 0.1.2->0.2.0).
- Research: 2 researcher agents (WebAuthn PRF envelope/KEK design + browser matrix; GA protobuf wire format, enums, base64 traps, RFC 4226/6238 vectors) + GitNexus impact (lib symbols all LOW) + scout report with line-anchored evidence.
- Plan scaffolded via `ak plan create` -> plans/261006-2150-otp-vault-hardening-features-polish (8 phases, 78h, 130 tasks; validate+parse OK).
- Red team: 4 hostile code-reviewer personas returned 38 raw findings -> 15 accepted groups, 1 rejected (false-positive path resolution). Criticals: phase-1 de-dup drift (inline app.js:1-465 copies are lenient where lib is strict; extractOtpAuthUris + nextOrderValue missing from import list; lib normalizeEntry strips `order`), phase-6 save path & backup-import never rewired for DEK, phase-3 v2-key deletion + SW CACHE_NAME staleness.
- Fix agent applied all accepted findings (47 markers, 9 files); whole-plan consistency sweep clean; Validation Log records Full-tier verification and 4 unresolved questions (DEK-vs-KEK gate, chrome.storage.session cache gate, real-GA-QR + real-authenticator manual assets, i18n t() depth).

## Decision
- De-dup must reconcile semantics BEFORE deletion: port lenient invalidItemCount behavior INTO lib/vault.js in its own commit; relabeling semantic changes as refactor: is forbidden.
- v2 storage keys become permanent read-only fallbacks (no destructive migration); CACHE_NAME bumps every bundle-changing release.
- Biometric backups are exported passphrase-encrypted so restore works on any version; live biometric vault requires >=0.1.5.
- Key lesson: call-site existence is not call-site semantics — three "verified" phase-1 claims were falsified by tracing actual code paths.

## Next steps
- User reviews plan at plans/261006-2150-otp-vault-hardening-features-polish/plan.md (esp. Red Team Review + Validation Log).
- Answer the 4 unresolved questions when available.
- Then run /ak:cook with the absolute plan path (fresh session recommended: /clear first).

> Historical work record — not durable authority. Prefer docs/specs/ADRs for current decisions.
