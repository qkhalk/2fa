---
title: "Ship migration-and-language wave: Aegis/2FAS import, QR export, vi locale, backup v3"
date: 2026-10-27
summary: Implemented and shipped the full proposed feature wave for the OTP vault with review and simplifier passes; 8 commits on ghfork/main
---

# Ship migration-and-language wave: Aegis/2FAS import, QR export, vi locale, backup v3

## What happened
Executed the ak:cook wave for personal-otp-vault (D:\2fa):
- lib/importers.js (new): Aegis plain-text JSON + 2FAS backup decoders, fail-closed limits, wired into the shared import preview in web + extension.
- lib/otp.js buildOtpAuthUri + per-entry QR export (vendored npm qrcode bundled like jsqr; Copy URI both frontends, Download PNG web).
- lib/i18n.js rewritten: ~483-key en catalog + complete vi translation (coverage-tested), resolveLocale/applyTranslations/translateStrengthAssessment, Language setting in both frontends, data-i18n DOM convention.
- lib/vault.js backup v3: keyed HMAC-SHA256 mac (PBKDF2, domain-separated salt), verifyBackupMac before decrypt; v1/v2 still import.
- Extension MV3 command Ctrl+Shift+U opens the popup; sw cache bumped to v8.

Review cycle: code-reviewer verdict SHIP, 0 P0/P1, 6 P2 — all fixed (constant-time mac compare, 5M kdf iteration ceiling, file.size pre-check, digits/period defaults, v2-downgrade warning in review dialog, plural bug). Two code-simplifier passes applied (toHex helper, looksLikeEncryptedAegis single-sourcing, dead code removal).

## Decision
- Pushed to ghfork (vibecoder11200/2fa), NOT origin (qkhalk/2fa): 403 denied for this account; ghfork/main was the actual current base (origin was behind at a844d68).
- Version stays 0.3.0 and CHANGELOG uses an Unreleased section — bumping extension/manifest.json triggers the GitHub release workflow, which was not authorized.
- Intermediate commits group lib features separately from the UI wiring wave; the tip is the only e2e-green state.

## Verification
148 unit + 67 web e2e + 29 extension e2e green. Light-theme visual specs flake ONLY under back-to-back full-suite load (hot machine); always pass on isolated rerun — pre-existing trait, not from this wave.

## Next steps
- Sync ghfork/main -> origin (qkhalk/2fa) via PR or fix credentials.
- On release: npm run release:prepare (bumps version), then the keyed-mac caveat in CHANGELOG goes into release notes (v3 backups unreadable by pre-0.4.0).

> Historical work record — not durable authority. Prefer docs/specs/ADRs for current decisions.
