---
title: "Phase 8: Docs & Release Consistency — 0.2.0 Final"
description: "Sync README + docs/ with all shipped features, AGENTS/CLAUDE sync if needed, final detect_changes sweep, full test matrix, and the 0.2.0 release."
status: todo
priority: P2
estimate: 4h
release: 0.2.0
---

# Phase 8: Docs & Release Consistency — 0.2.0 Final

## Context Links

- Research: n/a (documentation of Phases 1-7 outcomes)
- Scout evidence: `reports/scout-report.md` sections 6, 8
- Depends on: ALL phases (final gate)
- Parent plan: `plan.md`

## Overview

- **Priority:** P2
- **Status:** todo
- **Description:** Bring documentation to parity with the shipped vault (HOTP + SHA-256/512, GA import, biometric unlock, auto-lock, dark mode, i18n, new storage keys, CSP/offline posture, 600k downgrade caveat), run the final GitNexus `detect_changes` sweep and the full test matrix, and cut release 0.2.0 via the lockstep release script. AGENTS.md/CLAUDE.md are synced manually only where commands or architecture notes changed.

## Key Insights

- Docs live at: `README.md` (user-facing + release automation), `docs/codebase-summary.md`, `docs/code-standards.md`, `docs/system-architecture.md`, `docs/project-overview-pdr.md`, `docs/project-roadmap.md`, `docs/offline-compatibility.md` (README "Documentation" section links all of them).
- Release machinery (verified): `npm run release:prepare -- <version>` (`scripts/prepare-release.mjs`) bumps `package.json` + `extension/manifest.json` in lockstep; `npm run verify:version` enforces; GitHub Actions `.github/workflows/release.yml` triggers on manifest version change → tag `extension-v<version>` + packaged archive. Current version: 0.1.1 → this plan ships 0.1.2 … 0.2.0.
- Repo rules (AGENTS.md): Conventional Commits, no co-author trailers, NEVER commit `.gitignore` (local-only), AGENTS.md/CLAUDE.md kept in sync MANUALLY as plain files (no symlinks/hard links).
- Content that MUST land in docs (accumulated caveats from earlier phases): (1) 600k downgrade trap — vaults re-encrypted after 0.1.2 cannot be read by older app versions; (2) HOTP entries in new backups degrade to TOTP in pre-0.1.3 app versions; (3) ONLY the live biometric-mode vault requires ≥0.1.5 code to unlock — backups remain universally restorable (Phase 6 FR10 exports them passphrase-encrypted in the standard envelope format, with no `dek` block); (4) backup checksum is integrity-only, not authenticity; (5) `jsqr` is the sole runtime-bundled dependency (build-time npm, no CDN); (6) framing protection is a HOSTING concern — meta CSP cannot deliver `frame-ancestors` (CSP3 ignores it in meta), so the docs give header-based guidance (`X-Frame-Options: DENY` / CSP `frame-ancestors 'none'` header) for whoever serves the PWA; (7) CSP trade-off note for the changelog: `connect-src 'self' https:` is deliberate — it keeps the QR-URL import feature (which fetches arbitrary user-supplied hosts) working; scripts/images stay locked to 'self'; (8) release checklist: bump `CACHE_NAME` (`sw.js:1`) in EVERY release that changes `app.bundle.js` — cache-first serving (sw.js:50-62) keeps stale bundles alive in already-open tabs otherwise.
- Test matrix at this point: unit (otp, vault, migration, biometric, i18n) + e2e (app, app-destructive-backup, extension, extension-visual, offline, web-visual, autolock, data-safety, biometric, polish).

## Requirements

### Functional
- FR1: README updated: Highlights (new features), Tech (jsqr note), Storage/security notes (600k, auto-lock, biometric), no stale claims (e.g., "TOTP" → "TOTP/HOTP").
- FR2: docs/ updates: system-architecture (key hierarchy incl. DEK/PRF envelopes, entry schema v3 fields, new storage-key table, header-based framing-protection guidance for hosting since meta CSP cannot deliver it), code-standards (new lib modules, dependency exception for jsqr, new test files), codebase-summary (new files), offline-compatibility (CSP incl. the `connect-src 'self' https:` QR-URL-import trade-off, no CDN, camera still offline), project-overview-pdr (feature list), project-roadmap (mark shipped themes; note deferred ideas: 2FAS/Aegis import, QR export, keyboard shortcut).
- FR3: AGENTS.md/CLAUDE.md manual sync ONLY if something there became stale (commands unchanged; if Architecture section mentions lib contents, add biometric/migration modules). Plain-file edit, no links.
- FR4: Release notes (GitHub Release body or CHANGELOG section in docs) capture the eight caveat items from Key Insights — including the CSP trade-off note (QR-URL import) and the CACHE_NAME bump rule — and carry the per-release CACHE_NAME checklist forward so future releases inherit it.

### Non-functional
- NFR1: Docs voice matches existing files (concise, factual, no marketing).
- NFR2: No code changes in this phase except version fields via the release script.

## Architecture

Not applicable (documentation + release gate). Flow: docs commits → full test matrix → `detect_changes()` final sweep → `npm run release:prepare -- 0.2.0` → `npm run verify:version` → push/PR → CI tags `extension-v0.2.0`.

## Related Code Files

- Modify: `D:\2fa\README.md`
- Modify: `D:\2fa\docs\codebase-summary.md`, `docs\code-standards.md`, `docs\system-architecture.md`, `docs\project-overview-pdr.md`, `docs\project-roadmap.md`, `docs\offline-compatibility.md`
- Modify: `D:\2fa\AGENTS.md` + `D:\2fa\CLAUDE.md` (only if stale after the above audit)
- Modify: `D:\2fa\package.json` + `D:\2fa\extension\manifest.json` (via release script only)
- Create: none

## Implementation Steps

1. Audit drift: diff each docs file against the shipped feature set (grep for "TOTP" only-claims, storage-key tables, dependency lists); list needed edits per file.
2. Write doc updates (FR1-FR3) in Conventional Commits batches: `docs: update readme for hotp import and biometric unlock`, `docs: sync architecture and standards`, etc.
3. Full test matrix, in order: `npm run build` → `npm run test:unit` → `npx playwright test tests/e2e/app.spec.js` → `npx playwright test tests/e2e/extension.spec.js` → `npx playwright test tests/e2e/offline.spec.js` → `npx playwright test tests/e2e/app-destructive-backup.spec.js` → visual + phase suites (autolock, data-safety, biometric, polish). All green required.
4. Final GitNexus `detect_changes()`; for regression review run `detect_changes({scope: "compare", base_ref: "main"})` — confirm the whole plan's blast radius matches the phase reports (lib/vault.js, lib/otp.js, lib/migration.js, lib/biometric.js, lib/i18n.js, app.js, index.html, styles.css, extension/*, tests/*, package.json, manifest.json).
5. Release: `npm run release:prepare -- 0.2.0` → `npm run verify:version` → commit `chore: release 0.2.0` → push branch → PR → merge → verify CI creates tag `extension-v0.2.0` and attaches the archive.
6. Verify the released extension archive loads as an unpacked extension and the PWA smoke-passes offline (`tests/e2e/offline.spec.js` already proves the shell).

## Todo

- [x] Docs drift audit (per-file edit list)

<!-- Updated: Red Team Review Session 1 - caveat #3 corrected (live vault only), framing-protection guidance, CSP trade-off changelog notes, CACHE_NAME per-release checklist (Key Insights 6-8, FR2/FR4, todo) -->
- [x] README + docs/ updated (FR1-FR2)
- [x] AGENTS.md/CLAUDE.md synced if stale (FR3)
- [x] Release notes with the eight caveat items incl. CSP trade-off + CACHE_NAME checklist (FR4)
- [x] Full test matrix green (step 3 list)
- [x] Final detect_changes() + compare vs main reviewed
- [x] Release 0.2.0 prepared, verified, CI tag confirmed

## Success Criteria

- [x] All doc files state the shipped behavior accurately (spot-check: storage keys, HOTP support, biometric caveat, CSP posture).
- [x] Full test matrix green (step 3 commands, all suites).
- [x] `npm run verify:version` passes; CI publishes `extension-v0.2.0` with archive attached.
- [x] `.gitignore` untouched and uncommitted; all commits Conventional Commits without co-author trailers.

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Docs drift missed (stale claims survive) | M x M | Step-1 audit produces an explicit per-file checklist before writing |
| Release script bump misses a consumer of version | L x M | `verify:version` + CI both gate; script is the only allowed version editor |
| Test matrix flake near release | M x L | Re-run failures once; genuine flakes get fixed or quarantined BEFORE tag, never after |

## Security Considerations

- Docs must not disclose anything sensitive (no real secrets in examples; biometric docs describe storage of non-secrets only).
- Caveat items (downgrade traps) are user-safety information — release notes are the authoritative copy.

## Next Steps

- Plan complete. Deferred ideas recorded in project-roadmap.md (2FAS/Aegis import, single-entry QR export, extension keyboard shortcut, backup HMAC v3).

## Rollback Plan

- Docs: git revert. Release: delete tag + re-release is discouraged; a defective 0.2.0 gets a patch release (0.2.1) instead — standard semver practice.
