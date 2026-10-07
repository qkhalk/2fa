---
title: Fixed six QA findings in OTP vault UI and backup import
date: 2026-10-06
summary: "Copy-failure toast retitle, URI import duplicate/invalid counts, no-match heading, friendly JSON error, legacy v1 tolerance; 37 unit + 63 e2e green"
---

# Fixed six QA findings in OTP vault UI and backup import

## What happened
Manual QA (browser-driven, agent-browser + CDP for the extension) found six issues. All six fixed in one pass:
1. Copy-failure feedback appeared under the wrong toast title ("Import") and wrote to the import panel status line. Now `showToast("Vault", ...)` at the action site (app.js createEntryNode copy catch). The original "silent" severity was a false positive of my own headless probe - feedback existed, title was wrong.
2. URI import with all-duplicate input gave terse "No new entries found from URI". Now appends "(N duplicates skipped)" and "(N invalid URIs ignored)" via buildPreviewCandidatesFromUris; dialog status also reports both counts.
3. Search no-match reused the "Vault ready for the first import" onboarding heading. showEmptyState now takes an optional heading; no-match shows "No matching entries" + a hint. One e2e assertion updated to the new contract (app.spec.js:104).
4. Corrupt/empty backup JSON surfaced raw SyntaxError ("Unexpected end of JSON input"). importBackupFile and stageBackupImport now own JSON.parse and throw "Backup file is not valid JSON" before parseBackupFile.
5. Legacy v1 backups with a stripped `encrypted` field were rejected as "version not supported". migrateBackup (lib/vault.js + app.js inlined copy, kept in behavioral sync) now treats `encrypted !== true` as plain for v1 shapes; strict entry validation unchanged. New unit test in tests/unit/vault.test.js.
6. Same-secret duplicate rule (secret+digits+period, label ignored) documented in README Notes and PDR FR5 instead of changing the dedupe key.

## Decision
- Did not change the duplicate-match key: it is a deliberate anti-double-import guard; documented instead.
- Did not mutate shared toUserMessage: owned the JSON.parse semantics at the two call sites.
- Invalid-URI counter is defense-in-depth: extractOtpAuthUris pre-validates on all current paths, so the counter is unreachable today but correct for future callers.

## Next steps
- Impact analysis flagged createEntryNode/showEmptyState CRITICAL and buildPreviewCandidatesFromUris HIGH (centrality, not change danger); verified via browser re-drive of each fixed path, 37/37 unit tests, 63/63 e2e (one flaky extension visual re-run pass).
- detect_changes: changed symbols map 1:1 to plan; no unexpected scope.
- Changes uncommitted - awaiting user go-ahead.

> Historical work record — not durable authority. Prefer docs/specs/ADRs for current decisions.
