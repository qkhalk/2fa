---
title: "Phase 4: Google Authenticator Import — Migration Parser & Preview"
description: "Dependency-free otpauth-migration protobuf decoder in lib/ with batch stitching, enum/skip rules, and an import-preview UI on web and extension."
status: todo
priority: P2
estimate: 10h
release: 0.1.3
---

# Phase 4: Google Authenticator Import — Migration Parser & Preview

## Context Links

- Research: `research/research-ga-migration-hotp.md` sections 1, 2, 6 (authoritative: field numbers, enums, base64/issuer/batch gotchas, decoder pseudocode)
- Scout evidence: `reports/scout-report.md` sections 3, 4
- Depends on: Phase 3 (`type`/`counter`/`algorithm` fields, `generateHotp` — HOTP entries from GA must import as HOTP)
- Parent plan: `plan.md`

## Overview

- **Priority:** P2 (highest user value feature; depends on Phase 3)
- **Status:** todo
- **Description:** Add native import of Google Authenticator exports (`otpauth-migration://offline?data=<base64 protobuf>`): a bounded, dependency-free protobuf wire decoder in a new `lib/migration.js`, batch stitching for multi-QR exports, and an import-preview UI (checkbox list + skipped-token warnings) on web and extension. Never aborts a batch on one bad entry; every skipped token is reported.

## Key Insights

- Wire schema (two independent reverse-engineering sources agree; Google never published the .proto): MigrationPayload = repeated otp_parameters(f1, len-delim), version(f2), batch_size(f3), batch_index(f4, 0-based), batch_id(f5). OtpParameters = secret(f1, RAW BYTES not base32), name(f2), issuer(f3), algorithm(f4 enum), digits(f5 enum), type(f6 enum), counter(f7 int64, HOTP only).
- Enums: algorithm 1=SHA1, 2=SHA256, 3=SHA512, 0=unspecified(→SHA1), 4=MD5(→skip+warn, WebCrypto has no MD5 and it is a security downgrade), >4 skip+warn. digits 1=6, 2=8, 0→6. type 1=HOTP, 2=TOTP, 0→TOTP. CRITICAL: GA's internal SQLite DB uses the OPPOSITE type order (TOTP=0/HOTP=1) — never share one mapping (research §1).
- Base64 trap: `data` is STANDARD base64 (`+ / =`) percent-encoded in the URI. `URLSearchParams` turns `+` into space — parse the query manually or restore `+`. Tolerate base64url (`-`→`+`, `_`→`/`, re-pad) for third-party producers.
- No period field exists in the payload — imported TOTP entries default `period = 30` even though the vault supports 15-120s.
- Issuer-in-name: GA often leaves `issuer` empty with `Issuer:account` in `name` — split at the FIRST colon, trim leading spaces off the account (Aegis production rule).
- Batching: each QR is a complete independently decodable payload; stitch by grouping on `batch_id`, merge all otp_parameters, order by `batch_index` (0..batch_size-1), dedupe by (secret, name). Partial scans import what was scanned.
- Decoder must be total and bounds-checked (consumes untrusted QR input): unknown fields skipped by wire type (wt0 varint, wt1 +8B, wt5 +4B, wt2 length-prefixed); wire types 3/4 (groups) throw; varint ≤10 bytes; counter via `BigInt.asIntN(64)` then Number only if ≤ MAX_SAFE_INTEGER.
- Batch bounds (red-team): untrusted `batch_size`/`batch_index` must be validated BEFORE allocation/accumulation — `batch_index ∈ [0, batch_size)` required; `batch_size > 10` rejected as `MIGRATION_DATA_MALFORMED`; total stitched entries capped at 500; per-payload decoded byte length capped before decode. Without these, a crafted QR (or a stuck camera loop) can balloon memory/accumulation indefinitely — the camera accumulation MUST have a termination guarantee.

<!-- Updated: Red Team Review Session 1 - batch bounds: batch_index range, batch_size cap, 500-entry stitch cap, per-payload byte cap, camera termination -->
- Existing URI extraction: `extractOtpAuthUri(s)`/`extractOtpAuthUris` (`lib/otp.js:202-235`) scan for `otpauth://`; migration scheme must NOT enter `parseOtpAuthUri` — separate `parseMigrationUri` (research §5).
- Import paths available: web paste/URL/QR-camera/clipboard-image; popup paste/clipboard only (no camera). `hasDuplicateEntry` (`lib/otp.js:236`) dedupes against the vault (secret+digits+period match).

## Requirements

### Functional
- FR1: `lib/migration.js` exports `parseMigrationUri(uri)` → `{entries: OtpParameters[], warnings: string[], batch: {size, index, id}}` and `stitchMigrationBatches(payloads)` → `{entries, warnings, batches: {id, size, scannedIndexes[]}}`. Bounds (fail-closed): `batch_index ∈ [0, batch_size)` else `MIGRATION_DATA_MALFORMED`; `batch_size > 10` rejected; stitched entries capped at 500 total; per-payload decoded byte length capped (constant documented in the module) BEFORE decode. Internal: `decodeMigrationPayload(Uint8Array)`, `decodeOtpParameters(Uint8Array)`, varint/skip helpers.
- FR2: Mapping to vault entries: secret → base32 (new `bytesToBase32` export in `lib/otp.js`), name/issuer → label via issuer-in-name rule, algorithm/digits/type/counter per enum rules, `period: 30` always, then through `normalizeEntry` (Phase 3 fields).
- FR3: Import preview UI (web + popup): dialog lists parsed entries (label, type badge, algorithm, digits, counter for HOTP) with checkboxes default-checked, shows per-entry and batch warnings, an "Import N entries" button, and dedupe behavior (duplicates pre-unchecked with "already in vault" hint).
- FR4: Entry points — web: new "Google Authenticator" import action accepting pasted export text/URI, plus automatic detection of `otpauth-migration://` in existing clipboard/URL/QR-scan paths; camera loop accumulates multiple QRs (stitch-by-batch_id) until `batch_size` scanned or user stops. Accumulation is bounded: the camera loop terminates when all `batch_size` QRs are scanned, when the stitched-entry cap (500) is hit, or on user stop — it never accumulates unbounded. Extension: paste/clipboard import path.
- FR5: Multi-QR progress: show "scanned X of Y QR codes" while accumulating; allow partial import.

### Non-functional
- NFR1: Zero dependencies; decoder ≤ ~150 lines; lib/ browser-agnostic and Node-testable (docs/code-standards.md).
- NFR2: Decoder never throws on unknown fields; fails closed only on truncated/malformed structure with a specific error code.
- NFR3: Decoded secrets never logged; warnings are count/label-based only.

## Architecture

**Data flow:** raw input (text/URI/QR) → `extractMigrationUris` (new helper alongside `extractOtpAuthUris` in app/popup layer or lib) → `parseMigrationUri` per QR → session accumulates payloads keyed by `batch_id` → `stitchMigrationBatches` on demand → map each OtpParameters → candidate entry via `normalizeEntry` → preview dialog (user selects) → `hasDuplicateEntry` filter → `replaceEntries` + `persistEntries` (encrypted path when enabled).

**Module boundaries:** `lib/migration.js` knows the wire format only (bytes in, plain objects out); UI mapping + enum-to-entry conversion lives in the lib as `migrationToEntryCandidates` (pure, testable), keeping DOM code thin. Scheme detection helpers stay in `lib/otp.js` next to their otpauth:// siblings.

## Related Code Files

- Create: `D:\2fa\lib\migration.js` — wire decoder, enum maps, batch stitch, candidate mapping.
- Modify: `D:\2fa\lib\otp.js` — `bytesToBase32` export; `extractOtpAuthUris` gains a migration-scheme sibling helper.
- Modify: `D:\2fa\app.js` — import-panel action, preview dialog, camera multi-QR accumulation (`app.js:1394/1676` decode loop), clipboard/URL path detection.
- Modify: `D:\2fa\extension\popup.js` + `popup.html` — paste/clipboard migration import + preview parity.
- Create: `D:\2fa\tests\unit\migration.test.js` — fixtures and rules below.
- Modify: `D:\2fa\tests\unit\otp.test.js` — `bytesToBase32` round-trip.
- Modify: `D:\2fa\tests\e2e\app.spec.js` — preview UI flow with a fixture migration URI.

## Implementation Steps

1. GitNexus `query({search_query: "import otpauth uri parse"})` to confirm no existing migration handling; `impact({target: "extractOtpAuthUris"})`, `impact({target: "hasDuplicateEntry"})`.
2. Write `lib/migration.js` decoder per research §2 pseudocode: `varint`, `skipField`, `lenBytes`, `decodeOtpParameters`, `decodeMigrationPayload`, `b64DecodeBytes` (standard base64, tolerate url-safe, no URLSearchParams for the data param), `parseMigrationUri`, `stitchMigrationBatches`, `migrationToEntryCandidates`. Fail-closed error codes: `MIGRATION_URI_INVALID`, `MIGRATION_DATA_MALFORMED`. Batch bounds enforced before accumulation/decode: `batch_index ∈ [0, batch_size)`, `batch_size > 10` → `MIGRATION_DATA_MALFORMED`, 500-entry stitch cap, per-payload decoded byte cap (FR1).
3. Add `bytesToBase32` to `lib/otp.js` (RFC 3548 alphabet, no padding by app convention) + round-trip unit test with `base32ToBytes`.
4. Web UI: add "Import from Google Authenticator" to the import panel; wire paste-URI → preview dialog → import; extend clipboard/URL import text scan to detect `otpauth-migration://`; in the camera decode loop (`app.js:1394, 1676`), detect migration payloads, accumulate by batch_id, show "X of Y QRs" progress, stop-early button; enforce the termination guards (all scanned / 500-entry cap / user stop).
5. Preview dialog: build from `<template>` clone + textContent (existing XSS-safe pattern, `app.js:971-1007`); per-entry checkboxes; warnings list; import button runs dedupe + `replaceEntries`.
6. Extension parity: same preview + import in `popup.js`/`popup.html` via clipboard/paste (no camera). Reuse lib candidates mapping — zero duplication of parsing in UI code.
7. Tests (`tests/unit/migration.test.js`): hand-built encoder helpers (test-local `encodeVarint/encodeTag/encodeLenBytes`); fixtures: (a) 2-entry payload (TOTP/SHA1/6d + HOTP/SHA256/8d/counter=5); (b) issuer-in-name split; (c) MD5 + unknown-algorithm skip warnings; (d) digits/type 0 defaults; (e) batch stitch order + dedupe by (secret,name); (f) standard base64 with `+ / =` percent-encoded and `+`-as-space restoration; (g) base64url tolerated; (h) unknown field (f99) each wire type skipped; (i) truncated varint throws `MIGRATION_DATA_MALFORMED`; (j) counter int64 (10-byte varint) decodes; (k) batch bounds — `batch_index >= batch_size` rejected, `batch_size = 11` rejected as `MIGRATION_DATA_MALFORMED`, oversized per-payload byte input rejected pre-decode, stitched totals > 500 capped; camera accumulation terminates on the caps (loop-invariant test).
8. E2E: `tests/e2e/app.spec.js` addition — paste fixture migration URI → preview shows 2 entries → import → entries appear, counter visible for HOTP. Manual acceptance (research limitation): round-trip one REAL GA export QR through the parser before release [UNVERIFIED: real fixture availability — requires a phone].
9. `detect_changes()` sweep. Commits: `feat: add otpauth-migration protobuf parser`, `feat: add ga import preview ui`, `test: cover migration decoder rules`.

## Todo

- [x] lib/migration.js decoder + stitch + candidates mapping
- [x] bytesToBase32 + extraction helper in lib/otp.js
- [x] Web import action + preview dialog + camera multi-QR accumulation
- [x] Extension paste/clipboard import + preview parity
- [x] Unit fixtures (a)-(k) green (incl. batch bounds + termination); bytesToBase32 round-trip
- [x] E2E preview-import flow green
- [x] Real-export-QR acceptance smoke (manual — asset CONFIRMED: requester provides a real GA export QR; Validation Session 2)
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.1.3` (with Phase 3)

## Success Criteria

- [x] `npx vitest run tests/unit/migration.test.js` and `npx vitest run tests/unit/otp.test.js` green; `npm run test:unit` green.
- [x] `npm run build` green; `npx playwright test tests/e2e/app.spec.js` green including the migration-import case.
- [x] `npx playwright test tests/e2e/extension.spec.js` green with popup paste-import parity.
- [x] Skipped tokens always produce visible warnings; a payload of ALL-bad entries imports nothing and reports every skip.
- [x] Manual acceptance: a REAL Google Authenticator export QR (provided by the requester — confirmed available, Validation Session 2) round-trips through web import and extension paste import; the entries it produces (labels, types, counters) match what Google Authenticator shows; skipped-token warnings match reality.

<!-- Updated: Validation Session 2 - manual acceptance asset confirmed (real GA export QR provided by requester) -->

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Untrusted batch fields drive unbounded accumulation/decode (memory blowup, stuck camera loop) | M x H | FR1 bounds: batch_index range check, batch_size ≤ 10, 500-entry stitch cap, per-payload byte cap pre-decode; camera loop terminates on caps (fixture k) |
| Reverse-engineered proto drift vs. current GA app (research limitation) | M x H | Defensive total decoder (unknown fields/enums skipped, never abort); real-QR acceptance smoke before release; warnings make failures visible |
| Base64 `+`-vs-space corruption silently changes secrets | M x H | Fixture (f) dedicated to this trap; manual query parse, no URLSearchParams on data param |
| Type-enum mixup (QR vs SQLite order) flips HOTP/TOTP | L x H | Single QR-enum map, code comment citing research; HOTP fixture asserts type=1→hotp |
| Preview XSS via decoded label strings | L x H | textContent-only rendering per existing pattern; no innerHTML with dynamic data |

<!-- Updated: Red Team Review Session 1 - risk table: unbounded batch accumulation row added -->

## Security Considerations

- GA exports are plaintext secrets in transit (CVE-2023-3823 lesson): parsing is fully local; no telemetry; warn users the export QR contains raw secrets and to delete it after import.
- Decoded candidates pass `normalizeEntry` strict validation before touching vault state.
- Import writes go through the same encrypted persistence as all other writes.

## Next Steps

- Phase 5 adds data-safety UX on top of the entry-mutation flows (undo-delete hooks `replaceEntries`).

## Rollback Plan

- Revert commits; `lib/migration.js` and UI additions are additive — no storage or crypto changes. Imported entries remain valid vault entries.
