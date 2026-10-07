# Scout Report — Codebase Evidence (Personal OTP Vault)

Scouted: 2026-10-07, main @ d38ab18. Tools: direct reads, grep, GitNexus impact (repo `2fa`).

## 1. Storage & state model

| Key | Location | Notes |
|---|---|---|
| `personal_otp_vault_entries_v2` | `app.js:467` | plaintext entries (persist, non-encrypt mode) |
| `personal_otp_vault_settings_v3` | `app.js:468` | settings: `persist`, `encrypt`, `blurCodes`, `screenshotSafe`, `clearClipboard`, `sortBy`, `groupBy` (render at `app.js:622-643`) |
| `personal_otp_vault_persist_warning_seen_v1` | `app.js:469` | one-time warning flag |
| `personal_otp_vault_encrypted_v1` | `app.js:470` | encrypted payload `{salt, iv, data}` |
| `otp_extension_*` | `extension/popup.js` | extension mirror via `chrome.storage.local` (PDR TAR2) |

- Unlock state: `currentPassphrase` plain module variable — `app.js` and `extension/popup.js:79`. **No idle timer, no throttling anywhere** (grep `autoLock|idleTimer|LOCK_|attempt|lockout` = 0 relevant hits).
- `persistEntries()` (`app.js:1193-1214`) already has snapshot/rollback for save failures — auto-upgrade re-encryption can hook here safely.
- `tick()` (`app.js:1171-1176`) skips regenerating codes while unlock panel visible.

## 2. Crypto (`lib/vault.js`)

- `deriveVaultKey` hardcodes `iterations: 150000, hash: "SHA-256"`, salt 16B (`lib/vault.js:46-56`). **KDF params are NOT stored in the payload** — envelope is only `{salt, iv, data}` (`lib/vault.js:67-71`), so any iteration change breaks old vault decryption.
- Backup v2 envelope: `{version:2, encrypted, createdAt, itemCount, checksum, payload}`, checksum = SHA-256 hex of `JSON.stringify(payload)` (`lib/vault.js:149-158`). Integrity-only; no HMAC/authenticity. v1→v2 migration paths at `lib/vault.js:177-243`.
- `normalizePassphrase`: min 8 chars, trim only (`lib/vault.js:38-44`).

## 3. OTP engine (`lib/otp.js`)

- `parseOtpAuthUri` rejects: non-`otpauth:` (`:159`), non-`totp` host (`:162`), non-SHA1 algorithm (`:167`), issuer/label mismatch (`:174`). digits ∈ {6,8}, period 15–120.
- `generateTotp` (`:307-319`): WebCrypto HMAC-SHA1, 8-byte BE counter, RFC 6238 truncation. Extensible to SHA-256/512 by parameterizing the `hash` in `importKey`/`sign` (`hmacSha1` at `:297-305` is the single seam).
- `generateEntryId` uses `Math.random()` (`:36`).
- `normalizeEntry` (`:91-103`) is the shape gate every entry passes (import, backup, manual) — new fields (`type`, `counter`, `algorithm`) must be added here; `hasRequiredBackupEntryShape` (`lib/vault.js:96-108`) must stay backward-compatible with entries lacking them.

## 4. App shell & rendering

- `index.html:467`: `<script src="https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js" defer>` — **no SRI, no CSP meta anywhere in index.html**. jsQR vendored via npm will remove this.
- Entry rendering is XSS-safe: `createEntryNode` clones `<template>` and uses `textContent` (`app.js:971-1007`); `innerHTML` uses are static strings only (`app.js:935, 808, 818, 838, 1106, 1296, 1546`; `popup.js:202, 225, 373-383`).
- Copy flow (`app.js:988-1007`): clipboard write + optional 30s clear + copy history (max 6). Undo-delete toast can hook `removeEntry` path and `replaceEntries`.
- Camera scan uses `window.jsQR` (`app.js:1394, 1676`) — vendoring changes this to an import.
- Reorder: `moveEntry` (`app.js:917-924`) + `resequenceEntries`; `order` field on entries (PDR FR3).

## 5. Extension

- `extension/manifest.json`: MV3, permissions `[storage, clipboardRead]`, empty `background.js` (`onInstalled` no-op). No `commands` entry (keyboard shortcut missing).
- `popup.js` mirrors app flows against `chrome.storage.local`; lock/unlock logic duplicated (lock flow at `popup.js:97-157`).

## 6. Tests & build

- Unit: `tests/unit/otp.test.js`, `tests/unit/vault.test.js` (Vitest, Node). Backup destructive tests: `tests/e2e/app-destructive-backup.spec.js`.
- E2E: `app.spec.js`, `extension.spec.js` (persistent context, unpacked extension), `offline.spec.js` (SW allowed), visual suites with win32 snapshots (`tests/e2e/*-visual.spec.js`).
- Build: esbuild → `app.bundle.js` + `extension/popup.bundle.js` (`scripts/build.mjs`); version sync enforced (`scripts/verify-version-sync.mjs`); release via `npm run release:prepare -- <version>`.
- Playwright default config blocks service workers; only `offline.spec.js` allows them.

## 7. GitNexus impact (upstream blast radius, repo `2fa`)

| Symbol (canonical, `lib/`) | Upstream impacted | Risk |
|---|---|---|
| `lib/vault.js:encryptEntries` | 6 | LOW |
| `lib/otp.js:parseOtpAuthUri` | 6 | LOW |
| `lib/otp.js:generateTotp` | 5 | LOW |

Note: the index contains duplicated symbols from build artifacts (`app.js`, `app.bundle.js` embed copies of lib functions) — always disambiguate with `file_path` hints pointing at `lib/`. Re-run `impact()` before each edit per AGENTS.md.

## 8. Constraints for the plan

- AGENTS.md: GitNexus `impact` before every symbol edit; `detect_changes()` before commit; Conventional Commits; never commit `.gitignore`; keep AGENTS.md/CLAUDE.md in sync manually.
- No runtime dependencies philosophy applies to crypto — jsQR via npm is a build-time bundle, acceptable per user decision.
- Version bump requires `package.json` + `extension/manifest.json` in lockstep (CI fails otherwise).
- Visual snapshots must be regenerated whenever styling changes (dark mode, drag-drop).
