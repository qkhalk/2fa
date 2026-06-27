# Codebase Summary

Last updated: 2026-06-27

## Directory Layout

```
2fa/
├── index.html              # Root PWA app entry point
├── app.js                  # Main browser app (~2000 lines)
├── styles.css              # App styles
├── sw.js                   # Service worker for offline/PWA support
├── manifest.webmanifest   # PWA manifest
├── lib/
│   ├── otp.js             # TOTP domain logic (generation, parsing, validation)
│   └── vault.js           # Encryption (PBKDF2 + AES-GCM) and backup logic
├── extension/
│   ├── popup.js           # Extension popup entry point
│   ├── popup.html         # Extension popup UI
│   ├── popup.css          # Extension styles
│   ├── manifest.json      # Chrome MV3 extension manifest
│   ├── background.js      # Extension service worker
│   └── icons/             # Extension-specific icons
├── scripts/
│   ├── build.mjs          # esbuild bundler for web and extension
│   ├── generate-icons.mjs # Icon generation from SVG source
│   ├── prepare-release.mjs # Version bumping automation
│   └── verify-version-sync.mjs # Version consistency check
├── tests/
│   ├── unit/              # Vitest unit tests for lib/ modules
│   │   ├── otp.test.js
│   │   └── vault.test.js
│   └── e2e/               # Playwright end-to-end tests
│       ├── app.spec.js            # Web app flows
│       ├── extension.spec.js      # Extension popup flows
│       ├── offline.spec.js        # PWA offline testing
│       ├── app-destructive-backup.spec.js # Backup safety tests
│       ├── web-visual.spec.js      # Visual regression (web)
│       └── extension-visual.spec.js # Visual regression (extension)
├── docs/                  # Documentation
├── icons/                 # PWA icons (generated from icon.svg)
├── icon.svg               # Single source of truth for branding
└── package.json           # Dependencies and scripts

Build artifacts (not in source control):
├── app.bundle.js          # Bundled root app
└── extension/popup.bundle.js # Bundled extension popup
```

## Root App vs Extension Split

The project implements two frontends that share identical domain logic:

### Root App (`/`)
- **Storage**: Browser localStorage (keys: `personal_otp_vault_*`)
- **Entry Point**: `index.html` → `app.js`
- **Build Output**: `app.bundle.js`
- **Features**: Full PWA support, camera scan, offline capability
- **Use Case**: Primary local-first web application

### Extension (`extension/`)
- **Storage**: Chrome `chrome.storage.local` (keys: `otp_extension_*`)
- **Entry Point**: `popup.html` → `popup.js`
- **Build Output**: `extension/popup.bundle.js`
- **Features**: QR import via BarcodeDetector, popup-specific UI
- **Use Case**: Browser extension for quick access

## Shared Lib/ Architecture

The `lib/` directory contains domain logic that must remain browser-agnostic and extension-agnostic:

### `lib/otp.js`
TOTP generation using Web Crypto API:
- HMAC-SHA1-based TOTP (RFC 6238)
- 8-byte big-endian counter
- Dynamic truncation for 6 or 8-digit codes
- Support for custom periods (15-120 seconds, default 30)
- `otpauth://` URI parsing and validation
- Label/tag normalization and grouping
- Entry sorting (pinned-alpha, custom, recent, period)
- Search and filtering

### `lib/vault.js`
Encryption and backup logic:
- Key derivation: PBKDF2 (150,000 iterations, SHA-256, 16-byte salt)
- Encryption: AES-256-GCM (12-byte IV, 16-byte auth tag)
- Backup format version 2 with SHA-256 checksum
- Automatic v1 → v2 migration
- Export/import with merge/replace support

## Build System

### Icon Generation
- Source: `icon.svg` (SVG format)
- Tools: `sharp` (PNG), ImageMagick `magick` (ICO)
- Outputs: PWA icons in `icons/`, extension icons in `extension/icons/`, `favicon.ico`

### Bundling
- Tool: esbuild
- Targets: Chrome 114, Safari 16, Firefox 115
- Format: ESM
- Entry points: `app.js` → `app.bundle.js`, `extension/popup.js` `extension/popup.bundle.js`
- No sourcemaps (configured in `scripts/build.mjs`)

### Version Management
- Single source of truth: `package.json` version
- Extension version must match: `extension/manifest.json` version
- CI verifies sync; fails fast if versions drift
- Release workflow triggered on version change in extension manifest

## Test Layout

### Unit Tests (`tests/unit/`)
- Framework: Vitest (Node.js environment)
- Scope: Shared `lib/` modules only
- Files: `otp.test.js`, `vault.test.js`
- Focus: Domain logic, crypto operations, parsing, validation

### E2E Tests (`tests/e2e/`)
- Framework: Playwright
- Browser: Chromium (installed via `scripts/prepare-release.mjs`)
- Coverage areas:
  - Web app flows: encryption, backup, XSS protection, rollback
  - Extension flows: popup operations, storage interactions
  - PWA/offline: service worker registration, offline mode
  - Backup safety: import/export, merge strategies
  - Visual regression: screenshot comparisons (Windows-pinned)

## Storage Key Versioning Convention

All storage keys use `_vN` suffix to enable migration and backward compatibility:

### Root App (localStorage)
- `personal_otp_vault_entries_v2` - Current entries format
- `personal_otp_vault_encrypted_v1` - Encrypted vault blob
- `personal_otp_vault_settings_v3` - User settings
- `personal_otp_vault_persist_warning_seen_v1` - Warning acknowledgment

### Extension (chrome.storage.local)
- `otp_extension_entries_v2` - Current entries format
- `otp_extension_encrypted_v1` - Encrypted vault blob
- `otp_extension_settings_v1` - Extension settings
- `otp_extension_ui_v1` - UI state

## Service Worker and Offline Support

- Service Worker: `sw.js` (caches `otp-vault-cache-v3`)
- PWA Manifest: `manifest.webmanifest`
- Offline Strategy: App shell caching with localStorage fallback
- Test Notes: Service workers enabled only in `offline.spec.js` (other Playwright tests block them for determinism)

## Extension Configuration

- MV3 Manifest: `extension/manifest.json`
- Permissions: `storage`, `clipboardRead`
- Background: Minimal service worker (`background.js`)
- Packaging: Automated via GitHub Actions workflow on version change
