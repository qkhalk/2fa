<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:00c6fb,1:005bea&height=170&section=header&text=2FA%20Vault&fontSize=42&fontColor=ffffff&animation=fadeIn" width="100%" />

  <p>
    <img src="https://img.shields.io/github/languages/top/qkhalk/2fa?style=for-the-badge" alt="language" />
    <img src="https://img.shields.io/github/stars/qkhalk/2fa?style=for-the-badge&logo=github" alt="stars" />
    <img src="https://img.shields.io/github/license/qkhalk/2fa?style=for-the-badge" alt="license" />
  </p>
</div>

# Personal OTP Vault

Personal OTP Vault is a local-first TOTP/HOTP authenticator that runs as both a browser app and a Chrome-compatible extension popup. The project focuses on private device-side OTP generation, stricter import validation, encrypted local storage with optional biometric unlock, offline support, and practical recovery flows.

## Highlights

- Local-first TOTP and HOTP generation with Web Crypto (SHA-1/256/512, 6-8 digits, 15-120s periods)
- Strict `otpauth://` parsing to reduce false positives
- Manual entry, clipboard import, QR import, URL import, camera scan, and Google Authenticator migration-QR import with preview
- Optional encrypted storage using PBKDF2 (600k iterations) + AES-GCM, with automatic legacy re-encryption on unlock
- Optional biometric unlock via WebAuthn PRF (two-envelope DEK design; the passphrase always remains the recovery path)
- Auto-lock on idle, unlock throttling with exponential backoff, and undo-delete with a 10-minute tombstone
- Backup export/import with versioned checksum verification, plus a 30-day backup reminder and server time-drift check
- Grouping, sorting, tags, bulk actions, copy history, pointer drag & drop reorder, and per-entry countdown rings
- Dark mode with a System/Light/Dark toggle, vendored fonts, and no third-party runtime origins
- PWA support and a Chrome extension popup
- Unit tests, frontend e2e tests, extension e2e tests, accessibility scan, and CI

## Tech

- Vanilla HTML/CSS/JS with no build frameworks
- Shared domain logic in `lib/`: `otp.js` (TOTP/HOTP engine), `vault.js` (KDF envelope + DEK mode), `migration.js` (Google Authenticator otpauth-migration), `biometric.js` (WebAuthn PRF), `i18n.js` (English catalog)
- `jsqr` is the sole runtime-bundled dependency (installed via npm and bundled by esbuild — no CDN or third-party origin)
- Vendored woff2 fonts in `fonts/` keep the app shell fully self-hosted
- `esbuild` for bundling (targets Chrome 114+, Safari 16+, Firefox 115+)
- `Vitest` for unit tests (lib/ modules only)
- `Playwright` for browser, extension, offline, accessibility, and visual e2e tests

## Getting Started

```bash
npm install
npm run build
```

Open `index.html` through a local server or run:

```bash
npm run serve:test
```

Then visit `http://127.0.0.1:4173`.

## Scripts

```bash
npm run build:icons
npm run build
npm run test:unit
npm run test:e2e
npm test
```

`npm run build:icons` regenerates the app and extension PNG icon assets from `icon.svg`.

## Extension

The extension source lives in `extension/`. After building, load the folder as an unpacked extension in Chromium-based browsers.

## Icons And Favicon

- `icon.svg` is the single source for app branding.
- `npm run build:icons` generates PWA icons in `icons/` and extension icons in `extension/icons/`.
- The web app references `favicon.ico`, `icon.svg`, `icons/favicon-16x16.png`, `icons/favicon-32x32.png`, and `icons/apple-touch-icon.png` from `index.html`.
- `favicon.ico` is generated separately for broader browser compatibility.

If you update `icon.svg`, regenerate raster assets and the `.ico` file:

```bash
npm run build:icons
```

`npm run build:icons` now regenerates `favicon.ico` from the transparent PNG favicon sources so browser tabs do not get white corner fills.

## Contributing

See [Code Standards](docs/code-standards.md) for detailed conventions and development guidelines.

Suggested flow:

1. Create a branch from `main`
2. Run `npm test`
3. Use Conventional Commits
4. Open a PR against the upstream repository
5. Use the PR template and include screenshots for UI changes

## Release Automation

- GitHub Actions runs `.github/workflows/release.yml` automatically when `extension/manifest.json` changes on `main` or `master`.
- `package.json` and `extension/manifest.json` must keep the same version. CI and release automation fail fast if they drift.
- Use `npm run release:prepare -- <version>` to bump both files together before opening a release PR.
- If the extension `version` value changes, the workflow builds the extension bundle, creates tag `extension-v<version>`, and publishes a GitHub Release.
- The release attaches the packaged extension archive for that version.
- You can also trigger the same workflow manually from the Actions tab.
- Release checklist: if the release changes `app.bundle.js`, bump `CACHE_NAME` in `sw.js` in the same release — cache-first service-worker serving otherwise keeps stale bundles alive in already-open tabs.

## Documentation

- [Changelog](CHANGELOG.md) - Release notes and compatibility caveats
- [Codebase Summary](docs/codebase-summary.md) - Directory layout and architecture overview
- [Code Standards](docs/code-standards.md) - Conventions and development guidelines
- [System Architecture](docs/system-architecture.md) - Technical design and data flows
- [Project Overview & PDR](docs/project-overview-pdr.md) - Product requirements and goals
- [Project Roadmap](docs/project-roadmap.md) - Development themes and future proposals
- [Offline Compatibility](docs/offline-compatibility.md) - Safari/iOS PWA behavior

## Notes

- This repo keeps some local-only workflow files ignored from Git on purpose.
- The app is designed for trusted personal devices. Encrypted storage is strongly recommended when persistence is enabled.
- Version compatibility: vaults re-encrypted after 0.1.2 (600k PBKDF2) cannot be read by older app versions; HOTP entries in new backups degrade to TOTP in pre-0.1.3 versions; only a LIVE biometric-mode vault requires 0.1.5+ code to unlock — backups export in the standard passphrase-encrypted envelope and restore on any version.
- The backup checksum is integrity-only (unkeyed), not authenticity: anyone with the file can recompute it. Protect backup files like passwords.
- Framing protection (clickjacking) is a hosting concern: a meta CSP cannot deliver `frame-ancestors`, so serve the PWA with `X-Frame-Options: DENY` or a `CSP: frame-ancestors 'none'` header. The app's meta CSP intentionally allows `connect-src 'self' https:` so the QR-image-URL import can fetch user-supplied hosts; scripts and images stay locked to `'self'`.
- Duplicate detection matches entries by secret, digit count, and period — the label is not part of the match. A duplicate is skipped on manual add and during imports, so the same secret cannot be stored twice under different labels.
