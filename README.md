# Personal OTP Vault

Personal OTP Vault is a local-first TOTP manager that runs as both a browser app and a Chrome-compatible extension popup. The project focuses on private device-side OTP generation, stricter import validation, encrypted local storage, offline support, and practical recovery flows.

## Highlights

- Local-first TOTP generation with Web Crypto
- Strict `otpauth://` parsing to reduce false positives
- Manual entry, clipboard import, QR import, URL import, and camera scan
- Optional encrypted storage using PBKDF2 + AES-GCM
- Backup export/import with versioned checksum verification
- Grouping, sorting, tags, bulk actions, and copy history
- PWA support and a Chrome extension popup
- Unit tests, frontend e2e tests, extension e2e tests, and CI

## Tech

- Vanilla HTML/CSS/JS
- Shared OTP and vault logic in `lib/`
- `esbuild` for web and extension bundling
- `Vitest` for unit tests
- `Playwright` for browser and extension e2e tests

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

## Notes

- This repo keeps some local-only workflow files ignored from Git on purpose.
- The app is designed for trusted personal devices. Encrypted storage is strongly recommended when persistence is enabled.
- Safari/iOS offline notes are documented in `docs/offline-compatibility.md`.
