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
npm run build
npm run test:unit
npm run test:e2e
npm test
```

## Extension

The extension source lives in `extension/`. After building, load the folder as an unpacked extension in Chromium-based browsers.

## Contributing

Suggested flow:

1. Create a branch from `main`
2. Run `npm test`
3. Use Conventional Commits
4. Open a PR against the upstream repository
5. Use the PR template and include screenshots for UI changes

## Notes

- This repo keeps some local-only workflow files ignored from Git on purpose.
- The app is designed for trusted personal devices. Encrypted storage is strongly recommended when persistence is enabled.
- Safari/iOS offline notes are documented in `docs/offline-compatibility.md`.
