# Offline Compatibility Checklist

This project uses Service Worker + Cache Storage + Web App Manifest to provide a fast app-shell load after the first successful online visit.

## What We Can Rely On

- App shell caching for repeat visits after first load
- Local entry access from browser storage when offline
- Navigation fallback to the cached `index.html`
- Faster repeated launches after the service worker is installed
- Fully self-hosted shell: `jsqr` is bundled by esbuild and fonts are vendored woff2 files in `fonts/` — no CDN or third-party origins
- Camera QR scanning and Google Authenticator migration-QR import work offline

## Content Security Policy

The app ships a meta CSP: scripts, styles, images, and fonts are locked to
`'self'`; `connect-src` deliberately allows `'self' https:` so the QR-image-URL
import can fetch arbitrary user-supplied hosts (the feature is opt-in per
fetch). Because a meta CSP cannot deliver `frame-ancestors` (CSP3 ignores it in
meta), framing protection is a HOSTING concern: serve the PWA with
`X-Frame-Options: DENY` or a `Content-Security-Policy: frame-ancestors 'none'`
response header.

Release note: `sw.js` `CACHE_NAME` must be bumped in every release that changes
`app.bundle.js` — cache-first serving otherwise keeps stale bundles alive in
already-open tabs.

## Safari / iOS Checklist

- Test on Safari macOS
- Test on Safari iPhone
- Test on Safari iPad
- Re-test after adding the app to the Home Screen
- Re-test after backgrounding the app and reopening later
- Re-test after several weeks of no usage if offline persistence is business-critical

## Known WebKit Constraints

- Service worker support on Apple platforms exists, but behavior differs from Chromium in storage lifecycle and partitioning.
- Cache storage is subject to quota and eviction policies.
- WebKit can remove unused service workers and caches after a few weeks, so offline must be resilient to cache loss.

## Sources

- MDN Service Worker API: https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API
- MDN Cache API: https://developer.mozilla.org/en-US/docs/Web/API/Cache
- MDN Web App Manifest: https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Manifest/index.html
- WebKit "Workers at Your Service": https://webkit.org/blog/8090/workers-at-your-service/
