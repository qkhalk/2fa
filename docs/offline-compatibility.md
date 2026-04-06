# Offline Compatibility Checklist

This project uses Service Worker + Cache Storage + Web App Manifest to provide a fast app-shell load after the first successful online visit.

## What We Can Rely On

- App shell caching for repeat visits after first load
- Local entry access from browser storage when offline
- Navigation fallback to the cached `index.html`
- Faster repeated launches after the service worker is installed

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
