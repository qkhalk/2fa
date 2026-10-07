---
title: "Phase 7: Polish — Dark Mode, Drag & Drop, Ring, A11y, i18n"
description: "3-state dark mode with snapshot regeneration, pointer-based drag & drop reorder, per-entry countdown ring, haptic on copy, a11y pass, and the lib/ i18n framework — both platforms."
status: todo
priority: P3
estimate: 18h
release: 0.2.0
---

# Phase 7: Polish — Dark Mode, Drag & Drop, Ring, A11y, i18n

## Context Links

- Research: `plans/2026-10-07-improvement-ideas-research.md` P1-P6
- Scout evidence: `reports/scout-report.md` sections 4, 6
- Depends on: Phases 1-6 (entry rendering, settings shape, and mutation flows are final before visual work)
- Parent plan: `plan.md`

## Overview

- **Priority:** P3 (pure UX; no security surface)
- **Status:** todo
- **Estimate note (red team):** re-budgeted 10h → 18h — the original 10h was not credible given the full scope: tokenizing the 1009-line `styles.css` behind a snapshot-neutrality gate, regenerating 14+ snapshot variants (web + extension × light + dark × changed DOM states), pointer-based DnD on two platforms, per-entry ring, haptics, an axe pass with fixes, and the i18n framework + refactor.
- **Description:** Ship the polish wave: dark mode with a System/Light/Dark toggle (default System via `prefers-color-scheme`), pointer-based drag & drop reorder (move buttons kept as the accessible fallback), a per-entry countdown ring, `navigator.vibrate` haptic on copy, a light accessibility pass (axe-core scan + fixes), and the i18n dictionary framework in `lib/` seeded with English strings. All features land in web app AND extension popup. Visual-regression snapshots are regenerated for both themes.

<!-- Updated: Red Team Review Session 1 - estimate re-budgeted 10h -> 18h with scope rationale -->

## Key Insights

- `styles.css` has no `prefers-color-scheme`/theme handling today (brainstorm P1 audit). Approach: light tokens on `:root` CSS variables; dark overrides in BOTH `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) }` (System) and `:root[data-theme="dark"]` (explicit). JS sets `data-theme` only for explicit Light/Dark; `system` removes the attribute. Setting `theme: 'system'|'light'|'dark'` rides the existing settings objects (additive, default 'system').
- Snapshot suites: `tests/e2e/web-visual.spec.js` + `tests/e2e/extension-visual.spec.js` with win32 snapshot dirs (scout §6). Default Playwright config blocks service workers; visual specs are unaffected by that. Any CSS change invalidates snapshots — regenerate BOTH suites after dark mode AND after drag-handle/ring DOM changes, for both themes (`--update-snapshots`).
- Reorder today: `moveEntry(entryId, direction)` (`app.js:917-924`) + `resequenceEntries` (`app.js:866`; popup mirrors at `extension/popup.js:251, 289`). Entries carry an `order` field (PDR FR3). Drag & drop = pointer events on a drag handle (HTML5 DnD is poor on mobile), committing through the SAME `resequenceEntries` + persist path — no new persistence semantics.
- Countdown: `tick()` (`app.js:1171-1176`) already recomputes every second into `updateAllEntries`; per-entry ring = SVG circle `stroke-dashoffset` derived from `period - (now % period)`. With mixed periods (15-120s) a per-entry ring fixes the current single global bar limitation (brainstorm P3). Update via inline `style` custom property per card — no innerHTML.
- Copy flow: `app.js:988-1007` (clipboard write + optional 30s clear + copy history). Haptic = `navigator.vibrate(20)` after successful write; no-op where unsupported (iOS Safari ignores it — acceptable, progressive enhancement).
- a11y: add `@axe-core/playwright` devDependency; scan both apps; fix critical findings (contrast, focus-visible, aria-labels on icon buttons, dialog semantics). Toast (Phase 5) gets `role="status"`.
- i18n framework (locked scope: framework + English catalog, not full migration): `lib/i18n.js` exports `t(key, params)` + `registerStrings(locale, dict)`; default locale 'en'; missing key falls back to key name. Both apps import it; seed the dictionary with English strings and refactor ONLY the unlock + settings areas to `t()` calls as the pattern-setter (scope tightened in Validation Session 2: toast/import strings stay hardcoded this release; their dictionary keys are reserved).

## Requirements

### Functional
- FR1: Theme: 3-state toggle (System/Light/Dark) in Settings on both platforms; default System; choice persists and applies without reload.
- FR2: Snapshots regenerated: web + extension visual suites pass in light AND dark for the new DOM/CSS.
- FR3: Drag & drop: pointer-based handle on each card (both platforms); live reorder preview while dragging; drop commits new order through `resequenceEntries` + persist; order survives reload; move-up/down buttons unchanged and still work.
- FR4: Per-entry countdown ring showing remaining fraction of that entry's period; degrades gracefully (hidden if reduced-motion or unsupported).
- FR5: Haptic feedback on successful copy (both platforms; silent no-op when `navigator.vibrate` is undefined).
- FR6: A11y pass: zero critical axe violations on main views (locked + unlocked + settings); keyboard-operable theme toggle, drag alternative exists (buttons), toasts announced.
- FR7: `lib/i18n.js` framework with `t`/`registerStrings`, English dictionary seeded (unlock + settings keys; toast/import keys reserved but unmigrated), and ONLY the unlock + settings areas reading strings via `t()` on both platforms (Validation Session 2 scope decision).

<!-- Updated: Validation Session 2 - i18n t() refactor scope tightened to unlock + settings areas only -->

### Non-functional
- NFR1: No new runtime dependencies (`@axe-core/playwright` is devDependency only; i18n is a lib module).
- NFR2: `prefers-reduced-motion` respected by ring animation and drag preview.
- NFR3: Ring/tick updates stay O(visible entries) with style-only writes.

## Architecture

**Theming:** tokens (`--bg`, `--fg`, `--card`, `--accent`, `--danger`, ...) declared once in `styles.css`; all components consume variables (Phases 2/5 already required variable-ready styles). Theme resolution: `document.documentElement.dataset.theme = theme === 'system' ? '' : theme`.

**Drag & drop:** `pointerdown` on handle → capture pointer → `pointermove` computes target index from card midpoints → translate previews → `pointerup` → reorder array + `resequenceEntries` + `persistEntries`. Same code shape duplicated per platform (DOM differs); pure reorder math (`computeDropIndex`) can live in lib for unit tests.

**i18n:** dictionaries are plain objects; `t('settings.autoLock', {minutes: 15})` does `{minutes}` interpolation; no locale detection in this phase (English only, per locked decision).

## Related Code Files

- Modify: `D:\2fa\styles.css` — token-ize all colors, dark blocks, drag-handle/ring/toast styles, focus-visible.
- Modify: `D:\2fa\index.html` + `D:\2fa\app.js` — theme toggle control, drag handles, ring SVG in the entry template, haptic call, a11y labels.
- Modify: `D:\2fa\extension\popup.html` + `extension/popup.js` + `extension/popup.css` (if separate) — parity.
- Create: `D:\2fa\lib\i18n.js` — framework + en dictionary.
- Modify: `D:\2fa\lib\otp.js` (or lib root) — pure reorder helper if extracted (`computeDropIndex`).
- Modify: `D:\2fa\package.json` — `@axe-core/playwright` devDependency.
- Modify: `D:\2fa\tests\e2e\web-visual.spec.js`, `tests\e2e\extension-visual.spec.js` — dual-theme snapshot scenarios; regenerate snapshot dirs.
- Create: `D:\2fa\tests\unit\i18n.test.js`; Create: `D:\2fa\tests\e2e\polish.spec.js` (theme persistence, DnD reorder persistence, ring attribute, axe scan).

## Implementation Steps

1. Theme tokens: refactor `styles.css` to variables (no visual change), verify snapshots STILL PASS pre-dark (`npx playwright test tests/e2e/web-visual.spec.js`) — this proves the refactor is neutral before adding dark values.
2. Add dark blocks + `theme` setting + toggle UI (both platforms) + no-reload application; regenerate snapshots for both themes in both suites (`--update-snapshots`), inspect diffs by eye before committing.
3. GitNexus `impact({target: "moveEntry"})`, `impact({target: "resequenceEntries"})`. Add drag handle + pointer logic (web + popup); commit through existing reorder path; unit-test `computeDropIndex`.
4. Countdown ring: add SVG circle to entry template; update `stroke-dashoffset` in `updateAllEntries` per entry period; reduced-motion opt-out.
5. Haptic: `navigator.vibrate(20)` in both copy flows after success.
6. a11y: `npm i -D @axe-core/playwright`; scan main pages; fix criticals (labels, contrast, focus, dialog roles, toast `role="status"`); re-scan to zero criticals.
7. i18n: write `lib/i18n.js` + tests; seed dictionary; refactor ONLY unlock/settings strings via `t()` on both platforms (Validation Session 2 — toast/import stay hardcoded).
8. E2E: `tests/e2e/polish.spec.js` — toggle theme → `data-theme` set + persists after reload; pointer-drag moves card and order persists; ring offset changes between two tick phases; axe scan clean.
9. `detect_changes()` sweep. Commits: `feat: add dark mode with system toggle`, `feat: add drag and drop reorder`, `feat: per entry countdown ring and copy haptic`, `fix: accessibility pass`, `feat: add i18n framework`.

## Todo

- [x] styles.css tokenized (snapshots pass unchanged first)
- [x] Dark mode + 3-state toggle both platforms; snapshots regenerated (light+dark, web+ext)
- [x] Pointer drag & drop both platforms; buttons fallback intact; unit test computeDropIndex
- [x] Per-entry countdown ring + reduced-motion opt-out
- [x] Haptic on copy both platforms
- [x] axe scan green (0 criticals) + fixes
- [x] lib/i18n.js + en dictionary + refactored areas + unit tests
- [x] polish.spec.js green
- [x] detect_changes() + Conventional Commits
- [x] Release gate: `npm run release:prepare -- 0.2.0` (with Phase 8)

## Success Criteria

- [x] `npx vitest run tests/unit/i18n.test.js` green; `npm run test:unit` green; `npm run build` green.
- [x] `npx playwright test tests/e2e/web-visual.spec.js` and `npx playwright test tests/e2e/extension-visual.spec.js` green with regenerated dual-theme snapshots.
- [x] `npx playwright test tests/e2e/polish.spec.js tests/e2e/app.spec.js tests/e2e/extension.spec.js` green.
- [x] Manual smoke: dark mode readable in both platforms; drag works with mouse AND touch; ring matches period; keyboard-only reorder possible via buttons.

## Risk Assessment

| Risk | L x I | Mitigation |
|------|-------|------------|
| Snapshot churn (regenerate masks real regressions) | M x M | Two-step: token refactor must pass OLD snapshots before dark values land; eyeball every diff |
| Pointer DnD fights scroll/touch gestures | M x M | `touch-action: none` on handle only; buttons remain full alternative; test on touch viewport |
| Tick-loop perf with per-entry ring on large vaults | L x M | Style-property writes only; O(n) per tick acceptable at personal-vault scale (<200 entries) |
| a11y fixes alter visuals → more snapshot churn | M x L | Bundle a11y fixes BEFORE final snapshot regeneration (order steps 2 and 6) |
| i18n refactor misses strings → mixed language UI | L x L | English-only catalog; t() falls back to key visibly, easy to grep |

## Security Considerations

- None new: no crypto, storage-format, or permission changes. Theme/DnD/i18n add zero trusted-input surface (strings are static catalog values).

## Next Steps

- Phase 8 finalizes docs and cuts 0.2.0.

## Rollback Plan

- Revert commits; theme setting field is inert on old code; snapshots return to previous committed state via git. No data changes.
