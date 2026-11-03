import jsQR from "jsqr";
import QRCode from "qrcode";
import {
  buildOtpAuthUri,
  compareEntries,
  computeDropIndex,
  entryMatchesQuery,
  extractMigrationUris,
  extractOtpAuthUri,
  extractOtpAuthUris,
  formatCode,
  generateHotp,
  generateTotp,
  getEntryGroup,
  getIssuerInitials,
  hasDuplicateEntry,
  nextOrderValueFrom,
  normalizeEntries,
  normalizeEntry,
  normalizeTags,
  parseLabelParts,
  parseOtpAuthUri,
  reportError,
  toUserMessage,
} from './lib/otp.js';
import { MAX_IMPORT_FILE_BYTES, parseThirdPartyImport } from './lib/importers.js';
import {
  MAX_STITCHED_ENTRIES,
  migrationToEntryCandidates,
  parseMigrationUri,
  stitchMigrationBatches,
} from './lib/migration.js';
import {
  assessPassphraseStrength,
  createEncryptedBackup,
  createPlainBackup,
  decryptVaultEntries,
  decryptVaultEntriesWithKey,
  encryptEntries,
  encryptEntriesWithDek,
  generateVaultDek,
  isDekEncryptedPayload,
  isLegacyEncryptedPayload,
  KDF_PARAMS_DEFAULT,
  normalizePassphrase,
  parseBackupFile,
  shouldWarnBackup,
  unwrapDekWithPassphrase,
  verifyBackupMac,
  wrapDekWithPassphrase,
} from './lib/vault.js';
import {
  deriveKek,
  enrollBiometricUnlock,
  fromB64u,
  prfCapable,
  runAssertCeremony,
  toB64u,
  unwrapDek,
  wrapDek,
} from './lib/biometric.js';
import { applyTranslations, resolveLocale, setLocale, t, translateStrengthAssessment } from './lib/i18n.js';

// app.js
var STORAGE_KEY = "personal_otp_vault_entries_v3";
var LEGACY_STORAGE_KEY = "personal_otp_vault_entries_v2";
var BIOMETRIC_KEY = "personal_otp_vault_biometric_v1";
var SETTINGS_KEY = "personal_otp_vault_settings_v3";
var WARNING_KEY = "personal_otp_vault_persist_warning_seen_v1";
var ENCRYPTED_VAULT_KEY = "personal_otp_vault_encrypted_v1";
var UPGRADE_SENTINEL_KEY = "personal_otp_vault_legacy_upgrade_hash";
var form = document.getElementById("otp-form");
var labelInput = document.getElementById("label");
var secretInput = document.getElementById("secret");
var tagsInput = document.getElementById("tags");
var digitsInput = document.getElementById("digits");
var periodInput = document.getElementById("period");
var entryTypeSelect = document.getElementById("entry-type");
var counterInput = document.getElementById("counter");
var counterField = document.getElementById("counter-field");
var algorithmSelect = document.getElementById("algorithm");
var uriInput = document.getElementById("uri");
var parseUriBtn = document.getElementById("parse-uri");
var importGaBtn = document.getElementById("import-ga");
var importClipboardBtn = document.getElementById("import-clipboard");
var qrFileInput = document.getElementById("qr-file");
var qrUrlInput = document.getElementById("qr-url");
var importQrUrlBtn = document.getElementById("import-qr-url");
var startCameraBtn = document.getElementById("start-camera");
var stopCameraBtn = document.getElementById("stop-camera");
var cameraPreview = document.getElementById("camera-preview");
var clearAllBtn = document.getElementById("clear-all");
var importStatus = document.getElementById("import-status");
var searchInput = document.getElementById("search");
var sortSelect = document.getElementById("sort-select");
var groupSelect = document.getElementById("group-select");
var entriesRoot = document.getElementById("entries");
var template = document.getElementById("entry-template");
var timerValue = document.getElementById("timer-value");
var timerBar = document.getElementById("timer-bar");
var offlineChip = document.getElementById("offline-chip");
var summaryTotal = document.getElementById("summary-total");
var summaryPinned = document.getElementById("summary-pinned");
var summaryGroups = document.getElementById("summary-groups");
var summaryStorage = document.getElementById("summary-storage");
var workspaceHeading = document.getElementById("workspace-heading");
var bulkBar = document.getElementById("bulk-bar");
var bulkSummary = document.getElementById("bulk-summary");
var bulkTagInput = document.getElementById("bulk-tag-input");
var bulkTagApplyBtn = document.getElementById("bulk-tag-apply");
var bulkRemoveBtn = document.getElementById("bulk-remove");
var onboardingPanel = document.getElementById("onboarding");
var copyHistoryRoot = document.getElementById("copy-history");
var toastRegion = document.getElementById("toast-region");
var persistToggle = document.getElementById("persist-toggle");
var encryptToggle = document.getElementById("encrypt-toggle");
var unlockOnLoadToggle = document.getElementById("unlock-on-load");
var blurCodesToggle = document.getElementById("blur-codes-toggle");
var screenshotSafeToggle = document.getElementById("screenshot-safe-toggle");
var clearClipboardToggle = document.getElementById("clear-clipboard-toggle");
var encryptionFields = document.getElementById("encryption-fields");
var passphraseGuidance = document.getElementById("passphrase-guidance");
var vaultPassphraseInput = document.getElementById("vault-passphrase");
var vaultPassphraseConfirmInput = document.getElementById("vault-passphrase-confirm");
var changePassphraseBtn = document.getElementById("change-passphrase-btn");
var saveSettingsBtn = document.getElementById("save-settings");
var settingsStatus = document.getElementById("settings-status");
var exportBackupBtn = document.getElementById("export-backup");
var importBackupInput = document.getElementById("import-backup");
var installAppBtn = document.getElementById("install-app");
var lockAppBtn = document.getElementById("lock-app");
var unlockPanel = document.getElementById("unlock-panel");
var unlockPassphraseInput = document.getElementById("unlock-passphrase");
var unlockBtn = document.getElementById("unlock-btn");
var unlockStatus = document.getElementById("unlock-status");
var privacyDialog = document.getElementById("privacy-dialog");
var unlockForm = document.getElementById("unlock-form");
var settingsForm = document.getElementById("settings-form");
var importPreviewForm = document.getElementById("import-preview-form");
var backupReviewForm = document.getElementById("backup-review-form");
var editEntryForm = document.getElementById("edit-entry-form");
var importDialog = document.getElementById("import-dialog");
var importPreviewTitle = document.getElementById("import-preview-title");
var importPreviewStatus = document.getElementById("import-preview-status");
var importPreviewTagsInput = document.getElementById("import-preview-tags");
var importPreviewList = document.getElementById("import-preview-list");
var backupReviewDialog = document.getElementById("backup-review-dialog");
var backupReviewSummary = document.getElementById("backup-review-summary");
var backupImportMode = document.getElementById("backup-import-mode");
var backupPassphraseRow = document.getElementById("backup-passphrase-row");
var backupImportPassphraseInput = document.getElementById("backup-import-passphrase");
var backupReviewStatus = document.getElementById("backup-review-status");
var editEntryDialog = document.getElementById("edit-entry-dialog");
var editEntryIdInput = document.getElementById("edit-entry-id");
var editLabelInput = document.getElementById("edit-label");
var editSecretInput = document.getElementById("edit-secret");
var editTagsInput = document.getElementById("edit-tags");
var editDigitsInput = document.getElementById("edit-digits");
var editPeriodInput = document.getElementById("edit-period");
var editCounterField = document.getElementById("edit-counter-field");
var editCounterInput = document.getElementById("edit-counter");
var editAlgorithmSelect = document.getElementById("edit-algorithm");
var editEntryStatus = document.getElementById("edit-entry-status");
var changePassphraseDialog = document.getElementById("change-passphrase-dialog");
var changePassphraseForm = document.getElementById("change-passphrase-form");
var currentPassphraseInput = document.getElementById("current-passphrase");
var newPassphraseInput = document.getElementById("new-passphrase");
var newPassphraseConfirmInput = document.getElementById("new-passphrase-confirm");
var changePassphraseStatus = document.getElementById("change-passphrase-status");
var confirmDialog = document.getElementById("confirm-dialog");
var confirmForm = document.getElementById("confirm-form");
var confirmTitle = document.getElementById("confirm-title");
var confirmMessage = document.getElementById("confirm-message");
var confirmAcceptBtn = document.getElementById("confirm-accept");
var confirmCallback = null;
var qrExportDialog = document.getElementById("qr-export-dialog");
var qrExportCanvas = document.getElementById("qr-export-canvas");
var qrExportTitle = document.getElementById("qr-export-title");
var qrExportStatus = document.getElementById("qr-export-status");
var copyQrUriBtn = document.getElementById("copy-qr-uri");
var downloadQrBtn = document.getElementById("download-qr");
var importAppsInput = document.getElementById("import-app-file");
var languageSelect = document.getElementById("language-select");
var qrExportUri = "";
document.getElementById("debug-toggle")?.remove();
document.getElementById("debug-panel")?.remove();
var debugList = null;
var defaultSettings = {
  persist: false,
  encrypt: false,
  unlockOnLoad: false,
  blurCodes: false,
  screenshotSafe: false,
  clearClipboard: false,
  autoLockMinutes: 15,
  timeDriftCheck: false,
  theme: "system",
  locale: "system",
  sortBy: "pinned-alpha",
  groupBy: "none"
};
var settings = loadSettings();
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var currentPassphrase = "";
var heldDek = null;         // CryptoKey held between unlock and lock (biometric/DEK mode)
var dekEnvelopeMeta = null; // { salt, kdf, dek } — stable across DEK-mode saves
var biometricCapable = false;
var staleVaultTab = false;
var UNLOCK_GUARD_KEY = "personal_otp_vault_unlock_guard_v1";
var UNDO_TOMBSTONE_KEY = "personal_otp_vault_undo_tombstone_v1";
var UNDO_TOMBSTONE_TTL_MS = 10 * 60 * 1000;
var UNDO_TOAST_MS = 10000;
var lastActivity = Date.now();
var operationDepth = 0;
var lastThrottleMessage = "";
var undoState = null; // { items: [{entry, index}], toastNode, timer }
var cameraStream = null;
var cameraScanTimer = null;
var deferredInstallPrompt = null;
var cameraDetection = { uri: "", hits: 0 };
var selectedEntryIds = /* @__PURE__ */ new Set();
var copyHistory = [];
var debugEvents = [];
var importPreviewState = null;
var backupImportState = null;
initialize();
// Locale resolution + static markup translation. data-i18n attributes in the
// HTML carry the static strings; re-run after a language change.
function applyLocale() {
  setLocale(resolveLocale(settings.locale));
  applyTranslations(document);
  // Dynamic surfaces hold translated strings in memory; re-render them so a
  // language switch never leaves stale mixed-language text on screen.
  renderEntries();
  renderBulkBar();
  renderCopyHistory();
  updateDataSafetyBanners();
  renderBiometricControls();
}

function initialize() {
  applyLocale();
  syncSettingsUI();
  applyVisualSettings();
  loadVaultOnStartup();
  renderEntries();
  renderCopyHistory();
  renderDebugFeed();
  renderBulkBar();
  updateDataSafetyBanners();
  tick();
  bindEvents();
  setInterval(tick, 1e3);
  registerPwaSupport();
  prfCapable().then((capable) => {
    biometricCapable = capable;
    renderBiometricControls();
  }).catch(() => {
    biometricCapable = false;
    renderBiometricControls();
  });
  logDebug("info", "Vault initialized");
}
function loadSettings() {
  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) return { ...defaultSettings };
    return { ...defaultSettings, ...JSON.parse(raw) };
  } catch (error) {
    reportError("Failed to load settings", error);
    return { ...defaultSettings };
  }
}
function saveSettings() {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
}
function syncSettingsUI() {
  persistToggle.checked = settings.persist;
  encryptToggle.checked = settings.encrypt;
  const autoLockSelect = document.getElementById("auto-lock-select");
  if (autoLockSelect) autoLockSelect.value = String(settings.autoLockMinutes);
  const themeSelect = document.getElementById("theme-select");
  if (themeSelect) themeSelect.value = settings.theme || "system";
  if (languageSelect) languageSelect.value = settings.locale || "system";
  const timeDriftToggle = document.getElementById("time-drift-toggle");
  if (timeDriftToggle) timeDriftToggle.checked = Boolean(settings.timeDriftCheck);
  const mustUnlockOnLoad = settings.persist && settings.encrypt;
  const hasExistingEncryptedVault = mustUnlockOnLoad && Boolean(currentPassphrase || localStorage.getItem(ENCRYPTED_VAULT_KEY));
  unlockOnLoadToggle.checked = mustUnlockOnLoad ? true : settings.unlockOnLoad;
  unlockOnLoadToggle.disabled = mustUnlockOnLoad;
  blurCodesToggle.checked = settings.blurCodes;
  screenshotSafeToggle.checked = settings.screenshotSafe;
  clearClipboardToggle.checked = settings.clearClipboard;
  sortSelect.value = settings.sortBy;
  groupSelect.value = settings.groupBy;
  encryptionFields.classList.toggle("hidden", !settings.encrypt || hasExistingEncryptedVault);
  passphraseGuidance?.classList.toggle("hidden", !hasExistingEncryptedVault);
  const canChangePassphrase = settings.persist && settings.encrypt;
  changePassphraseBtn?.classList.toggle("hidden", !canChangePassphrase);
  if (lockAppBtn) {
    lockAppBtn.classList.toggle("hidden", !settings.encrypt);
  }
  renderBiometricControls();
}
function applyVisualSettings() {
  document.body.classList.toggle("blur-codes", settings.blurCodes);
  document.body.classList.toggle("screenshot-safe", settings.screenshotSafe);
  // Theme resolution (FR1): explicit Light/Dark sets data-theme; System
  // removes the attribute so prefers-color-scheme decides.
  const theme = settings.theme || "system";
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }
}
// Phase 6 UI gating: the settings section is visible iff the runtime proves
// PRF capability; the unlock button additionally requires an enrolled record.
function renderBiometricControls() {
  const section = document.getElementById("biometric-settings");
  const record = readBiometricRecord();
  if (section) {
    section.classList.toggle("hidden", !biometricCapable);
    const enrollBtn = document.getElementById("enroll-biometric-btn");
    const disenrollBtn = document.getElementById("disenroll-biometric-btn");
    const statusLine = document.getElementById("biometric-status-line");
    if (enrollBtn) {
      enrollBtn.classList.toggle("hidden", !biometricCapable || Boolean(record) || !settings.persist || !settings.encrypt);
    }
    if (disenrollBtn) {
      disenrollBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
    if (statusLine) {
      statusLine.textContent = !biometricCapable
        ? ""
        : record
          ? t("settings.biometricEnrolled")
          : settings.persist && settings.encrypt
            ? t("settings.biometricAvailable")
            : t("settings.biometricNeedsEncryption");
    }
  }
  const unlockBiometricBtn = document.getElementById("biometric-unlock-btn");
  if (unlockBiometricBtn) {
    unlockBiometricBtn.classList.toggle("hidden", !biometricCapable || !record);
  }
}

function renderWorkspaceSummary() {
  if (!summaryTotal) return;
  const groups = getEntryGroups().filter(([, groupEntries]) => groupEntries.length > 0);
  summaryTotal.textContent = String(entries.length);
  summaryPinned.textContent = String(entries.filter((entry) => entry.pinned).length);
  summaryGroups.textContent = String(settings.groupBy === "none" ? 1 : Math.max(groups.length, 0));

  const isLocked = !unlockPanel.classList.contains("hidden") && settings.encrypt;
  let storageText = settings.persist ? settings.encrypt ? t("workspace.storageEncrypted") : t("workspace.storageDevice") : t("workspace.storageSession");
  if (isLocked) {
    storageText += t("workspace.storageLocked");
  }
  summaryStorage.textContent = storageText;
}

function renderConnectionState() {
  if (!offlineChip) return;
  const online = navigator.onLine !== false;
  offlineChip.textContent = online ? t("workspace.online") : t("workspace.offlineReady");
  offlineChip.classList.toggle("offline", !online);
}
function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success", "warning");
  if (tone) node.classList.add(tone);
}
function showToast(title, message = "", tone = "success") {
  if (!toastRegion) return;
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  const strong = document.createElement("strong");
  strong.textContent = title;
  toast.appendChild(strong);
  if (message) {
    const paragraph = document.createElement("p");
    paragraph.textContent = message;
    toast.appendChild(paragraph);
  }
  toastRegion.appendChild(toast);
  window.setTimeout(() => toast.remove(), 4200);
}
function setImportStatus(message, tone = "") {
  setStatus(importStatus, message, tone);
  if (message) showToast(tone === "error" ? t("toast.importTitle") : t("toast.vaultTitle"), message, tone || "success");
}
function setSettingsStatus(message, tone = "") {
  setStatus(settingsStatus, message, tone);
  if (message) showToast(tone === "error" ? t("toast.settingsTitle") : t("toast.vaultTitle"), message, tone || "success");
}
function setChangePassphraseStatus(message, tone = "") {
  setStatus(changePassphraseStatus, message, tone);
}
function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}
function renderPassphraseStrength(input, meterRoot) {
  if (!input || !meterRoot) return;
  const assessment = translateStrengthAssessment(assessPassphraseStrength(input.value));
  meterRoot.classList.toggle("hidden", input.value.length === 0);
  const fill = meterRoot.querySelector(".strength-fill");
  if (fill) fill.dataset.score = String(assessment.score);
  const label = meterRoot.querySelector(".strength-label");
  if (label) label.textContent = assessment.label;
  const warnings = meterRoot.querySelector(".strength-warnings");
  if (warnings) warnings.textContent = assessment.warnings.join(" ");
}
function bindPassphraseStrengthMeters() {
  const unlockMeter = document.getElementById("unlock-passphrase-strength");
  const setMeter = document.getElementById("set-passphrase-strength");
  unlockPassphraseInput?.addEventListener("input", () => renderPassphraseStrength(unlockPassphraseInput, unlockMeter));
  vaultPassphraseInput?.addEventListener("input", () => renderPassphraseStrength(vaultPassphraseInput, setMeter));
  vaultPassphraseConfirmInput?.addEventListener("input", () => renderPassphraseStrength(vaultPassphraseConfirmInput, setMeter));
}
function logDebug(level, message, detail = "") {
  debugEvents = [{
    level,
    message,
    detail: detail ? String(detail) : "",
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  }, ...debugEvents].slice(0, 18);
  renderDebugFeed();
}
function hasSeenPersistWarning() {
  return localStorage.getItem(WARNING_KEY) === "true";
}
function markPersistWarningSeen() {
  localStorage.setItem(WARNING_KEY, "true");
}
function loadVaultOnStartup() {
  if (!settings.persist) {
    entries = [];
    setLocked(false);
    return;
  }
  if (settings.encrypt) {
    const encryptedPayload = localStorage.getItem(ENCRYPTED_VAULT_KEY);
    const legacyPlainEntries = loadPlainEntries();
    settings.unlockOnLoad = true;
    reconcileOrphanedBiometricRecord();
    if (!encryptedPayload && legacyPlainEntries.length > 0) {
      entries = legacyPlainEntries;
      setLocked(false);
      offerUndoFromTombstone();
      return;
    }
    entries = [];
    setLocked(Boolean(encryptedPayload));
    return;
  }
  entries = loadPlainEntries();
  setLocked(false);
  offerUndoFromTombstone();
}
function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  lockAppBtn.disabled = locked;
  form.querySelectorAll("input, button, select, textarea").forEach((el) => {
    el.disabled = locked;
  });
  searchInput.disabled = locked;
  sortSelect.disabled = locked;
  groupSelect.disabled = locked;
  changePassphraseBtn?.classList.toggle("hidden", locked || !settings.persist || !settings.encrypt);
  renderBiometricControls();
}
function markVaultStale() {
  if (staleVaultTab || !settings.persist) return;
  staleVaultTab = true;
  document.getElementById("vault-stale-banner")?.classList.remove("hidden");
}
// The single lock path (auto-lock idle expiry AND the manual "Lock Vault"
// button): clears the passphrase and sensitive in-memory state. The manual
// button historically left currentPassphrase resident — this fixes that.
function lockVault() {
  currentPassphrase = "";
  heldDek = null;
  dekEnvelopeMeta = null;
  if (unlockPassphraseInput) unlockPassphraseInput.value = "";
  setUnlockStatus("");
  entries = [];
  selectedEntryIds.clear();
  if (settings.clearClipboard) {
    copyHistory = [];
    renderCopyHistory();
  }
  stopCameraScan();
  if (importPreviewState) {
    importPreviewState = null;
    importDialog?.close?.();
  }
  for (const id of ["add-dialog", "settings-dialog", "history-dialog"]) {
    const sheet = document.getElementById(id);
    if (sheet?.open) sheet.close();
  }
  clearPendingUndo();
  purgeUndoTombstone();
  hideDriftBanner();
  setLocked(true);
  renderEntries();
  renderBulkBar();
}
function noteActivity() {
  lastActivity = Date.now();
}
function bindAutoLockActivity() {
  let lastNoted = 0;
  const throttled = () => {
    const now = Date.now();
    if (now - lastNoted < 1000) return;
    lastNoted = now;
    noteActivity();
  };
  document.addEventListener("pointermove", throttled);
  document.addEventListener("keydown", throttled);
  // No visibilitychange reset: returning to the tab must never extend the
  // session — real time since lastActivity keeps counting while hidden.
}
function vaultBusy() {
  return operationDepth > 0;
}
function readUnlockGuard() {
  try {
    const raw = localStorage.getItem(UNLOCK_GUARD_KEY);
    if (!raw) return { attempts: 0, lockedUntil: 0 };
    const parsed = JSON.parse(raw);
    return { attempts: Number(parsed.attempts) || 0, lockedUntil: Number(parsed.lockedUntil) || 0 };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}
function writeUnlockGuard(guard) {
  localStorage.setItem(UNLOCK_GUARD_KEY, JSON.stringify(guard));
}
function unlockBackoffSeconds(attempts) {
  return Math.min(60, 2 ** Math.max(0, attempts - 3));
}
function bindMultiTabGuard() {
  window.addEventListener("storage", (event) => {
    if (event.key !== ENCRYPTED_VAULT_KEY && event.key !== STORAGE_KEY && event.key !== LEGACY_STORAGE_KEY) return;
    if (event.newValue === event.oldValue) return;
    markVaultStale();
  });
  const banner = document.getElementById("vault-stale-banner");
  banner?.querySelector("#vault-stale-reload")?.addEventListener("click", () => window.location.reload());
  banner?.querySelector("#vault-stale-dismiss")?.addEventListener("click", () => banner.classList.add("hidden"));
}
// Reads the v3 plaintext store, falling back to the legacy v2 key only while
// v3 is absent (first load after the upgrade). v2 is never deleted — stale
// tabs and older bundles may still read/write it — but once v3 exists it is
// authoritative, so v2 data cannot resurrect entries deleted after migration.
function readPlainEntriesRaw() {
  const v3Raw = localStorage.getItem(STORAGE_KEY);
  if (v3Raw) return normalizeEntries(JSON.parse(v3Raw));
  const v2Raw = localStorage.getItem(LEGACY_STORAGE_KEY);
  if (v2Raw) return normalizeEntries(JSON.parse(v2Raw));
  return [];
}
function loadPlainEntries() {
  try {
    const parsed = readPlainEntriesRaw();
    return parsed.every((entry) => !entry.order) ? resequenceEntries(parsed) : parsed;
  } catch (error) {
    reportError("Failed to load plain entries", error);
    return [];
  }
}
function savePlainEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}
function snapshotPersistedVaultArtifacts() {
  return {
    plainEntries: localStorage.getItem(STORAGE_KEY),
    legacyPlainEntries: localStorage.getItem(LEGACY_STORAGE_KEY),
    encryptedEntries: localStorage.getItem(ENCRYPTED_VAULT_KEY)
  };
}
function restorePersistedVaultArtifacts(snapshot) {
  if (snapshot.plainEntries === null) {
    localStorage.removeItem(STORAGE_KEY);
  } else {
    localStorage.setItem(STORAGE_KEY, snapshot.plainEntries);
  }
  if (snapshot.legacyPlainEntries === null) {
    localStorage.removeItem(LEGACY_STORAGE_KEY);
  } else {
    localStorage.setItem(LEGACY_STORAGE_KEY, snapshot.legacyPlainEntries);
  }
  if (snapshot.encryptedEntries === null) {
    localStorage.removeItem(ENCRYPTED_VAULT_KEY);
  } else {
    localStorage.setItem(ENCRYPTED_VAULT_KEY, snapshot.encryptedEntries);
  }
}
function clearPersistedEntries() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(LEGACY_STORAGE_KEY);
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
  removeBiometricRecord();
  heldDek = null;
  dekEnvelopeMeta = null;
}
function entryKey(entry) {
  return `${entry.secret}::${entry.digits}::${entry.period}`;
}
function getVisibleEntries() {
  return [...entries].filter((entry) => entryMatchesQuery(entry, searchInput.value || "")).sort((a, b) => compareEntries(a, b, settings.sortBy));
}
function getEntryGroups() {
  const visibleEntries = getVisibleEntries();
  const groups = /* @__PURE__ */ new Map();
  for (const entry of visibleEntries) {
    const name = getEntryGroup(entry, settings.groupBy);
    if (!groups.has(name)) groups.set(name, []);
    groups.get(name).push(entry);
  }
  if (settings.groupBy === "none") return [["All Entries", visibleEntries]];
  return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right, void 0, { sensitivity: "base" }));
}
function setOnboardingVisibility() {
  onboardingPanel?.classList.add("hidden");
}
function renderTagRow(node, entry) {
  const tagRow = node.querySelector(".entry-tag-row");
  if (!tagRow) return;
  tagRow.innerHTML = "";
  for (const tag of entry.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag-chip";
    chip.textContent = tag;
    tagRow.appendChild(chip);
  }
}
function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  copyHistoryRoot.innerHTML = "";
  if (copyHistory.length === 0) {
    const empty = document.createElement("li");
    empty.className = "history-empty";
    empty.textContent = t("history.empty");
    copyHistoryRoot.appendChild(empty);
  } else {
    for (const item of copyHistory) {
      const row = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = item.label;
      const span = document.createElement("span");
      span.textContent = `${item.code} • ${item.at}`;
      row.append(strong, span);
      copyHistoryRoot.appendChild(row);
    }
  }
  const historyCount = document.getElementById("history-count");
  if (historyCount) historyCount.textContent = String(copyHistory.length);
}
function renderDebugFeed() {
  if (!debugList) return;
  debugList.innerHTML = "";
  if (debugEvents.length === 0) {
    const row = document.createElement("li");
    const strong = document.createElement("strong");
    strong.textContent = "No debug events yet";
    const span = document.createElement("span");
    span.textContent = "Import, backup, and vault operations will appear here.";
    row.append(strong, span);
    debugList.appendChild(row);
    return;
  }
  for (const event of debugEvents) {
    const row = document.createElement("li");
    const strong = document.createElement("strong");
    strong.textContent = `[${event.level}] ${event.message}`;
    const span = document.createElement("span");
    span.textContent = `${event.at}${event.detail ? ` • ${event.detail}` : ""}`;
    row.append(strong, span);
    debugList.appendChild(row);
  }
}
function renderBulkBar() {
  if (!bulkBar || !bulkSummary) return;
  const selectedCount = selectedEntryIds.size;
  bulkBar.classList.toggle("hidden", selectedCount === 0);
  bulkSummary.textContent = t("workspace.selectedCount", { count: selectedCount });
}

// Restores manual-order numbers only when a decrypt path produced entries
// without them (mirrors extension/popup.js).
function resequenceIfUnordered(decrypted) {
  return decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
}
function resequenceEntries(items) {
  return items.map((entry, index) => ({
    ...entry,
    order: index + 1
  }));
}

// HOTP counter-increment-on-use: persists counter+1 through the encrypted
// vault path. A failed persist leaves the stored counter behind the code the
// user already consumed — surface it instead of silently regressing (FR9).
async function consumeHotpCounter(entry, action) {
  if (entry.type !== "hotp") return;
  try {
    await replaceEntries(entries.map((item) => item.id === entry.id ? { ...item, counter: item.counter + 1 } : item));
  } catch (error) {
    reportError(`HOTP counter persist failed (${action})`, error);
    showToast(
      "HOTP counter",
      t("vault.hotpSaveFailed"),
      "error"
    );
  }
}

// --- Undo delete with pending-purge tombstone (Phase 5, FR1) ---

// The tombstone rides the vault's own persistence semantics: written only
// when persistence is on, encrypted with the held passphrase when the vault
// is encrypted. Auto-purged after 10 minutes; purged immediately on undo,
// lock, and replacement by a newer deletion.
async function writeUndoTombstone(items) {
  try {
    if (!settings.persist) return;
    const tombstone = { at: Date.now(), indexes: items.map((item) => item.index) };
    const deletedEntries = items.map((item) => item.entry);
    if (settings.encrypt && currentPassphrase) {
      tombstone.vault = await encryptEntries(deletedEntries, currentPassphrase);
    } else if (settings.encrypt && heldDek && dekEnvelopeMeta) {
      // Biometric-only session: encrypt under the held DEK (no passphrase).
      tombstone.dekVault = await encryptEntriesWithDek(deletedEntries, heldDek, dekEnvelopeMeta);
    } else {
      tombstone.entries = deletedEntries;
    }
    localStorage.setItem(UNDO_TOMBSTONE_KEY, JSON.stringify(tombstone));
  } catch (error) {
    reportError("Undo tombstone write failed", error);
  }
}

function purgeUndoTombstone() {
  localStorage.removeItem(UNDO_TOMBSTONE_KEY);
}

async function readLiveUndoTombstone() {
  try {
    const raw = localStorage.getItem(UNDO_TOMBSTONE_KEY);
    if (!raw) return null;
    const tombstone = JSON.parse(raw);
    if (!tombstone || typeof tombstone.at !== "number" || Date.now() - tombstone.at > UNDO_TOMBSTONE_TTL_MS) {
      purgeUndoTombstone();
      return null;
    }
    let deletedEntries = tombstone.entries || [];
    if (tombstone.dekVault) {
      if (!heldDek) {
        purgeUndoTombstone();
        return null;
      }
      deletedEntries = await decryptVaultEntriesWithKey(heldDek, tombstone.dekVault);
    } else if (tombstone.vault) {
      deletedEntries = await decryptVaultEntries(tombstone.vault, currentPassphrase);
    }
    if (!Array.isArray(deletedEntries) || deletedEntries.length === 0) {
      purgeUndoTombstone();
      return null;
    }
    const indexes = Array.isArray(tombstone.indexes) ? tombstone.indexes : [];
    return deletedEntries.map((entry, position) => ({ entry, index: indexes[position] ?? position }));
  } catch (error) {
    reportError("Undo tombstone read failed", error);
    purgeUndoTombstone();
    return null;
  }
}

function clearPendingUndo() {
  if (!undoState) return;
  if (undoState.timer) clearTimeout(undoState.timer);
  undoState.toastNode?.remove();
  undoState = null;
}

async function undoDelete(items) {
  clearPendingUndo();
  purgeUndoTombstone();
  let reinserted = 0;
  const nextEntries = [...entries];
  for (const { entry, index } of items) {
    // If the same id was re-added meanwhile, keep the current entry (no-op).
    if (nextEntries.some((existing) => existing.id === entry.id)) continue;
    nextEntries.splice(Math.min(Math.max(index, 0), nextEntries.length), 0, entry);
    reinserted += 1;
  }
  if (reinserted === 0) {
    setImportStatus(t("import.nothingToUndo"), "warning");
    return;
  }
  await replaceEntries(nextEntries);
  setImportStatus(reinserted === 1 ? t("import.restoredOne") : t("import.restoredMany", { count: reinserted }), "success");
}

// Shows the 10s undo toast and persists the tombstone so undo survives a
// reload (web) or popup close (extension). A newer deletion replaces the
// pending one (single undo buffer).
async function offerUndoDelete(items) {
  clearPendingUndo();
  await writeUndoTombstone(items);

  const toast = document.createElement("div");
  toast.className = "toast undo";
  toast.setAttribute("role", "status");
  const strong = document.createElement("strong");
  strong.textContent = items.length === 1 ? t("undo.entryRemovedOne") : t("undo.entryRemovedMany", { count: items.length });
  const undoBtn = document.createElement("button");
  undoBtn.type = "button";
  undoBtn.className = "btn small";
  undoBtn.textContent = t("common.undo");
  undoBtn.addEventListener("click", () => undoDelete(items));
  toast.append(strong, undoBtn);
  toastRegion.appendChild(toast);

  const timer = setTimeout(() => {
    toast.remove();
    if (undoState?.toastNode === toast) {
      purgeUndoTombstone();
      undoState = null;
    }
  }, UNDO_TOAST_MS);
  undoState = { items, toastNode: toast, timer };
}

// Called after unlock (and on unlocked startup): a tombstone from a previous
// session offers undo before its 10-minute expiry.
async function offerUndoFromTombstone() {
  if (undoState) return;
  const items = await readLiveUndoTombstone();
  if (items) await offerUndoDelete(items);
}

// --- Backup reminder + time drift banners (Phase 5, FR2/FR3) ---

function setBannerVisible(id, visible) {
  document.getElementById(id)?.classList.toggle("hidden", !visible);
}
function hideDriftBanner() {
  setBannerVisible("drift-banner", false);
}
function renderBackupReminder() {
  const warn = shouldWarnBackup(settings, entries.length);
  setBannerVisible("backup-reminder-banner", warn);
  const line = document.getElementById("last-export-line");
  if (!line) return;
  const lastBackupAt = Number(settings.lastBackupAt);
  if (!Number.isFinite(lastBackupAt) || lastBackupAt <= 0) {
    line.textContent = t("backup.lastExportNever");
    return;
  }
  const days = Math.floor((Date.now() - lastBackupAt) / 86400000);
  const exportAge = days === 0 ? t("backup.lastExportToday")
    : days === 1 ? t("backup.lastExportOneDay")
    : t("backup.lastExportDays", { days });
  const checksum = settings.lastBackupHash ? t("backup.lastExportChecksum", { hash: String(settings.lastBackupHash).slice(0, 8) }) : "";
  line.textContent = `${exportAge}${checksum}${t("backup.lastExportSuffix")}`;
}
function updateDataSafetyBanners() {
  renderBackupReminder();
}

function parseHttpDateHeader(value) {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}
function parseTraceTimestamp(text) {
  const match = /(?:^|\n)ts=([0-9.]+)/.exec(text || "");
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds * 1000 : null;
}
function computeSkewMs(serverMs) {
  if (!Number.isFinite(serverMs)) return null;
  return Math.abs(Date.now() - serverMs);
}
function showDriftBanner(skewMs) {
  const banner = document.getElementById("drift-banner");
  if (!banner) return;
  banner.querySelector("#drift-skew").textContent = `${(skewMs / 1000).toFixed(1)}s`;
  setBannerVisible("drift-banner", true);
}
async function checkTimeDrift() {
  if (!settings.timeDriftCheck) return;
  try {
    let serverMs;
    if (typeof chrome !== "undefined" && chrome.runtime?.id) {
      const response = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
      serverMs = parseTraceTimestamp(await response.text());
    } else {
      const response = await fetch(location.href, { method: "HEAD", cache: "no-store" });
      serverMs = parseHttpDateHeader(response.headers.get("date"));
    }
    const skewMs = computeSkewMs(serverMs);
    if (skewMs !== null && skewMs > 5000) showDriftBanner(skewMs);
    else hideDriftBanner();
  } catch (error) {
    // Local-first respect: a failed check is a silent skip.
    reportError("Time drift check skipped", error);
    hideDriftBanner();
  }
}

function openEditEntryDialog(entry) {
  if (!editEntryDialog) return;
  editEntryIdInput.value = entry.id;
  editLabelInput.value = entry.label;
  editSecretInput.value = entry.secret;
  editTagsInput.value = (entry.tags || []).join(", ");
  editDigitsInput.value = String(entry.digits);
  editPeriodInput.value = String(entry.period);
  editAlgorithmSelect.value = entry.algorithm || "SHA1";
  editCounterField?.classList.toggle("hidden", entry.type !== "hotp");
  if (editCounterInput) editCounterInput.value = String(entry.type === "hotp" ? entry.counter : 0);
  setStatus(editEntryStatus, "");
  editEntryDialog.showModal();
}

async function saveEditedEntry() {
  const id = editEntryIdInput.value;
  const current = entries.find((entry) => entry.id === id);
  if (!current) throw new Error(t("edit.noLongerExists"));
  const updated = normalizeEntry({
    ...current,
    label: editLabelInput.value,
    secret: editSecretInput.value,
    tags: normalizeTags(editTagsInput.value),
    digits: Number(editDigitsInput.value),
    period: Number(editPeriodInput.value),
    algorithm: editAlgorithmSelect.value,
    counter: current.type === "hotp" && editCounterInput ? Number(editCounterInput.value) : current.counter,
    order: current.order
  });
  if (entries.some((entry) => entry.id !== id && entryKey(entry) === entryKey(updated))) {
    throw new Error(t("edit.duplicate"));
  }
  await replaceEntries(entries.map((entry) => entry.id === id ? updated : entry));
}

function showConfirmDialog(title, message) {
  return new Promise((resolve) => {
    if (!confirmDialog) {
      resolve(false);
      return;
    }
    confirmTitle.textContent = title;
    confirmMessage.textContent = message;
    confirmCallback = resolve;
    confirmDialog.showModal();
  });
}

async function moveEntry(entryId, direction) {
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const index = ordered.findIndex((entry) => entry.id === entryId);
  const nextIndex = index + direction;
  if (index < 0 || nextIndex < 0 || nextIndex >= ordered.length) return;
  [ordered[index], ordered[nextIndex]] = [ordered[nextIndex], ordered[index]];
  await replaceEntries(resequenceEntries(ordered));
}

// --- Drag & drop reorder (Phase 7 FR3) ---
// Pointer-based handle drag; commits through the same custom-order path as
// the move buttons. Pointer capture routes move/up events to the dragged
// card, so no document-level listeners are needed.
var entryDragState = null;

function cardMidpoints() {
  return [...entriesRoot.querySelectorAll(".entry")].map(
    (card) => card.getBoundingClientRect().top + card.offsetHeight / 2
  );
}

function startEntryDrag(event, entry, node) {
  if (settings.sortBy !== "custom" || event.button !== 0 || entryDragState) return;
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const fromIndex = ordered.findIndex((item) => item.id === entry.id);
  if (fromIndex < 0 || ordered.length < 2) return;
  event.preventDefault();
  entryDragState = { entryId: entry.id, fromIndex, node };
  node.classList.add("dragging");
  document.body.classList.add("dragging-entry");
  try {
    node.setPointerCapture(event.pointerId);
  } catch {
    // Pointer capture is unavailable; drag still works while the pointer
    // stays over the card.
  }
  node.addEventListener("pointermove", moveEntryDrag);
  node.addEventListener("pointerup", endEntryDrag);
  node.addEventListener("pointercancel", endEntryDrag);
}

function moveEntryDrag(event) {
  if (!entryDragState) return;
  const hovered = [...entriesRoot.querySelectorAll(".entry")].find((card) => {
    if (card === entryDragState.node) return false;
    const rect = card.getBoundingClientRect();
    return event.clientY >= rect.top && event.clientY <= rect.bottom;
  });
  [...entriesRoot.querySelectorAll(".entry")].forEach((card) => {
    card.classList.toggle("drag-over", card === hovered);
  });
}

async function endEntryDrag(event) {
  const state = entryDragState;
  if (!state) return;
  entryDragState = null;
  state.node.removeEventListener("pointermove", moveEntryDrag);
  state.node.removeEventListener("pointerup", endEntryDrag);
  state.node.removeEventListener("pointercancel", endEntryDrag);
  state.node.classList.remove("dragging");
  document.body.classList.remove("dragging-entry");
  entriesRoot.querySelectorAll(".entry").forEach((card) => card.classList.remove("drag-over"));
  const target = computeDropIndex(cardMidpoints(), state.fromIndex, event.clientY);
  const ordered = [...entries].sort((left, right) => compareEntries(left, right, "custom"));
  const currentIndex = ordered.findIndex((item) => item.id === state.entryId);
  if (currentIndex < 0) return;
  const [moved] = ordered.splice(currentIndex, 1);
  ordered.splice(Math.min(target, ordered.length), 0, moved);
  try {
    await replaceEntries(resequenceEntries(ordered));
    setImportStatus(t("entries.manualOrderUpdated"), "success");
  } catch (error) {
    reportError("Drag reorder failed", error);
    setImportStatus(toUserMessage(error, t("vault.reorderFailed")), "error");
  }
}
function addCopyHistory(label, code) {
  copyHistory = [{
    label,
    code: formatCode(code),
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }, ...copyHistory.filter((item) => item.label !== label)].slice(0, 6);
  renderCopyHistory();
}
function openAddDialog(tab) {
  const dialog = document.getElementById("add-dialog");
  if (!dialog) return;
  setImportStatus("");
  if (!dialog.open) dialog.showModal();
  if (tab) {
    const radio = document.getElementById(`tab-${tab}`);
    if (radio) radio.checked = true;
  }
}
function showEmptyState(message, heading = t("empty.heading")) {
  entriesRoot.innerHTML = "";
  entriesRoot.innerHTML = `
    <section class="workspace-empty">
      <div class="workspace-empty-copy">
        <p class="empty-kicker">${t("empty.kicker")}</p>
        <h3>${heading}</h3>
        <p>${message}</p>
        <div class="workspace-empty-actions">
          <button type="button" class="btn primary" data-empty-action="focus-secret">${t("empty.addFirst")}</button>
          <button type="button" class="btn ghost" data-empty-action="focus-uri">${t("empty.pasteUri")}</button>
          <button type="button" class="btn ghost" data-empty-action="start-camera">${t("empty.scanQr")}</button>
        </div>
      </div>
      <div class="workspace-empty-guide">
        <div class="preview-item">
          <strong>${t("empty.step1Title")}</strong>
          <p>${t("empty.step1Text")}</p>
        </div>
        <div class="preview-item">
          <strong>${t("empty.step2Title")}</strong>
          <p>${t("empty.step2Text")}</p>
        </div>
        <div class="preview-item">
          <strong>${t("empty.step3Title")}</strong>
          <p>${t("empty.step3Text")}</p>
        </div>
      </div>
    </section>`;
  entriesRoot.querySelectorAll("[data-empty-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.getAttribute("data-empty-action");
      if (action === "focus-secret") {
        openAddDialog("manual");
        secretInput.focus();
      }
      if (action === "focus-uri") {
        openAddDialog("paste");
        uriInput.focus();
      }
      if (action === "start-camera") {
        openAddDialog("camera");
        startCameraBtn.click();
      }
    });
  });
}
function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  const avatar = node.querySelector(".entry-avatar");
  const label = node.querySelector(".entry-label");
  const account = node.querySelector(".entry-account");
  const meta = node.querySelector(".entry-meta");
  const copyBtn = node.querySelector(".copy");
  const editBtn = node.querySelector(".edit");
  const moveUpBtn = node.querySelector(".move-up");
  const moveDownBtn = node.querySelector(".move-down");
  const revealBtn = node.querySelector(".reveal");
  const pinBtn = node.querySelector(".pin");
  const removeBtn = node.querySelector(".remove");
  const selectBox = node.querySelector(".entry-select");
  const dragHandle = node.querySelector(".drag-handle");
  if (dragHandle) {
    // Manual reorder only applies to custom sort; hidden otherwise.
    dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
    dragHandle.addEventListener("pointerdown", (event) => {
      startEntryDrag(event, entry, node);
    });
  }
  avatar.textContent = getIssuerInitials(entry.label);
  refreshEntryMetadata(node, entry);
  renderTagRow(node, entry);
  const qrBtn = node.querySelector(".qr");
  if (qrBtn) {
    qrBtn.onclick = () => openQrExport(entry);
  }
  copyBtn.onclick = async () => {
    try {
      const latestCode = node.dataset.otp;
      if (!latestCode) return;
      await navigator.clipboard.writeText(latestCode);
      // Progressive enhancement: silent no-op where unsupported (iOS Safari).
      navigator.vibrate?.(20);
      addCopyHistory(entry.label, latestCode);
      copyBtn.textContent = t("entries.copied");
      if (settings.clearClipboard) {
        setTimeout(() => {
          navigator.clipboard.writeText("").catch((error) => reportError("Clipboard clear failed", error));
        }, 3e4);
      }
      setTimeout(() => {
        copyBtn.textContent = t("entries.copy");
      }, 1e3);
      await consumeHotpCounter(entry, "copy");
    } catch (error) {
      reportError("Copy failed", error);
      showToast(t("toast.vaultTitle"), toUserMessage(error, t("vault.copyFailedShort")), "error");
    }
  };

  editBtn.onclick = () => {
    openEditEntryDialog(entry);
  };

  moveUpBtn.onclick = async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      saveSettings();
      await moveEntry(entry.id, -1);
      setImportStatus(t("entries.manualOrderUpdated"), "success");
    } catch (error) {
      reportError("Move up failed", error);
      setImportStatus(toUserMessage(error, t("vault.reorderEntryFailed")), "error");
    }
  };

  moveDownBtn.onclick = async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      saveSettings();
      await moveEntry(entry.id, 1);
      setImportStatus(t("entries.manualOrderUpdated"), "success");
    } catch (error) {
      reportError("Move down failed", error);
      setImportStatus(toUserMessage(error, t("vault.reorderEntryFailed")), "error");
    }
  };
  revealBtn.onclick = async () => {
    node.classList.toggle("revealed");
    const revealed = node.classList.contains("revealed");
    revealBtn.textContent = revealed ? t("entries.hide") : t("entries.reveal");
    // Revealing an HOTP code consumes it: advance the persisted counter.
    if (revealed && entry.type === "hotp") {
      await consumeHotpCounter(entry, "reveal");
    }
  };
  pinBtn.onclick = async () => {
    try {
      await replaceEntries(entries.map((item) => item.id === entry.id ? { ...item, pinned: !item.pinned } : item));
      setImportStatus(t("entries.pinToggled"), "success");
    } catch (error) {
      reportError("Pin toggle failed", error);
      setImportStatus(toUserMessage(error, t("vault.pinFailed")), "error");
    }
  };
  removeBtn.onclick = async () => {
    try {
      const confirmed = await showConfirmDialog(
        t("confirm.removeTitle"),
        t("confirm.removeText", { label: entry.label })
      );
      if (!confirmed) return;
      const index = entries.findIndex((item) => item.id === entry.id);
      const nextEntries = entries.filter((item) => item.id !== entry.id);
      await replaceEntries(nextEntries);
      selectedEntryIds.delete(entry.id);
      renderBulkBar();
      setImportStatus(t("entries.removed"), "success");
      if (index >= 0) await offerUndoDelete([{ entry, index }]);
    } catch (error) {
      reportError("Entry removal failed", error);
      setImportStatus(toUserMessage(error, t("vault.removeFailed")), "error");
    }
  };
  if (selectBox) {
    selectBox.onchange = () => {
      if (selectBox.checked) selectedEntryIds.add(entry.id);
      else selectedEntryIds.delete(entry.id);
      renderBulkBar();
    };
  }
  return node;
}
function refreshEntryMetadata(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".entry-label").textContent = parts.issuer;
  node.querySelector(".entry-account").textContent = parts.account;
  node.querySelector(".entry-meta").textContent = t("entries.meta", { digits: entry.digits, period: entry.period });
  const algoBadge = node.querySelector(".entry-algo");
  if (algoBadge) {
    const showAlgo = entry.algorithm && entry.algorithm !== "SHA1";
    algoBadge.textContent = showAlgo ? entry.algorithm.replace(/^SHA/, "SHA-") : "";
    algoBadge.classList.toggle("hidden", !showAlgo);
  }
  const counterBadge = node.querySelector(".entry-counter");
  if (counterBadge) {
    const isHotp = entry.type === "hotp";
    counterBadge.textContent = isHotp ? `#${entry.counter}` : "";
    counterBadge.classList.toggle("hidden", !isHotp);
  }
  renderTagRow(node, entry);
}
function renderEntries() {
  setOnboardingVisibility();
  renderWorkspaceSummary();
  renderConnectionState();
  const isLocked = !unlockPanel.classList.contains("hidden") && settings.encrypt;
  if (workspaceHeading) {
    workspaceHeading.textContent = isLocked ? t("entries.headingLocked") : t("entries.headingCurrent");
  }
  if (isLocked) {
    showEmptyState(t("empty.locked"));
    return;
  }
  if (entries.length === 0) {
    entryNodes.clear();
    showEmptyState(t("empty.noEntries"));
    return;
  }
  const groups = getEntryGroups();
  if (groups.length === 0 || groups.every(([, groupEntries]) => groupEntries.length === 0)) {
    showEmptyState(t("empty.noMatch"), t("empty.headingNoMatch"));
    return;
  }
  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (const [groupName, groupEntries] of groups) {
    if (groupEntries.length === 0) continue;
    const wrapper = document.createElement("section");
    wrapper.className = "entry-group";
    if (settings.groupBy !== "none") {
      const title = document.createElement("p");
      title.className = "entry-group-title";
      title.textContent = groupName === "All Entries" ? t("entries.groupAll")
        : groupName === "Untagged" ? t("entries.groupUntagged")
        : groupName;
      wrapper.appendChild(title);
    }
    for (const entry of groupEntries) {
      let node = entryNodes.get(entry.id);
      if (!node) {
        node = createEntryNode(entry);
        entryNodes.set(entry.id, node);
      }
      refreshEntryMetadata(node, entry);
      // Nodes are reused across renders — keep handle visibility in sync
      // with the current sort mode.
      const dragHandle = node.querySelector(".drag-handle");
      if (dragHandle) dragHandle.classList.toggle("hidden", settings.sortBy !== "custom");
      node.classList.toggle("pinned", entry.pinned);
      node.querySelector(".pin").textContent = entry.pinned ? t("entries.unpin") : t("entries.pin");
      const selectBox = node.querySelector(".entry-select");
      if (selectBox) selectBox.checked = selectedEntryIds.has(entry.id);
      wrapper.appendChild(node);
    }
    fragment.appendChild(wrapper);
  }
  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }
  entriesRoot.appendChild(fragment);
}
async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  const code = node.querySelector(".entry-code");
  const seconds = node.querySelector(".entry-seconds");
  const bar = node.querySelector(".entry-bar");
  const ring = node.querySelector(".ring-progress");
  const copyBtn = node.querySelector(".copy");
  try {
    let otp;
    if (entry.type === "hotp") {
      // HOTP renders the deterministic code for the persisted counter —
      // no rolling timer; the counter advances only on reveal/copy (FR8).
      seconds.textContent = t("entries.counterLeft", { counter: entry.counter });
      bar.style.transform = "scaleX(1)";
      node.classList.toggle("urgent", false);
      // Style-only write, O(1) per card per tick (NFR3).
      if (ring) ring.style.strokeDashoffset = "0";
      otp = await generateHotp(entry.secret, entry.counter, entry.digits, entry.algorithm);
    } else {
      const remaining = entry.period - now % entry.period;
      seconds.textContent = t("entries.secondsLeft", { seconds: remaining });
      bar.style.transform = `scaleX(${remaining / entry.period})`;
      node.classList.toggle("urgent", remaining <= 10);
      if (ring) ring.style.strokeDashoffset = String(100 - (remaining / entry.period) * 100);
      otp = await generateTotp(entry.secret, entry.digits, entry.period, now, entry.algorithm);
    }
    code.textContent = formatCode(otp);
    node.dataset.otp = otp;
    copyBtn.disabled = false;
  } catch (error) {
    reportError("OTP generation failed", error);
    code.textContent = t("entries.invalidSecret");
    node.dataset.otp = "";
    copyBtn.disabled = true;
  }
}
async function updateAllEntries(now) {
  await Promise.all(getVisibleEntries().map((entry) => updateEntryNode(entry, now)));
}
function updateTimer(now) {
  const visibleEntries = getVisibleEntries();
  const period = visibleEntries.length > 0 ? Math.min(...visibleEntries.map((entry) => entry.period)) : 30;
  const remaining = period - now % period;
  timerValue.textContent = `${remaining}s`;
  timerBar.style.transform = `scaleX(${remaining / period})`;
}
async function tick() {
  const now = Math.floor(Date.now() / 1e3);
  updateTimer(now);
  if (vaultBusy()) return;

  const vaultLocked = !unlockPanel.classList.contains("hidden") && settings.encrypt;
  if (settings.encrypt && settings.autoLockMinutes > 0 && !vaultLocked
      && Date.now() - lastActivity >= settings.autoLockMinutes * 60000) {
    lockVault();
    return;
  }
  if (vaultLocked) {
    const guard = readUnlockGuard();
    const remainingMs = guard.lockedUntil - Date.now();
    unlockBtn.disabled = remainingMs > 0;
    if (remainingMs > 0) {
      lastThrottleMessage = t("vault.tooManyAttempts", { seconds: Math.ceil(remainingMs / 1000) });
      setUnlockStatus(lastThrottleMessage, "error");
    } else if (unlockStatus.classList.contains("error") && unlockStatus.textContent === lastThrottleMessage) {
      setUnlockStatus("");
    }
    return;
  }
  await updateAllEntries(now);
}
async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(encryptedPayload));
  return encryptedPayload;
}
async function readEncryptedVaultPayload() {
  const raw = localStorage.getItem(ENCRYPTED_VAULT_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error("Encrypted data is unreadable", { cause: error });
  }
}

// --- Biometric (WebAuthn PRF) unlock — Phase 6 ---

function bytesToBase64(bytes) {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function base64ToBytes(value) {
  const text = atob(value);
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) bytes[i] = text.charCodeAt(i);
  return bytes;
}
function readBiometricRecord() {
  try {
    const raw = localStorage.getItem(BIOMETRIC_KEY);
    if (!raw) return null;
    const record = JSON.parse(raw);
    if (!record || typeof record.credentialId !== "string"
        || typeof record.prfSalt !== "string"
        || typeof record.wrappedDek !== "string"
        || typeof record.wrappedIv !== "string") {
      return null;
    }
    return record;
  } catch (error) {
    reportError("Failed to read biometric record", error);
    return null;
  }
}
function writeBiometricRecord(record) {
  localStorage.setItem(BIOMETRIC_KEY, JSON.stringify(record));
}
function removeBiometricRecord() {
  localStorage.removeItem(BIOMETRIC_KEY);
}
// { salt, kdf, dek } snapshot for DEK-mode saves — salt/kdf/passphrase-wrap
// stay stable, only the data iv rotates per save (FR8).
function extractDekEnvelopeMeta(payload) {
  if (!isDekEncryptedPayload(payload)) return null;
  return { salt: payload.salt, kdf: { ...payload.kdf }, dek: { ...payload.dek } };
}
async function exportDekRawBytes(dek) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", dek));
}
// Crash recovery (FR3): a biometric record whose envelope has no `dek` block
// (or is missing entirely) can never unwrap — delete the record so the vault
// falls back to passphrase-only.
function reconcileOrphanedBiometricRecord() {
  const record = readBiometricRecord();
  if (!record) return;
  let payload = null;
  try {
    const raw = localStorage.getItem(ENCRYPTED_VAULT_KEY);
    payload = raw ? JSON.parse(raw) : null;
  } catch {
    payload = null;
  }
  if (isDekEncryptedPayload(payload)) return;
  removeBiometricRecord();
  renderBiometricControls();
}
// FR12: one passphrase re-entry per sensitive operation when the session is
// biometric-only (heldDek without currentPassphrase). Verified fail-closed by
// unwrapping the DEK; the caller releases the passphrase after the operation.
async function requirePassphrase(actionLabel) {
  if (currentPassphrase) return currentPassphrase;
  if (!heldDek) return "";
  const candidate = window.prompt(t("vault.passphrasePrompt", { action: actionLabel }));
  if (!candidate) throw new Error(t("vault.passphraseRequired"));
  const normalized = normalizePassphrase(candidate);
  const payload = await readEncryptedVaultPayload();
  if (!payload || !isDekEncryptedPayload(payload)) {
    throw new Error(t("vault.passphraseRequired"));
  }
  heldDek = await unwrapDekWithPassphrase(payload, normalized);
  dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  currentPassphrase = normalized;
  return currentPassphrase;
}
function releasePassphrase(previousPassphrase) {
  if (!previousPassphrase) currentPassphrase = "";
}
async function persistEntries() {
  if (staleVaultTab) {
    throw new Error(t("vault.staleTab"));
  }
  const previousArtifacts = snapshotPersistedVaultArtifacts();
  try {
    if (!settings.persist) {
      clearPersistedEntries();
      return;
    }
    if (settings.encrypt) {
      if (heldDek) {
        // DEK mode (biometric unlock, FR8): re-encrypt data under the held
        // DEK — no passphrase involvement; salt/kdf/passphrase-wrap stable.
        const envelope = await encryptEntriesWithDek(entries, heldDek, dekEnvelopeMeta);
        localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(envelope));
      } else {
        if (!currentPassphrase) {
          throw new Error(t("vault.needsUnlockToSave"));
        }
        await saveEncryptedEntries(entries, currentPassphrase);
      }
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem(LEGACY_STORAGE_KEY);
      return;
    }
    savePlainEntries();
    localStorage.removeItem(ENCRYPTED_VAULT_KEY);
    // A plain vault has no DEK envelope — biometric mode cannot survive.
    removeBiometricRecord();
    heldDek = null;
    dekEnvelopeMeta = null;
  } catch (error) {
    restorePersistedVaultArtifacts(previousArtifacts);
    throw error;
  }
}
async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);
  if (entries.every((entry) => !entry.order)) {
    entries = resequenceEntries(entries);
  }
  selectedEntryIds = new Set([...selectedEntryIds].filter((id) => entries.some((entry) => entry.id === id)));
  try {
    await persistEntries();
  } catch (error) {
    entries = previousEntries;
    renderEntries();
    renderBulkBar();
    await tick();
    throw error;
  }
  renderEntries();
  renderBulkBar();
  updateDataSafetyBanners();
  await tick();
}
function buildManualEntry(input) {
  const entry = normalizeEntry({ ...input, pinned: false, order: nextOrderValueFrom(entries) });
  if (hasDuplicateEntry(entries, entry)) {
    throw new Error("This account already exists");
  }
  return entry;
}
async function addEntry(input) {
  const entry = buildManualEntry(input);
  await replaceEntries([...entries, entry]);
  return entry;
}

function buildPreviewCandidatesFromUris(uris, sourceLabel) {
  const unique = [];
  const seen = new Set();
  let skipped = 0;
  let invalid = 0;

  for (const uri of uris) {
    try {
      const entry = parseOtpAuthUri(uri);
      const key = entryKey(entry);
      if (seen.has(key) || hasDuplicateEntry(entries, entry)) {
        skipped++;
        continue;
      }
      seen.add(key);
      unique.push(entry);
    } catch {
      invalid++;
      continue;
    }
  }

  if (unique.length === 0) {
    const details = [];
    if (skipped > 0) details.push(t("vault.duplicatesSkipped", { count: skipped, plural: skipped === 1 ? "" : "s" }));
    if (invalid > 0) details.push(t("vault.invalidIgnored", { count: invalid, plural: invalid === 1 ? "" : "s" }));
    throw new Error(t("vault.noNewEntries", { source: sourceLabel, details: details.length > 0 ? ` (${details.join(", ")})` : "" }));
  }
  return { candidates: unique, skipped, invalid, sourceLabel };
}

// --- Google Authenticator migration import (Phase 4) ---

var migrationScanState = null;

// Extracts migration URIs from raw text and decodes each into raw payload
// bytes for stitching; parse failures become warnings, never aborts.
function collectMigrationPayloads(rawText) {
  const uris = extractMigrationUris(rawText);
  if (uris.length === 0) return { payloads: [], warnings: [] };
  const payloads = [];
  const warnings = [];
  for (const uri of uris) {
    try {
      payloads.push(parseMigrationUri(uri).payloadBytes);
    } catch (error) {
      warnings.push(toUserMessage(error, "A migration QR could not be read"));
    }
  }
  return { payloads, warnings };
}

// Stitches decoded payloads, maps to vault candidates through normalizeEntry,
// and opens the preview. Duplicates stay visible but pre-unchecked.
function stageMigrationPayloads(payloadByteArrays, sourceLabel) {
  const stitched = stitchMigrationBatches(payloadByteArrays);
  const warnings = [...stitched.warnings];
  if (stitched.entries.length === 0) {
    throw new Error(t("vault.noImportable", { source: sourceLabel, details: warnings.length ? `: ${warnings.join(" ")}` : "" }));
  }

  const candidates = [];
  let skipped = 0;
  let invalid = 0;
  for (const params of stitched.entries) {
    try {
      const candidate = migrationToEntryCandidates([params])[0];
      const entry = normalizeEntry(candidate);
      if (hasDuplicateEntry(entries, entry) || candidates.some((existing) => entryKey(existing) === entryKey(entry))) {
        candidates.push({ ...entry, duplicateHint: true });
        skipped += 1;
        continue;
      }
      candidates.push(entry);
    } catch (error) {
      invalid += 1;
      warnings.push(toUserMessage(error, "An entry could not be mapped"));
    }
  }

  openImportPreview({ candidates, skipped, invalid, warnings, sourceLabel }, sourceLabel);
}

function finishMigrationCameraScan() {
  const state = migrationScanState;
  migrationScanState = null;
  stopCameraScan();
  if (!state || state.payloads.length === 0) return;
  try {
    stageMigrationPayloads(state.payloads, "Camera");
  } catch (error) {
    reportError("Camera migration import failed", error);
    setImportStatus(toUserMessage(error, "Could not import the Google Authenticator scan"), "error");
  }
}

// Camera loop handler for migration QRs: accumulate distinct batch payloads,
// show progress, terminate on completion (all QRs of the batch scanned).
function handleMigrationScanFrame(uri) {
  try {
    const parsed = parseMigrationUri(uri);
    if (!migrationScanState) {
      migrationScanState = { payloads: [], seenKeys: new Set(), total: null };
    }
    const payloadKey = `${parsed.batch.id}:${parsed.batch.index}`;
    if (migrationScanState.seenKeys.has(payloadKey)) {
      setImportStatus(t("import.scanProgress", { done: migrationScanState.seenKeys.size, total: migrationScanState.total }), "warning");
      return;
    }
    if (migrationScanState.total !== null && parsed.batch.size !== migrationScanState.total) {
      setImportStatus(t("import.scanMixedBatches"), "error");
      migrationScanState = null;
      return;
    }
    migrationScanState.total = parsed.batch.size;
    migrationScanState.seenKeys.add(payloadKey);
    migrationScanState.payloads.push(parsed.payloadBytes);
    if (migrationScanState.seenKeys.size >= migrationScanState.total) {
      setImportStatus(t("import.scanComplete"), "success");
      finishMigrationCameraScan();
    } else {
      setImportStatus(t("import.scanProgress", { done: migrationScanState.seenKeys.size, total: migrationScanState.total }), "warning");
    }
  } catch (error) {
    reportError("Migration scan failed", error);
    setImportStatus(toUserMessage(error, "Could not read the Google Authenticator QR"), "error");
  }
}

function renderImportPreview() {
  if (!importPreviewState || !importPreviewList) return;

  const candidates = importPreviewState.candidates || importPreviewState;
  const skipped = importPreviewState.skipped || 0;
  const invalid = importPreviewState.invalid || 0;
  const warnings = importPreviewState.warnings || [];
  const sourceLabel = importPreviewState.sourceLabel || "Import";

  importPreviewTitle.textContent = t("import.previewTitle", { count: candidates.length, plural: candidates.length === 1 ? "" : "s" });
  let statusText = t("import.previewStatus", { source: sourceLabel });
  if (skipped > 0) {
    statusText += t("import.previewSkipped", { count: skipped, plural: skipped === 1 ? "" : "s" });
  }
  if (invalid > 0) {
    statusText += t("import.previewInvalid", { count: invalid, plural: invalid === 1 ? "y" : "ies" });
  }
  if (warnings.length > 0) {
    statusText += ` ${warnings.join(" ")}`;
  }
  importPreviewStatus.textContent = statusText;
  importPreviewList.innerHTML = "";

  candidates.forEach((entry, index) => {
    const row = document.createElement("article");
    row.className = "preview-item";
    row.dataset.index = String(index);

    const includeLabel = document.createElement("label");
    includeLabel.className = "toggle-row";
    const includeInput = document.createElement("input");
    includeInput.type = "checkbox";
    includeInput.className = "preview-include";
    includeInput.checked = !entry.duplicateHint;
    const includeText = document.createElement("span");
    includeText.textContent = entry.duplicateHint ? t("import.alreadyInVault") : t("import.includeEntry");
    includeLabel.append(includeInput, includeText);

    const labelField = document.createElement("label");
    const labelText = document.createElement("span");
    labelText.textContent = t("import.previewLabelField");
    const labelInput = document.createElement("input");
    labelInput.type = "text";
    labelInput.className = "preview-label";
    labelInput.value = entry.label;
    labelField.append(labelText, labelInput);

    const tagsField = document.createElement("label");
    const tagsText = document.createElement("span");
    tagsText.textContent = t("import.previewTagsField");
    const tagsInput = document.createElement("input");
    tagsInput.type = "text";
    tagsInput.className = "preview-tags";
    tagsInput.value = (entry.tags || []).join(", ");
    tagsInput.placeholder = t("import.previewTagsPlaceholder");
    tagsField.append(tagsText, tagsInput);

    const summary = document.createElement("p");
    const summaryParts = [`${entry.digits} digits`, `${entry.period}s`];
    if (entry.type === "hotp") summaryParts.push(`HOTP #${entry.counter}`);
    if (entry.algorithm && entry.algorithm !== "SHA1") summaryParts.push(entry.algorithm.replace(/^SHA/, "SHA-"));
    summary.textContent = summaryParts.join(" • ");

    row.append(includeLabel, labelField, tagsField, summary);
    importPreviewList.appendChild(row);
  });
}

function openImportPreview(previewResult, sourceLabel) {
  importPreviewState = previewResult;
  if (importPreviewTagsInput) importPreviewTagsInput.value = "";
  renderImportPreview();
  importDialog?.showModal?.();
}

async function commitImportPreview(previewState = importPreviewState) {
  if (!previewState) return;
  const extraTags = normalizeTags(importPreviewTagsInput?.value);
  let nextOrder = nextOrderValueFrom(entries);
  const rows = [...importPreviewList.querySelectorAll(".preview-item")];
  const candidates = previewState.candidates || previewState;
  const sourceLabel = previewState.sourceLabel || "Import";
  const enriched = rows.flatMap((row) => {
    const include = row.querySelector(".preview-include");
    if (!include?.checked) return [];
    const index = Number(row.dataset.index);
    const baseEntry = candidates[index];
    return [{
      ...baseEntry,
      label: row.querySelector(".preview-label")?.value.trim() || baseEntry.label,
      tags: normalizeTags([
        ...(baseEntry.tags || []),
        ...normalizeTags(row.querySelector(".preview-tags")?.value),
        ...extraTags,
      ]),
      order: nextOrder++,
    }];
  });
  if (enriched.length === 0) throw new Error(t("import.selectAtLeastOne"));
  await replaceEntries([...entries, ...enriched]);
  setImportStatus(enriched.length === 1
    ? t("import.importedOne", { source: sourceLabel })
    : t("import.importedMany", { source: sourceLabel, count: enriched.length }), "success");
}
async function importOtpAuthUri(otpUri, sourceLabel = "Import") {
  const parsed = normalizeEntry({ ...parseOtpAuthUri(otpUri), order: nextOrderValueFrom(entries) });
  if (hasDuplicateEntry(entries, parsed)) {
    throw new Error(t("vault.accountExists"));
  }
  await replaceEntries([...entries, parsed]);
  setImportStatus(t("import.uriImported", { source: sourceLabel }), "success");
}
async function decodeQrFromBlob(blob) {
  if (typeof jsQR !== "function") {
    throw new Error("QR scanner library failed to load");
  }
  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  if (!result?.data) {
    throw new Error(t("import.qrNotDetectedImage"));
  }
  return result.data;
}
async function importFromQrBlob(blob, sourceLabel) {
  const qrText = await decodeQrFromBlob(blob);
  // Google Authenticator migration QRs take priority over plain otpauth URIs.
  const migration = collectMigrationPayloads(qrText);
  if (migration.payloads.length > 0) {
    stageMigrationPayloads(migration.payloads, sourceLabel);
    return;
  }
  if (migration.warnings.length > 0) {
    throw new Error(migration.warnings.join(" "));
  }
  const uris = extractOtpAuthUris(qrText);
  if (uris.length === 0) throw new Error(t("import.noValidOtpUriInQr"));
  const candidates = buildPreviewCandidatesFromUris(uris, sourceLabel);
  openImportPreview(candidates, sourceLabel);
}
async function unlockVault(passphrase) {
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const payload = await readEncryptedVaultPayload();
  let decrypted;
  if (payload && isDekEncryptedPayload(payload)) {
    // Passphrase recovery in DEK mode (FR4): the passphrase unwraps the DEK,
    // which stays held so subsequent saves keep working without a re-prompt.
    heldDek = await unwrapDekWithPassphrase(payload, normalizedPassphrase);
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
    decrypted = await decryptVaultEntriesWithKey(heldDek, payload);
  } else {
    decrypted = payload ? await decryptVaultEntries(payload, normalizedPassphrase) : [];
    heldDek = null;
    dekEnvelopeMeta = null;
    reconcileOrphanedBiometricRecord();
  }
  currentPassphrase = normalizedPassphrase;
  entries = resequenceIfUnordered(decrypted);
  setLocked(false);
  renderEntries();
  await tick();
  await upgradeLegacyEncryptedVault(payload);
  await offerUndoFromTombstone();
}
// FR3: biometric unlock — full UV ceremony every time; holds the DEK, never
// the passphrase. Throttle guard applies (biometrics must not bypass backoff).
async function unlockWithBiometrics() {
  const guard = readUnlockGuard();
  if (guard.lockedUntil > Date.now()) {
    setUnlockStatus(t("vault.tooManyAttempts", { seconds: Math.ceil((guard.lockedUntil - Date.now()) / 1000) }), "error");
    return;
  }
  const record = readBiometricRecord();
  if (!record) {
    setUnlockStatus(t("ext.noBiometricEnrolled"), "error");
    return;
  }
  const payload = await readEncryptedVaultPayload();
  if (!payload || !isDekEncryptedPayload(payload)) {
    reconcileOrphanedBiometricRecord();
    setUnlockStatus(t("ext.biometricUnavailable"), "error");
    return;
  }
  operationDepth += 1;
  try {
    const prfSalt = fromB64u(record.prfSalt);
    const { prfOutput } = await runAssertCeremony({ credentialId: record.credentialId, prfSalt });
    const kek = await deriveKek(prfOutput, prfSalt);
    const dek = await unwrapDek(fromB64u(record.wrappedDek), fromB64u(record.wrappedIv), kek);
    const decrypted = await decryptVaultEntriesWithKey(dek, payload);
    heldDek = dek;
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
    currentPassphrase = "";
    entries = resequenceIfUnordered(decrypted);
    writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
    setLocked(false);
    renderEntries();
    await tick();
    await offerUndoFromTombstone();
    setUnlockStatus(t("unlock.statusBiometricSuccess"), "success");
  } catch (error) {
    reportError("Biometric unlock failed", error);
    setUnlockStatus(toUserMessage(error, t("ext.biometricUnlockFailed")), "error");
  } finally {
    operationDepth -= 1;
  }
}
// FR2: enrollment — a TWO-STORE write: envelope first (stays
// passphrase-recoverable), biometric record second. Re-enrollment keeps the
// DEK, data, and passphrase wrap untouched and swaps only the KEK copy.
async function enrollVaultBiometrics() {
  if (!settings.persist || !settings.encrypt) {
    throw new Error(t("settings.enabledEncryptedFirst"));
  }
  if (!currentPassphrase && !heldDek) {
    throw new Error(t("settings.unlockBeforeBiometric"));
  }
  const payload = await readEncryptedVaultPayload();
  if (payload && !isDekEncryptedPayload(payload) && !currentPassphrase) {
    throw new Error(t("settings.unlockBeforeBiometric"));
  }
  const enrollment = await enrollBiometricUnlock({});
  const prfSalt = enrollment.prfSalt;
  const kek = await deriveKek(enrollment.firstPrfOutput, prfSalt);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));

  let dek;
  let envelope;
  if (payload && isDekEncryptedPayload(payload)) {
    // Re-enrollment (NFR3): same DEK and data — only the KEK wrap is swapped.
    dek = heldDek || await unwrapDekWithPassphrase(payload, currentPassphrase);
    envelope = null; // envelope unchanged — no write, no crash window
  } else {
    // First enrollment: transform the standard envelope into DEK mode.
    dek = await generateVaultDek();
    const saltBytes = crypto.getRandomValues(new Uint8Array(KDF_PARAMS_DEFAULT.saltBytes));
    const dekBlock = await wrapDekWithPassphrase(dek, currentPassphrase, saltBytes, KDF_PARAMS_DEFAULT);
    envelope = await encryptEntriesWithDek(entries, dek, {
      salt: bytesToBase64(saltBytes),
      kdf: { ...KDF_PARAMS_DEFAULT },
      dek: dekBlock,
    });
  }

  const rawDek = await exportDekRawBytes(dek);
  const wrappedDek = await wrapDek(rawDek, kek, wrapIv);
  const record = {
    credentialId: enrollment.credentialId,
    prfSalt: toB64u(prfSalt),
    wrappedDek: toB64u(wrappedDek),
    wrappedIv: toB64u(wrapIv),
  };
  if (envelope) {
    localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(envelope));
    dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
  }
  writeBiometricRecord(record);
  heldDek = dek;
  renderBiometricControls();
}
// FR5: disenroll — passphrase-verified, then re-encrypt data directly under
// the passphrase key (standard Phase-1 envelope) and delete the record.
async function disenrollVaultBiometrics() {
  const record = readBiometricRecord();
  if (!record) {
    setSettingsStatus(t("settings.biometricNotEnabled"), "error");
    return;
  }
  const confirmed = await showConfirmDialog(
    t("settings.biometricDisableTitle"),
    t("settings.biometricDisableText")
  );
  if (!confirmed) return;
  const previousPassphrase = currentPassphrase;
  await requirePassphrase(t("settings.biometricDisablePromptAction"));
  try {
    const restored = await encryptEntries(entries, currentPassphrase);
    localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(restored));
    removeBiometricRecord();
    heldDek = null;
    dekEnvelopeMeta = null;
    setSettingsStatus(t("settings.biometricDisabled"), "success");
  } finally {
    releasePassphrase(previousPassphrase);
  }
  renderBiometricControls();
}
async function hashPayloadString(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
}
// Re-encrypts legacy (or tampered sub-floor) envelopes at the current default
// work factor right after a successful unlock. Fires at most once per payload
// hash so concurrent tabs do not stampede re-encrypts (FR3/FR8).
async function upgradeLegacyEncryptedVault(payload) {
  if (!payload || !isLegacyEncryptedPayload(payload)) return;
  const payloadHash = await hashPayloadString(JSON.stringify(payload));
  if (sessionStorage.getItem(UPGRADE_SENTINEL_KEY) === payloadHash) return;
  try {
    await persistEntries();
    sessionStorage.setItem(UPGRADE_SENTINEL_KEY, payloadHash);
  } catch (error) {
    reportError("Legacy vault upgrade failed", error);
  }
}
async function handleSaveSettings() {
  if (persistToggle.checked && encryptToggle.checked) {
    const needsInitialPassphrase = !settings.encrypt || !settings.persist || (!currentPassphrase && !heldDek);
    if (needsInitialPassphrase && !vaultPassphraseInput.value.trim()) {
      throw new Error(t("vault.needsPassphraseToEncrypt"));
    }
  }
  if (persistToggle.checked && !hasSeenPersistWarning()) {
    if (typeof privacyDialog.showModal === "function") {
      privacyDialog.showModal();
      return;
    }
  }
  const nextSettings = {
    persist: persistToggle.checked,
    encrypt: encryptToggle.checked,
    unlockOnLoad: encryptToggle.checked ? true : unlockOnLoadToggle.checked,
    blurCodes: blurCodesToggle.checked,
    screenshotSafe: screenshotSafeToggle.checked,
    clearClipboard: clearClipboardToggle.checked,
    autoLockMinutes: Number(document.getElementById("auto-lock-select")?.value ?? settings.autoLockMinutes) || 0,
    timeDriftCheck: document.getElementById("time-drift-toggle")?.checked ?? settings.timeDriftCheck,
    theme: document.getElementById("theme-select")?.value ?? settings.theme ?? "system",
    locale: languageSelect?.value ?? settings.locale ?? "system",
    sortBy: sortSelect.value,
    groupBy: groupSelect.value
  };
  let nextPassphrase = currentPassphrase;
  if (nextSettings.encrypt) {
    const first = vaultPassphraseInput.value.trim();
    const second = vaultPassphraseConfirmInput.value.trim();
    const needsInitialPassphrase = !settings.encrypt || !settings.persist || (!currentPassphrase && !heldDek);
    if (needsInitialPassphrase && !first) {
      throw new Error(t("vault.needsPassphraseToEncrypt"));
    }
    if (needsInitialPassphrase || first || second) {
      if (settings.encrypt && settings.persist && currentPassphrase && (first || second)) {
        nextPassphrase = currentPassphrase;
      } else {
        if (first !== second) {
          throw new Error(t("vault.confirmationMismatch"));
        }
        nextPassphrase = normalizePassphrase(first);
      }
    }
  } else {
    nextPassphrase = "";
  }
  const previousSettings = { ...settings };
  const previousPassphrase = currentPassphrase;
  const previousStoredSettings = localStorage.getItem(SETTINGS_KEY);
  settings = nextSettings;
  currentPassphrase = nextPassphrase;
  syncSettingsUI();
  applyVisualSettings();
  applyLocale();
  try {
    saveSettings();
    if (!settings.persist) {
      clearPersistedEntries();
      syncSettingsUI();
      setLocked(false);
      setSettingsStatus(t("settings.statusSessionOnly"), "success");
      vaultPassphraseInput.value = "";
      vaultPassphraseConfirmInput.value = "";
      return;
    }
    await persistEntries();
    syncSettingsUI();
  } catch (error) {
    settings = previousSettings;
    currentPassphrase = previousPassphrase;
    if (previousStoredSettings === null) {
      localStorage.removeItem(SETTINGS_KEY);
    } else {
      localStorage.setItem(SETTINGS_KEY, previousStoredSettings);
    }
    syncSettingsUI();
    applyVisualSettings();
    applyLocale();
    throw error;
  }
  setLocked(false);
  const encryptedVaultExists = settings.persist && settings.encrypt && Boolean(currentPassphrase || localStorage.getItem(ENCRYPTED_VAULT_KEY));
  setSettingsStatus(
    encryptedVaultExists ? t("settings.statusEncryptedVaultSaved") : settings.encrypt ? t("settings.statusEncryptedSaved") : t("settings.statusDeviceStorageUpdated"),
    "success"
  );
  vaultPassphraseInput.value = "";
  vaultPassphraseConfirmInput.value = "";
}
function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
async function exportBackup() {
  const previousPassphrase = currentPassphrase;
  // FR12 gate. FR10: the passphrase path below always emits a standard
  // envelope (no `dek` block), restorable by passphrase alone.
  await requirePassphrase(t("vault.actionExportBackup"));
  try {
    let envelope;
    if (settings.encrypt) {
      if (!currentPassphrase) {
        throw new Error(t("vault.needsUnlockToExport"));
      }
      const encryptedPayload = await encryptEntries(entries, currentPassphrase);
      envelope = await createEncryptedBackup(encryptedPayload, currentPassphrase);
    } else {
      envelope = await createPlainBackup(entries);
    }
    downloadJson("otp-vault-backup.json", envelope);
    await stampBackupExport(envelope);
  } finally {
    releasePassphrase(previousPassphrase);
  }
}
// Stamp lastBackupAt when the export envelope is BUILT. Download delivery is
// fire-and-forget (a blocked/cancelled download is indistinguishable from
// success), so the honest wording is "Last export" + envelope hash (FR2).
async function stampBackupExport(envelope) {
  settings.lastBackupAt = Date.now();
  settings.lastBackupHash = await hashPayloadString(JSON.stringify(envelope.payload));
  saveSettings();
  renderBackupReminder();
}
async function changeVaultPassphrase(currentPassphraseCandidate, nextPassphraseCandidate, confirmPassphraseCandidate) {
  if (!settings.persist || !settings.encrypt) {
    throw new Error(t("vault.changeNeedsEncryption"));
  }
  const previousPassphrase = currentPassphrase;
  if (!previousPassphrase) {
    await requirePassphrase(t("vault.actionChangePassphrase"));
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    releasePassphrase(previousPassphrase);
    throw new Error(t("vault.currentIncorrect"));
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    releasePassphrase(previousPassphrase);
    throw new Error(t("vault.confirmationMismatch"));
  }
  const normalizedNextPassphrase = normalizePassphrase(nextPassphraseCandidate);
  const payload = await readEncryptedVaultPayload();
  if (payload && isDekEncryptedPayload(payload)) {
    // FR11 in DEK mode: re-wrap the SAME DEK under the new passphrase —
    // data, salt, and the biometric wrap stay untouched.
    try {
      const dek = await unwrapDekWithPassphrase(payload, currentPassphrase);
      const meta = extractDekEnvelopeMeta(payload);
      const nextDekBlock = await wrapDekWithPassphrase(dek, normalizedNextPassphrase, base64ToBytes(meta.salt), meta.kdf);
      const envelope = await encryptEntriesWithDek(entries, dek, { ...meta, dek: nextDekBlock });
      localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(envelope));
      heldDek = dek;
      dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
      currentPassphrase = normalizedNextPassphrase;
    } finally {
      releasePassphrase(previousPassphrase);
    }
    return;
  }
  currentPassphrase = normalizedNextPassphrase;
  try {
    await persistEntries();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
  releasePassphrase(previousPassphrase);
}

function renderBackupReview(backup) {
  if (!backupReviewSummary) return;
  backupReviewSummary.innerHTML = "";

  const backupEntries = backup.entries || [];
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");

  let summaryItems = [
    backup.integrity === "verified"
      ? (backup.macProtected ? t("backup.integrityVerifiedKeyed") : t("backup.integrityVerified"))
      : t("backup.integrityLegacy"),
    backup.encrypted ? t("backup.encryptedYes") : t("backup.encryptedNo"),
    t("backup.schemaLine", { version: backup.schemaVersion }),
    t("backup.createdLine", { date: backup.createdAt || "unknown" }),
    t("backup.incomingItems", { count: backup.itemCount }),
    t("backup.vaultSize", { count: entries.length })
  ];

  if (backup.invalidItemCount > 0) {
    summaryItems.push(t("backup.invalidSkipped", { count: backup.invalidItemCount, plural: backup.invalidItemCount === 1 ? "" : "s" }));
  }

  if (mode === "merge" && backupEntries.length > 0 && entries.length > 0) {
    const duplicates = backupEntries.filter((candidate) =>
      entries.some((entry) => entryKey(entry) === entryKey(candidate))
    ).length;
    const newEntries = backupEntries.length - duplicates;
    summaryItems.push(t("backup.mergeSummary", { new: newEntries, duplicates, plural: duplicates === 1 ? "" : "s" }));
  }

  summaryItems.forEach((item) => {
    const row = document.createElement("div");
    row.className = "preview-item";
    row.textContent = item;
    backupReviewSummary.appendChild(row);
  });
  backupPassphraseRow?.classList.toggle("hidden", !backup.encrypted);
  // An encrypted backup without a keyed mac (v2 or earlier) imports, but the
  // version field inside the unkeyed-checksum region is downgradable, so the
  // missing authenticity signal is surfaced as a warning, not success.
  const verified = backup.integrity === "verified";
  const unkeyedEncrypted = verified && backup.encrypted && !backup.macProtected;
  setStatus(
    backupReviewStatus,
    !verified ? t("backup.reviewLegacy")
      : unkeyedEncrypted ? t("backup.reviewNoMac")
      : backup.macProtected ? t("backup.reviewVerifiedKeyed")
      : t("backup.reviewVerified"),
    verified && !unkeyedEncrypted ? "success" : "warning"
  );
}
async function importBackupFile(file, backup = null, rawBackup = null) {
  const previousPassphrase = currentPassphrase;
  // FR12: modifying the vault under a biometric-only session requires one
  // passphrase re-entry, released after the import settles.
  await requirePassphrase("import a backup");
  try {
    let inlineRawBackup = rawBackup;
    const resolvedBackup = backup || await (async () => {
      const text = await file.text();
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch (error) {
        throw new Error(t("backup.fileNotJson"));
      }
      inlineRawBackup = parsed;
      try {
        return await parseBackupFile(parsed);
      } catch (error) {
        throw new Error(toUserMessage(error, "Backup file is invalid"));
      }
    })();
    if (resolvedBackup.integrity === "legacy") {
      setSettingsStatus(t("backup.legacyStatus"), "warning");
    }
    const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");
    if (resolvedBackup.encrypted) {
      const passphrase = backupImportPassphraseInput?.value.trim() || window.prompt(t("backup.passphrasePrompt"));
      if (!passphrase) throw new Error(t("backup.importCancelledNoPassphrase"));
      if (resolvedBackup.macProtected) {
        const authentic = await verifyBackupMac(inlineRawBackup, passphrase);
        if (!authentic) throw new Error(t("backup.macFailed"));
      }
      const decrypted = await decryptVaultEntries(resolvedBackup.vault, passphrase);
      const nextEntries2 = mode === "replace" ? decrypted : [...entries, ...decrypted.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
      await replaceEntries(nextEntries2);
      return;
    }
    const nextEntries = mode === "replace" ? resolvedBackup.entries : [...entries, ...resolvedBackup.entries.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
    await replaceEntries(nextEntries);
  } finally {
    releasePassphrase(previousPassphrase);
  }
}
async function stageBackupImport(file) {
  const text = await file.text();
  let rawBackup;
  try {
    rawBackup = JSON.parse(text);
  } catch (error) {
    throw new Error(t("backup.fileNotJson"));
  }
  let backup;
  try {
    backup = await parseBackupFile(rawBackup);
  } catch (error) {
    throw new Error(toUserMessage(error, "Backup file is invalid"));
  }
  backupImportState = { file, backup, rawBackup };
  if (backupImportMode) backupImportMode.value = entries.length > 0 ? "merge" : "replace";
  if (backupImportPassphraseInput) backupImportPassphraseInput.value = "";
  renderBackupReview(backup);
  if (backupReviewDialog?.showModal) {
    backupReviewDialog.showModal();
    return;
  }
  await importBackupFile(file, backup, rawBackup);
}
async function commitBackupImport() {
  if (!backupImportState) return;
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");
  if (mode === "replace" && entries.length > 0) {
    const confirmed = await showConfirmDialog(
      t("confirm.replaceVaultTitle"),
      t("confirm.replaceVaultText", { count: entries.length, plural: entries.length === 1 ? "y" : "ies" })
    );
    if (!confirmed) {
      setSettingsStatus(t("backup.importCancelled"), "warning");
      return;
    }
  }
  await importBackupFile(backupImportState.file, backupImportState.backup, backupImportState.rawBackup);
}
// --- Single-entry QR export (move an entry to another authenticator app) ---

async function openQrExport(entry) {
  if (!qrExportDialog || !qrExportCanvas) return;
  qrExportUri = buildOtpAuthUri(entry);
  qrExportTitle.textContent = `${parseLabelParts(entry.label).issuer} — ${t("qr.heading")}`;
  setStatus(qrExportStatus, "");
  try {
    await QRCode.toCanvas(qrExportCanvas, qrExportUri, {
      width: 240,
      margin: 2,
      color: { dark: "#111318", light: "#ffffff" },
    });
    qrExportDialog.showModal();
  } catch (error) {
    reportError("QR export failed", error);
    setImportStatus(toUserMessage(error, t("qr.renderFailed")), "error");
  }
}

// --- Aegis / 2FAS export import (file-based third-party migration) ---

async function importThirdPartyFile(file) {
  if (file.size > MAX_IMPORT_FILE_BYTES) {
    throw new Error(t("import.fileTooLarge"));
  }
  const text = await file.text();
  const result = parseThirdPartyImport(text);
  const warnings = [...result.warnings];
  const candidates = [];
  let skipped = 0;
  let invalid = 0;
  for (const candidate of result.entries) {
    try {
      const entry = normalizeEntry(candidate);
      if (hasDuplicateEntry(entries, entry) || candidates.some((existing) => entryKey(existing) === entryKey(entry))) {
        candidates.push({ ...entry, duplicateHint: true });
        skipped += 1;
        continue;
      }
      candidates.push(entry);
    } catch (error) {
      invalid += 1;
      warnings.push(toUserMessage(error, t("import.mapFailed")));
    }
  }
  if (candidates.length === 0) {
    throw new Error(t("vault.noImportable", { source: result.format, details: warnings.length ? `: ${warnings.join(" ")}` : "" }));
  }
  openImportPreview({ candidates, skipped, invalid, warnings, sourceLabel: result.format }, result.format);
}

function registerCameraDetection(uri) {
  if (cameraDetection.uri === uri) {
    cameraDetection.hits += 1;
  } else {
    cameraDetection = { uri, hits: 1 };
  }
  return cameraDetection.hits >= 2;
}
async function startCameraScan() {
  if (cameraStream) return;
  cameraDetection = { uri: "", hits: 0 };
  cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  cameraPreview.srcObject = cameraStream;
  await cameraPreview.play();
  stopCameraBtn.disabled = false;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  cameraScanTimer = setInterval(async () => {
    if (!cameraPreview.videoWidth || !cameraPreview.videoHeight || typeof jsQR !== "function") return;
    canvas.width = cameraPreview.videoWidth;
    canvas.height = cameraPreview.videoHeight;
    ctx.drawImage(cameraPreview, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const result = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });

    // Migration QRs accumulate across frames (multi-QR batch export) instead
    // of using the two-frame confirmation used for single otpauth URIs.
    const migrationUris = extractMigrationUris(result?.data || "");
    if (migrationUris.length > 0) {
      handleMigrationScanFrame(migrationUris[0]);
      return;
    }

    const otpUri = extractOtpAuthUri(result?.data || "");
    if (!otpUri) {
      cameraDetection = { uri: "", hits: 0 };
      return;
    }
    if (!registerCameraDetection(otpUri)) {
      setImportStatus(t("import.scanConfirming"), "warning");
      return;
    }
    try {
      openImportPreview(buildPreviewCandidatesFromUris([otpUri], "Camera"), "Camera");
      stopCameraScan();
    } catch (error) {
      reportError("Camera import failed", error);
      setImportStatus(toUserMessage(error, "Could not import camera scan"), "error");
      cameraDetection = { uri: "", hits: 0 };
    }
  }, 900);
}
function stopCameraScan() {
  if (cameraScanTimer) clearInterval(cameraScanTimer);
  cameraScanTimer = null;
  cameraDetection = { uri: "", hits: 0 };
  if (cameraStream) {
    cameraStream.getTracks().forEach((track) => track.stop());
  }
  cameraStream = null;
  cameraPreview.srcObject = null;
  stopCameraBtn.disabled = true;
}
function registerPwaSupport() {
  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    deferredInstallPrompt = event;
    installAppBtn.disabled = false;
  });
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./sw.js").catch((error) => reportError("Service worker registration failed", error));
  }
  window.addEventListener("online", renderConnectionState);
  window.addEventListener("offline", renderConnectionState);
}
function bindEvents() {
  bindMultiTabGuard();
  bindPassphraseStrengthMeters();
  bindAutoLockActivity();
  document.getElementById("drift-dismiss")?.addEventListener("click", hideDriftBanner);
  document.getElementById("backup-reminder-dismiss")?.addEventListener("click", () => setBannerVisible("backup-reminder-banner", false));
  document.getElementById("check-drift-btn")?.addEventListener("click", async () => {
    if (!settings.timeDriftCheck) {
      setSettingsStatus(t("settings.driftCheckFirst"), "warning");
      return;
    }
    await checkTimeDrift();
    setSettingsStatus(t("settings.driftCheckDone"), "success");
  });
  document.addEventListener("keydown", (event) => {
    if (event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement) return;
    if (event.key === "/") {
      event.preventDefault();
      searchInput.focus();
    }
    if (event.key.toLowerCase() === "n") {
      event.preventDefault();
      secretInput.focus();
    }
  });
  encryptToggle.addEventListener("change", () => {
    encryptionFields.classList.toggle("hidden", !encryptToggle.checked);
  });
  entryTypeSelect?.addEventListener("change", () => {
    counterField?.classList.toggle("hidden", entryTypeSelect.value !== "hotp");
  });
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        type: entryTypeSelect?.value || "totp",
        counter: entryTypeSelect?.value === "hotp" ? Number(counterInput?.value || 0) : 0,
        algorithm: algorithmSelect?.value || "SHA1",
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
        tags: normalizeTags(tagsInput?.value)
      });
      form.reset();
      digitsInput.value = "6";
      periodInput.value = "30";
      counterField?.classList.add("hidden");
      syncSettingsUI();
      setImportStatus(t("add.entryAdded"), "success");
      document.getElementById("add-dialog")?.close();
    } catch (error) {
      reportError("Manual entry failed", error);
      setImportStatus(toUserMessage(error, t("vault.addFailed")), "error");
    }
  });
  parseUriBtn.addEventListener("click", async () => {
    try {
      const migration = collectMigrationPayloads(uriInput.value);
      if (migration.payloads.length > 0) {
        stageMigrationPayloads(migration.payloads, "URI");
        uriInput.value = "";
        return;
      }
      const uris = extractOtpAuthUris(uriInput.value);
      if (uris.length === 0) throw new Error(t("import.noValidUri"));
      openImportPreview(buildPreviewCandidatesFromUris(uris, "URI"), "URI");
      uriInput.value = "";
    } catch (error) {
      reportError("URI import failed", error);
      setImportStatus(toUserMessage(error, t("import.invalidUri")), "error");
    }
  });
  importGaBtn?.addEventListener("click", async () => {
    try {
      const source = uriInput.value.trim();
      if (!source) {
        throw new Error(t("import.pasteGaFirst"));
      }
      const migration = collectMigrationPayloads(source);
      if (migration.payloads.length === 0) {
        throw new Error(migration.warnings[0] || t("import.noGaFound"));
      }
      setImportStatus(t("import.decodingGa"));
      stageMigrationPayloads(migration.payloads, "Google Authenticator");
      uriInput.value = "";
    } catch (error) {
      reportError("GA import failed", error);
      setImportStatus(toUserMessage(error, t("import.gaFailed")), "error");
    }
  });
  importAppsInput?.addEventListener("change", async () => {
    const [file] = importAppsInput.files || [];
    if (!file) return;
    setImportStatus(t("import.appsReading"));
    try {
      await importThirdPartyFile(file);
    } catch (error) {
      reportError("Aegis/2FAS import failed", error);
      setImportStatus(toUserMessage(error, t("import.appsFileFailed")), "error");
    } finally {
      importAppsInput.value = "";
    }
  });
  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    const fileNameLabel = document.getElementById("qr-file-name");
    const fileBtn = qrFileInput.closest(".file-btn");
    if (fileNameLabel) fileNameLabel.textContent = file.name;
    fileBtn?.classList.add("has-file");
    setImportStatus(t("import.readingQrFile"));
    try {
      await importFromQrBlob(file, "QR file");
    } catch (error) {
      reportError("QR file import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import QR file"), "error");
    } finally {
      qrFileInput.value = "";
      if (fileNameLabel) fileNameLabel.textContent = t("add.qrFileChoose");
      fileBtn?.classList.remove("has-file");
    }
  });
  importQrUrlBtn.addEventListener("click", async () => {
    const url = (qrUrlInput.value || "").trim();
    if (!url) {
      setImportStatus(t("import.qrUrlRequired"), "error");
      return;
    }
    setImportStatus(t("import.fetchingQrUrl"));
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error(t("import.qrUrlDownloadFailed"));
      await importFromQrBlob(await response.blob(), "QR URL");
    } catch (error) {
      reportError("QR URL import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from URL"), "error");
    }
  });
  importClipboardBtn.addEventListener("click", async () => {
    setImportStatus(t("import.readingClipboard"));
    try {
      if (navigator.clipboard && typeof navigator.clipboard.read === "function") {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          const imageType = item.types.find((type) => type.startsWith("image/"));
          if (!imageType) continue;
          await importFromQrBlob(await item.getType(imageType), "Clipboard image");
          return;
        }
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length > 0) {
        stageMigrationPayloads(migration.payloads, "Clipboard");
        return;
      }
      const uris = extractOtpAuthUris(text);
      if (uris.length === 0) throw new Error(t("import.noClipboardUri"));
      openImportPreview(buildPreviewCandidatesFromUris(uris, "Clipboard"), "Clipboard");
    } catch (error) {
      reportError("Clipboard import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from clipboard"), "error");
    }
  });
  startCameraBtn.addEventListener("click", async () => {
    try {
      setImportStatus(t("import.startingCamera"));
      await startCameraScan();
      setImportStatus(t("import.cameraReady"), "");
    } catch (error) {
      reportError("Camera start failed", error);
      setImportStatus(toUserMessage(error, "Could not start camera"), "error");
    }
  });
  stopCameraBtn.addEventListener("click", () => {
    // Stopping mid-batch imports what was scanned so far (partial import).
    if (migrationScanState?.payloads.length > 0) {
      finishMigrationCameraScan();
      return;
    }
    stopCameraScan();
    setImportStatus(t("import.cameraStopped"));
  });
  clearAllBtn.addEventListener("click", async () => {
    try {
      if (entries.length === 0) {
        setImportStatus(t("vault.noEntriesToClear"), "warning");
        return;
      }
      const confirmed = await showConfirmDialog(
        t("confirm.clearAllTitle"),
        t("confirm.clearAllText", { count: entries.length, plural: entries.length === 1 ? "y" : "ies" })
      );
      if (!confirmed) return;
      await replaceEntries([]);
      setImportStatus(t("vault.allCleared"), "success");
    } catch (error) {
      reportError("Clear all failed", error);
      setImportStatus(toUserMessage(error, t("vault.clearFailed")), "error");
    }
  });
  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });
  sortSelect?.addEventListener("change", () => {
    settings.sortBy = sortSelect.value;
    saveSettings();
    renderEntries();
    tick();
  });
  groupSelect?.addEventListener("change", () => {
    settings.groupBy = groupSelect.value;
    saveSettings();
    renderEntries();
  });
  bulkTagApplyBtn?.addEventListener("click", async () => {
    const extraTags = normalizeTags(bulkTagInput.value);
    if (extraTags.length === 0) {
      setImportStatus(t("vault.tagsRequired"), "warning");
      return;
    }
    try {
      await replaceEntries(entries.map((entry) => selectedEntryIds.has(entry.id) ? { ...entry, tags: normalizeTags([...entry.tags || [], ...extraTags]) } : entry));
      bulkTagInput.value = "";
      setImportStatus(t("vault.tagsApplied"), "success");
    } catch (error) {
      reportError("Bulk tag update failed", error);
      setImportStatus(toUserMessage(error, "Could not update selected entries"), "error");
    }
  });
  bulkRemoveBtn?.addEventListener("click", async () => {
    try {
      const count = selectedEntryIds.size;
      if (count === 0) return;
      const confirmed = await showConfirmDialog(
        t("confirm.bulkRemoveTitle"),
        t("confirm.bulkRemoveText", { count, plural: count === 1 ? "y" : "ies" })
      );
      if (!confirmed) return;
      const removedItems = entries
        .map((entry, index) => ({ entry, index }))
        .filter(({ entry }) => selectedEntryIds.has(entry.id));
      await replaceEntries(entries.filter((entry) => !selectedEntryIds.has(entry.id)));
      selectedEntryIds.clear();
      renderBulkBar();
      setImportStatus(t("vault.selectedRemoved"), "success");
      await offerUndoDelete(removedItems);
    } catch (error) {
      reportError("Bulk remove failed", error);
      setImportStatus(toUserMessage(error, t("vault.bulkRemoveFailed")), "error");
    }
  });
  settingsForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await handleSaveSettings();
    } catch (error) {
      reportError("Save settings failed", error);
      setSettingsStatus(toUserMessage(error, "Could not save settings"), "error");
    }
  });
  exportBackupBtn.addEventListener("click", async () => {
    try {
      await exportBackup();
      setSettingsStatus(t("settings.exportBackupDone"), "success");
    } catch (error) {
      reportError("Backup export failed", error);
      setSettingsStatus(toUserMessage(error, t("settings.exportBackupFailed")), "error");
    }
  });
  changePassphraseBtn?.addEventListener("click", () => {
    if (!changePassphraseDialog?.showModal) return;
    setChangePassphraseStatus("");
    currentPassphraseInput.value = "";
    newPassphraseInput.value = "";
    newPassphraseConfirmInput.value = "";
    changePassphraseDialog.showModal();
  });
  changePassphraseForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await changeVaultPassphrase(
        currentPassphraseInput.value.trim(),
        newPassphraseInput.value.trim(),
        newPassphraseConfirmInput.value.trim()
      );
      setChangePassphraseStatus("");
      changePassphraseDialog.close("accept");
      setSettingsStatus(t("settings.statusPassphraseUpdated"), "success");
    } catch (error) {
      setChangePassphraseStatus(toUserMessage(error, "Could not update passphrase"), "error");
    }
  });
  changePassphraseDialog?.addEventListener("close", () => {
    setChangePassphraseStatus("");
  });
  importBackupInput.addEventListener("change", async () => {
    const [file] = importBackupInput.files || [];
    if (!file) return;
    try {
      await stageBackupImport(file);
    } catch (error) {
      reportError("Backup import failed", error);
      setSettingsStatus(toUserMessage(error, t("settings.statusImportFailed")), "error");
    } finally {
      importBackupInput.value = "";
    }
  });
  lockAppBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setSettingsStatus(t("settings.statusLockRequiresEncryption"), "error");
      return;
    }
    lockVault();
  });
  const settingsDialog = document.getElementById("settings-dialog");
  const historyDialog = document.getElementById("history-dialog");
  document.getElementById("open-add-dialog")?.addEventListener("click", () => openAddDialog("manual"));
  document.getElementById("open-settings-dialog")?.addEventListener("click", () => settingsDialog?.showModal());
  document.getElementById("open-history-dialog")?.addEventListener("click", () => historyDialog?.showModal());
  document.querySelectorAll("[data-sheet-close]").forEach((button) => {
    button.addEventListener("click", () => button.closest("dialog")?.close());
  });
  // Closing the Add sheet by any path (Escape, X, save, backdrop click) must
  // release the camera: the stream and scan timer would otherwise outlive
  // the panel.
  document.getElementById("add-dialog")?.addEventListener("close", stopCameraScan);
  // Clicking the backdrop beside a sheet dismisses it. The pointerdown guard
  // keeps text-selection drags that end outside the sheet from closing it.
  for (const sheetId of ["add-dialog", "settings-dialog", "history-dialog"]) {
    const sheet = document.getElementById(sheetId);
    if (!sheet) continue;
    let backdropPointerDown = false;
    sheet.addEventListener("pointerdown", (event) => {
      backdropPointerDown = event.target === sheet;
    });
    sheet.addEventListener("click", (event) => {
      if (event.target === sheet && backdropPointerDown) sheet.close();
    });
  }
  document.getElementById("biometric-unlock-btn")?.addEventListener("click", () => {
    unlockWithBiometrics();
  });
  document.getElementById("enroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      operationDepth += 1;
      try {
        await enrollVaultBiometrics();
        setSettingsStatus(t("settings.biometricEnabled"), "success");
      } finally {
        operationDepth -= 1;
      }
    } catch (error) {
      reportError("Biometric enrollment failed", error);
      setSettingsStatus(toUserMessage(error, t("vault.biometricEnrollmentFailed")), "error");
      renderBiometricControls();
    }
  });
  document.getElementById("disenroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      operationDepth += 1;
      try {
        await disenrollVaultBiometrics();
      } finally {
        operationDepth -= 1;
      }
    } catch (error) {
      reportError("Biometric disenroll failed", error);
      setSettingsStatus(toUserMessage(error, t("vault.biometricDisenrollFailed")), "error");
    }
  });
  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const guard = readUnlockGuard();
    const now = Date.now();
    if (guard.lockedUntil > now) {
      setUnlockStatus(t("vault.tooManyAttempts", { seconds: Math.ceil((guard.lockedUntil - now) / 1000) }), "error");
      return;
    }
    unlockBtn.disabled = true;
    operationDepth += 1;
    try {
      await unlockVault(unlockPassphraseInput.value);
      writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
      unlockPassphraseInput.value = "";
      setUnlockStatus(t("unlock.statusSuccess"), "success");
    } catch (error) {
      const attempts = guard.attempts + 1;
      const backoff = unlockBackoffSeconds(attempts);
      writeUnlockGuard({ attempts, lockedUntil: attempts >= 3 ? now + backoff * 1000 : 0 });
      const suffix = attempts >= 3 ? t("vault.lockedForSuffix", { seconds: backoff }) : "";
      reportError("Vault unlock failed", error);
      setUnlockStatus(toUserMessage(error, t("unlock.statusFailed")) + suffix, "error");
    } finally {
      operationDepth -= 1;
      unlockBtn.disabled = false;
    }
  });
  installAppBtn.addEventListener("click", async () => {
    if (!deferredInstallPrompt) {
      setSettingsStatus(t("settings.statusInstallUnavailable"), "error");
      return;
    }
    await deferredInstallPrompt.prompt();
    deferredInstallPrompt = null;
  });
  privacyDialog.addEventListener("close", () => {
    if (privacyDialog.returnValue === "accept") {
      markPersistWarningSeen();
      handleSaveSettings().catch((error) => {
        reportError("Save settings after privacy dialog failed", error);
        setSettingsStatus(toUserMessage(error, "Could not save settings"), "error");
      });
    } else {
      persistToggle.checked = settings.persist;
    }
  });
  importPreviewForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await commitImportPreview(importPreviewState);
      importPreviewState = null;
      importDialog.close();
    } catch (error) {
      reportError("Import preview commit failed", error);
      setImportStatus(toUserMessage(error, t("import.commitFailed")), "error");
    }
  });
  importDialog?.addEventListener("close", () => {
    importPreviewState = null;
  });

  backupReviewForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await commitBackupImport();
      backupImportState = null;
      backupReviewDialog.close();
      setSettingsStatus("Backup imported", "success");
    } catch (error) {
      setSettingsStatus(toUserMessage(error, t("settings.statusImportFailed")), "error");
    }
  });
  backupImportMode?.addEventListener("change", () => {
    if (backupImportState?.backup) {
      renderBackupReview(backupImportState.backup);
    }
  });
  backupReviewDialog?.addEventListener("close", () => {
    backupImportState = null;
  });

  editEntryForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await saveEditedEntry();
      editEntryDialog.close();
      setImportStatus(t("entries.updated"), "success");
    } catch (error) {
      setStatus(editEntryStatus, toUserMessage(error, t("vault.updateFailed")), "error");
    }
  });
  editEntryDialog?.addEventListener("close", () => {
    setStatus(editEntryStatus, "");
  });
  copyQrUriBtn?.addEventListener("click", async () => {
    if (!qrExportUri) return;
    try {
      await navigator.clipboard.writeText(qrExportUri);
      setStatus(qrExportStatus, t("qr.copiedUri"), "success");
    } catch (error) {
      reportError("QR URI copy failed", error);
      setStatus(qrExportStatus, toUserMessage(error, t("toast.copyFailed")), "error");
    }
  });
  downloadQrBtn?.addEventListener("click", () => {
    if (!qrExportCanvas) return;
    qrExportCanvas.toBlob((blob) => {
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "otp-entry-qr.png";
      link.click();
      URL.revokeObjectURL(url);
    }, "image/png");
  });
  confirmForm?.addEventListener("submit", (event) => {
    if (event.submitter?.value !== "accept") {
      if (confirmCallback) confirmCallback(false);
      confirmCallback = null;
      return;
    }
    event.preventDefault();
    if (confirmCallback) confirmCallback(true);
    confirmCallback = null;
    confirmDialog?.close();
  });
  confirmDialog?.addEventListener("close", () => {
    if (confirmCallback) confirmCallback(false);
    confirmCallback = null;
  });
}
