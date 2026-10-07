import jsQR from "jsqr";
import {
  compareEntries,
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
  encryptEntries,
  isLegacyEncryptedPayload,
  normalizePassphrase,
  parseBackupFile,
  shouldWarnBackup,
} from './lib/vault.js';

// app.js
var STORAGE_KEY = "personal_otp_vault_entries_v3";
var LEGACY_STORAGE_KEY = "personal_otp_vault_entries_v2";
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
  sortBy: "pinned-alpha",
  groupBy: "none"
};
var settings = loadSettings();
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var currentPassphrase = "";
var staleVaultTab = false;
var UNLOCK_GUARD_KEY = "personal_otp_vault_unlock_guard_v1";
var UNDO_TOMBSTONE_KEY = "personal_otp_vault_undo_tombstone_v1";
var UNDO_TOMBSTONE_TTL_MS = 10 * 60 * 1000;
var UNDO_TOAST_MS = 10000;
var lastActivity = Date.now();
var operationDepth = 0;
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
function initialize() {
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
}
function applyVisualSettings() {
  document.body.classList.toggle("blur-codes", settings.blurCodes);
  document.body.classList.toggle("screenshot-safe", settings.screenshotSafe);
}

function renderWorkspaceSummary() {
  if (!summaryTotal) return;
  const groups = getEntryGroups().filter(([, groupEntries]) => groupEntries.length > 0);
  summaryTotal.textContent = String(entries.length);
  summaryPinned.textContent = String(entries.filter((entry) => entry.pinned).length);
  summaryGroups.textContent = String(settings.groupBy === "none" ? 1 : Math.max(groups.length, 0));

  const isLocked = !unlockPanel.classList.contains("hidden") && settings.encrypt;
  let storageText = settings.persist ? settings.encrypt ? "Encrypted" : "Device" : "Session";
  if (isLocked) {
    storageText += " (Locked)";
  }
  summaryStorage.textContent = storageText;
}

function renderConnectionState() {
  if (!offlineChip) return;
  const online = navigator.onLine !== false;
  offlineChip.textContent = online ? "Online" : "Offline Ready";
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
  if (message) showToast(tone === "error" ? "Import" : "Vault", message, tone || "success");
}
function setSettingsStatus(message, tone = "") {
  setStatus(settingsStatus, message, tone);
  if (message) showToast(tone === "error" ? "Settings" : "Vault", message, tone || "success");
}
function setChangePassphraseStatus(message, tone = "") {
  setStatus(changePassphraseStatus, message, tone);
}
function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}
function renderPassphraseStrength(input, meterRoot) {
  if (!input || !meterRoot) return;
  const assessment = assessPassphraseStrength(input.value);
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
    empty.textContent = "No copied codes yet. The last few copied OTPs appear here for quick recall.";
    copyHistoryRoot.appendChild(empty);
    return;
  }
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
  bulkSummary.textContent = `${selectedCount} selected`;
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
      "Counter save failed — the next code may repeat. Use Edit on this entry to set the counter manually.",
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
    if (tombstone.vault) {
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
    setImportStatus("Nothing to undo — those entries already exist again", "warning");
    return;
  }
  await replaceEntries(nextEntries);
  setImportStatus(`Restored ${reinserted} entr${reinserted === 1 ? "y" : "ies"}`, "success");
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
  strong.textContent = items.length === 1 ? "Entry removed" : `${items.length} entries removed`;
  const undoBtn = document.createElement("button");
  undoBtn.type = "button";
  undoBtn.className = "btn small";
  undoBtn.textContent = "Undo";
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
    line.textContent = "Last export: never";
    return;
  }
  const days = Math.floor((Date.now() - lastBackupAt) / 86400000);
  const hashSuffix = settings.lastBackupHash ? ` (checksum ${String(settings.lastBackupHash).slice(0, 8)})` : "";
  line.textContent = `Last export: ${days === 0 ? "today" : `${days} day${days === 1 ? "" : "s"} ago`}${hashSuffix}. A cancelled download cannot be detected — verify your backup file after exporting.`;
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
  if (!current) throw new Error("Entry no longer exists");
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
    throw new Error("Another entry already uses this secret, digits, and period");
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
function addCopyHistory(label, code) {
  copyHistory = [{
    label,
    code: formatCode(code),
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }, ...copyHistory.filter((item) => item.label !== label)].slice(0, 6);
  renderCopyHistory();
}
function showEmptyState(message, heading = "Vault ready for the first import") {
  entriesRoot.innerHTML = "";
  entriesRoot.innerHTML = `
    <section class="workspace-empty">
      <div class="workspace-empty-copy">
        <p class="entry-group-title">workspace</p>
        <h3>${heading}</h3>
        <p>${message}</p>
        <div class="workspace-empty-actions">
          <button type="button" class="btn small" data-empty-action="focus-secret">Type a secret</button>
          <button type="button" class="btn small" data-empty-action="focus-uri">Paste OTP URI</button>
          <button type="button" class="btn small" data-empty-action="start-camera">Scan a QR</button>
        </div>
      </div>
      <div class="workspace-empty-guide">
        <div class="preview-item">
          <strong>1. Import or type</strong>
          <p>Use Base32, URI, clipboard, QR image, or camera.</p>
        </div>
        <div class="preview-item">
          <strong>2. Review and tag</strong>
          <p>Catch duplicates early and keep the vault organized by project or device.</p>
        </div>
        <div class="preview-item">
          <strong>3. Protect this device</strong>
          <p>Enable persistence only when needed, then add encryption and backups.</p>
        </div>
      </div>
    </section>`;
  entriesRoot.querySelectorAll("[data-empty-action]").forEach((button) => {
    button.addEventListener("click", () => {
      const action = button.getAttribute("data-empty-action");
      if (action === "focus-secret") secretInput.focus();
      if (action === "focus-uri") uriInput.focus();
      if (action === "start-camera") startCameraBtn.click();
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
  avatar.textContent = getIssuerInitials(entry.label);
  refreshEntryMetadata(node, entry);
  renderTagRow(node, entry);
  copyBtn.onclick = async () => {
    try {
      const latestCode = node.dataset.otp;
      if (!latestCode) return;
      await navigator.clipboard.writeText(latestCode);
      addCopyHistory(entry.label, latestCode);
      copyBtn.textContent = "Copied";
      if (settings.clearClipboard) {
        setTimeout(() => {
          navigator.clipboard.writeText("").catch((error) => reportError("Clipboard clear failed", error));
        }, 3e4);
      }
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1e3);
      await consumeHotpCounter(entry, "copy");
    } catch (error) {
      reportError("Copy failed", error);
      showToast("Vault", toUserMessage(error, "Could not copy OTP to clipboard"), "error");
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
      setImportStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Move up failed", error);
      setImportStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  };

  moveDownBtn.onclick = async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      saveSettings();
      await moveEntry(entry.id, 1);
      setImportStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Move down failed", error);
      setImportStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  };
  revealBtn.onclick = async () => {
    node.classList.toggle("revealed");
    const revealed = node.classList.contains("revealed");
    revealBtn.textContent = revealed ? "Hide" : "Reveal";
    // Revealing an HOTP code consumes it: advance the persisted counter.
    if (revealed && entry.type === "hotp") {
      await consumeHotpCounter(entry, "reveal");
    }
  };
  pinBtn.onclick = async () => {
    try {
      await replaceEntries(entries.map((item) => item.id === entry.id ? { ...item, pinned: !item.pinned } : item));
      setImportStatus("Entry order updated", "success");
    } catch (error) {
      reportError("Pin toggle failed", error);
      setImportStatus(toUserMessage(error, "Could not update entry order"), "error");
    }
  };
  removeBtn.onclick = async () => {
    try {
      const confirmed = await showConfirmDialog(
        "Remove this entry?",
        `This will remove "${entry.label}" from your vault. You can undo for 10 seconds.`
      );
      if (!confirmed) return;
      const index = entries.findIndex((item) => item.id === entry.id);
      const nextEntries = entries.filter((item) => item.id !== entry.id);
      await replaceEntries(nextEntries);
      selectedEntryIds.delete(entry.id);
      renderBulkBar();
      setImportStatus("Entry removed", "success");
      if (index >= 0) await offerUndoDelete([{ entry, index }]);
    } catch (error) {
      reportError("Entry removal failed", error);
      setImportStatus(toUserMessage(error, "Could not remove entry"), "error");
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
  node.querySelector(".entry-meta").textContent = `${entry.digits} digits \u2022 ${entry.period}s`;
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
    workspaceHeading.textContent = isLocked ? "Vault Locked" : "Current Codes";
  }
  if (isLocked) {
    showEmptyState("Vault is locked. Unlock to view your codes.");
    return;
  }
  if (entries.length === 0) {
    entryNodes.clear();
    showEmptyState("No entries yet. Import a URI, scan a QR, or add one manually.");
    return;
  }
  const groups = getEntryGroups();
  if (groups.length === 0 || groups.every(([, groupEntries]) => groupEntries.length === 0)) {
    showEmptyState("Adjust the search or clear the filter to see your entries.", "No matching entries");
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
      title.textContent = groupName;
      wrapper.appendChild(title);
    }
    for (const entry of groupEntries) {
      let node = entryNodes.get(entry.id);
      if (!node) {
        node = createEntryNode(entry);
        entryNodes.set(entry.id, node);
      }
      refreshEntryMetadata(node, entry);
      node.classList.toggle("pinned", entry.pinned);
      node.querySelector(".pin").textContent = entry.pinned ? "Unpin" : "Pin";
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
  const copyBtn = node.querySelector(".copy");
  try {
    let otp;
    if (entry.type === "hotp") {
      // HOTP renders the deterministic code for the persisted counter —
      // no rolling timer; the counter advances only on reveal/copy (FR8).
      seconds.textContent = `counter #${entry.counter}`;
      bar.style.transform = "scaleX(1)";
      node.classList.toggle("urgent", false);
      otp = await generateHotp(entry.secret, entry.counter, entry.digits, entry.algorithm);
    } else {
      const remaining = entry.period - now % entry.period;
      seconds.textContent = `${remaining}s left`;
      bar.style.transform = `scaleX(${remaining / entry.period})`;
      node.classList.toggle("urgent", remaining <= 10);
      otp = await generateTotp(entry.secret, entry.digits, entry.period, now, entry.algorithm);
    }
    code.textContent = formatCode(otp);
    node.dataset.otp = otp;
    copyBtn.disabled = false;
  } catch (error) {
    reportError("OTP generation failed", error);
    code.textContent = "Invalid secret";
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
      setUnlockStatus(`Too many failed attempts — unlock available in ${Math.ceil(remainingMs / 1000)}s`, "error");
    } else if (unlockStatus.classList.contains("error") && unlockStatus.textContent.startsWith("Too many failed attempts")) {
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
async function decryptStoredEntries(passphrase) {
  const payload = await readEncryptedVaultPayload();
  if (!payload) return [];
  return decryptVaultEntries(payload, passphrase);
}
async function persistEntries() {
  if (staleVaultTab) {
    throw new Error("Vault changed in another tab — reload this tab to make changes");
  }
  const previousArtifacts = snapshotPersistedVaultArtifacts();
  try {
    if (!settings.persist) {
      clearPersistedEntries();
      return;
    }
    if (settings.encrypt) {
      if (!currentPassphrase) {
        throw new Error("Unlock or set a passphrase before saving encrypted entries");
      }
      await saveEncryptedEntries(entries, currentPassphrase);
      localStorage.removeItem(STORAGE_KEY);
      localStorage.removeItem(LEGACY_STORAGE_KEY);
      return;
    }
    savePlainEntries();
    localStorage.removeItem(ENCRYPTED_VAULT_KEY);
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
    if (skipped > 0) details.push(`${skipped} duplicate${skipped === 1 ? "" : "s"} skipped`);
    if (invalid > 0) details.push(`${invalid} invalid URI${invalid === 1 ? "" : "s"} ignored`);
    throw new Error(`No new entries found from ${sourceLabel}${details.length > 0 ? ` (${details.join(", ")})` : ""}`);
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
    throw new Error(`No importable entries found in the ${sourceLabel} export${warnings.length ? `: ${warnings.join(" ")}` : ""}`);
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
      setImportStatus(`Scanned ${migrationScanState.seenKeys.size} of ${migrationScanState.total} QR codes...`, "warning");
      return;
    }
    if (migrationScanState.total !== null && parsed.batch.size !== migrationScanState.total) {
      setImportStatus("QR codes from different exports detected — restart the scan with one export.", "error");
      migrationScanState = null;
      return;
    }
    migrationScanState.total = parsed.batch.size;
    migrationScanState.seenKeys.add(payloadKey);
    migrationScanState.payloads.push(parsed.payloadBytes);
    if (migrationScanState.seenKeys.size >= migrationScanState.total) {
      setImportStatus("All QR codes scanned.", "success");
      finishMigrationCameraScan();
    } else {
      setImportStatus(`Scanned ${migrationScanState.seenKeys.size} of ${migrationScanState.total} QR codes...`, "warning");
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

  importPreviewTitle.textContent = `Review ${candidates.length} candidate${candidates.length === 1 ? "" : "s"}`;
  let statusText = `${sourceLabel}: only valid, non-duplicate entries are shown below.`;
  if (skipped > 0) {
    statusText += ` Skipped ${skipped} duplicate${skipped === 1 ? "" : "s"}.`;
  }
  if (invalid > 0) {
    statusText += ` Ignored ${invalid} invalid entr${invalid === 1 ? "y" : "ies"}.`;
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
    includeText.textContent = entry.duplicateHint ? "Already in vault" : "Import this entry";
    includeLabel.append(includeInput, includeText);

    const labelField = document.createElement("label");
    const labelText = document.createElement("span");
    labelText.textContent = "Label";
    const labelInput = document.createElement("input");
    labelInput.type = "text";
    labelInput.className = "preview-label";
    labelInput.value = entry.label;
    labelField.append(labelText, labelInput);

    const tagsField = document.createElement("label");
    const tagsText = document.createElement("span");
    tagsText.textContent = "Tags";
    const tagsInput = document.createElement("input");
    tagsInput.type = "text";
    tagsInput.className = "preview-tags";
    tagsInput.value = (entry.tags || []).join(", ");
    tagsInput.placeholder = "project, hardware-key";
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
  if (enriched.length === 0) throw new Error("Select at least one entry to import");
  await replaceEntries([...entries, ...enriched]);
  setImportStatus(`${sourceLabel}: imported ${enriched.length} entr${enriched.length === 1 ? "y" : "ies"}`, "success");
}
async function importOtpAuthUri(otpUri, sourceLabel = "Import") {
  const parsed = normalizeEntry({ ...parseOtpAuthUri(otpUri), order: nextOrderValueFrom(entries) });
  if (hasDuplicateEntry(entries, parsed)) {
    throw new Error("This account already exists");
  }
  await replaceEntries([...entries, parsed]);
  setImportStatus(`${sourceLabel}: account imported`, "success");
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
    throw new Error("Could not detect a QR code in that image");
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
  if (uris.length === 0) throw new Error("QR code was detected but does not contain a valid OTP URI");
  const candidates = buildPreviewCandidatesFromUris(uris, sourceLabel);
  openImportPreview(candidates, sourceLabel);
}
async function unlockVault(passphrase) {
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const payload = await readEncryptedVaultPayload();
  const decrypted = payload ? await decryptVaultEntries(payload, normalizedPassphrase) : [];
  currentPassphrase = normalizedPassphrase;
  entries = decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
  setLocked(false);
  renderEntries();
  await tick();
  await upgradeLegacyEncryptedVault(payload);
  await offerUndoFromTombstone();
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
    const needsInitialPassphrase = !settings.encrypt || !settings.persist || !currentPassphrase;
    if (needsInitialPassphrase && !vaultPassphraseInput.value.trim()) {
      throw new Error("Enter a passphrase to enable encryption");
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
    sortBy: sortSelect.value,
    groupBy: groupSelect.value
  };
  let nextPassphrase = currentPassphrase;
  if (nextSettings.encrypt) {
    const first = vaultPassphraseInput.value.trim();
    const second = vaultPassphraseConfirmInput.value.trim();
    const needsInitialPassphrase = !settings.encrypt || !settings.persist || !currentPassphrase;
    if (needsInitialPassphrase && !first) {
      throw new Error("Enter a passphrase to enable encryption");
    }
    if (needsInitialPassphrase || first || second) {
      if (settings.encrypt && settings.persist && currentPassphrase && (first || second)) {
        nextPassphrase = currentPassphrase;
      } else {
        if (first !== second) {
          throw new Error("Passphrase confirmation does not match");
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
  try {
    saveSettings();
    if (!settings.persist) {
      clearPersistedEntries();
      syncSettingsUI();
      setLocked(false);
      setSettingsStatus("Entries are now session-only", "success");
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
    throw error;
  }
  setLocked(false);
  const encryptedVaultExists = settings.persist && settings.encrypt && Boolean(currentPassphrase || localStorage.getItem(ENCRYPTED_VAULT_KEY));
  setSettingsStatus(
    encryptedVaultExists ? "Encrypted vault saved. Use Change Passphrase to rotate your vault secret." : settings.encrypt ? "Encrypted vault saved" : "Device storage updated",
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
  let envelope;
  if (settings.encrypt) {
    if (!currentPassphrase) {
      throw new Error("Unlock the vault before exporting encrypted backup");
    }
    const encryptedPayload = await encryptEntries(entries, currentPassphrase);
    envelope = await createEncryptedBackup(encryptedPayload);
  } else {
    envelope = await createPlainBackup(entries);
  }
  downloadJson("otp-vault-backup.json", envelope);
  await stampBackupExport(envelope);
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
    throw new Error("Enable encrypted device storage before changing the vault passphrase");
  }
  if (!currentPassphrase) {
    throw new Error("Unlock the vault before changing the passphrase");
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    throw new Error("Current passphrase is incorrect");
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    throw new Error("Passphrase confirmation does not match");
  }
  const normalizedNextPassphrase = normalizePassphrase(nextPassphraseCandidate);
  const previousPassphrase = currentPassphrase;
  currentPassphrase = normalizedNextPassphrase;
  try {
    await persistEntries();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
}
function renderBackupReview(backup) {
  if (!backupReviewSummary) return;
  backupReviewSummary.innerHTML = "";

  const backupEntries = backup.entries || [];
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");

  let summaryItems = [
    `Integrity: ${backup.integrity === "verified" ? "verified checksum" : "legacy backup"}`,
    `Encrypted: ${backup.encrypted ? "yes" : "no"}`,
    `Schema: v${backup.schemaVersion}`,
    `Created: ${backup.createdAt || "unknown"}`,
    `Incoming items: ${backup.itemCount}`,
    `Current vault size: ${entries.length}`
  ];

  if (backup.invalidItemCount > 0) {
    summaryItems.push(`Review: ${backup.invalidItemCount} invalid item${backup.invalidItemCount === 1 ? "" : "s"} skipped before import`);
  }

  if (mode === "merge" && backupEntries.length > 0 && entries.length > 0) {
    const duplicates = backupEntries.filter((candidate) =>
      entries.some((entry) => entryKey(entry) === entryKey(candidate))
    ).length;
    const newEntries = backupEntries.length - duplicates;
    summaryItems.push(`Merge: ${newEntries} new, ${duplicates} duplicate${duplicates === 1 ? "" : "s"} skipped`);
  }

  summaryItems.forEach((item) => {
    const row = document.createElement("div");
    row.className = "preview-item";
    row.textContent = item;
    backupReviewSummary.appendChild(row);
  });
  backupPassphraseRow?.classList.toggle("hidden", !backup.encrypted);
  setStatus(
    backupReviewStatus,
    backup.integrity === "verified" ? "Backup checksum verified. Choose merge to keep existing entries or replace to overwrite the vault." : "Legacy backup detected. Import is supported, but integrity could not be verified.",
    backup.integrity === "verified" ? "success" : "warning"
  );
}
async function importBackupFile(file, backup = null) {
  const resolvedBackup = backup || await (async () => {
    const text = await file.text();
    let rawBackup;
    try {
      rawBackup = JSON.parse(text);
    } catch (error) {
      throw new Error("Backup file is not valid JSON");
    }
    try {
      return await parseBackupFile(rawBackup);
    } catch (error) {
      throw new Error(toUserMessage(error, "Backup file is invalid"));
    }
  })();
  if (resolvedBackup.integrity === "legacy") {
    setSettingsStatus("Legacy backup detected. Importing without checksum verification.", "warning");
  }
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");
  if (resolvedBackup.encrypted) {
    const passphrase = backupImportPassphraseInput?.value.trim() || window.prompt("Backup is encrypted. Enter the backup passphrase:");
    if (!passphrase) throw new Error("Backup import cancelled");
    const decrypted = await decryptVaultEntries(resolvedBackup.vault, passphrase);
    const nextEntries2 = mode === "replace" ? decrypted : [...entries, ...decrypted.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
    await replaceEntries(nextEntries2);
    return;
  }
  const nextEntries = mode === "replace" ? resolvedBackup.entries : [...entries, ...resolvedBackup.entries.filter((candidate) => !entries.some((entry) => entryKey(entry) === entryKey(candidate)))];
  await replaceEntries(nextEntries);
}
async function stageBackupImport(file) {
  const text = await file.text();
  let rawBackup;
  try {
    rawBackup = JSON.parse(text);
  } catch (error) {
    throw new Error("Backup file is not valid JSON");
  }
  let backup;
  try {
    backup = await parseBackupFile(rawBackup);
  } catch (error) {
    throw new Error(toUserMessage(error, "Backup file is invalid"));
  }
  backupImportState = { file, backup };
  if (backupImportMode) backupImportMode.value = entries.length > 0 ? "merge" : "replace";
  if (backupImportPassphraseInput) backupImportPassphraseInput.value = "";
  renderBackupReview(backup);
  if (backupReviewDialog?.showModal) {
    backupReviewDialog.showModal();
    return;
  }
  await importBackupFile(file, backup);
}
async function commitBackupImport() {
  if (!backupImportState) return;
  const mode = backupImportMode?.value || (entries.length > 0 ? "merge" : "replace");
  if (mode === "replace" && entries.length > 0) {
    const confirmed = await showConfirmDialog(
      "Replace entire vault?",
      `This will delete all ${entries.length} existing entr${entries.length === 1 ? "y" : "ies"} and replace them with the backup contents. This action cannot be undone.`
    );
    if (!confirmed) {
      setSettingsStatus("Backup import cancelled", "warning");
      return;
    }
  }
  await importBackupFile(backupImportState.file, backupImportState.backup);
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
      setImportStatus("Potential OTP QR detected. Confirming with another frame...", "warning");
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
      setSettingsStatus("Enable the time-drift check first", "warning");
      return;
    }
    await checkTimeDrift();
    setSettingsStatus("Time check complete — see the banner if your clock is off", "success");
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
      setImportStatus("Entry added", "success");
    } catch (error) {
      reportError("Manual entry failed", error);
      setImportStatus(toUserMessage(error, "Could not add entry"), "error");
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
      if (uris.length === 0) throw new Error("No valid otpauth:// URI found");
      openImportPreview(buildPreviewCandidatesFromUris(uris, "URI"), "URI");
      uriInput.value = "";
    } catch (error) {
      reportError("URI import failed", error);
      setImportStatus(toUserMessage(error, "Invalid URI"), "error");
    }
  });
  importGaBtn?.addEventListener("click", async () => {
    try {
      const source = uriInput.value.trim();
      if (!source) {
        throw new Error("Paste your Google Authenticator export (the otpauth-migration:// text or URI) first");
      }
      const migration = collectMigrationPayloads(source);
      if (migration.payloads.length === 0) {
        throw new Error(migration.warnings[0] || "No Google Authenticator export found in the pasted text");
      }
      setImportStatus("Decoding Google Authenticator export...");
      stageMigrationPayloads(migration.payloads, "Google Authenticator");
      uriInput.value = "";
    } catch (error) {
      reportError("GA import failed", error);
      setImportStatus(toUserMessage(error, "Could not import the Google Authenticator export"), "error");
    }
  });
  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    setImportStatus("Reading QR file...");
    try {
      await importFromQrBlob(file, "QR file");
    } catch (error) {
      reportError("QR file import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import QR file"), "error");
    } finally {
      qrFileInput.value = "";
    }
  });
  importQrUrlBtn.addEventListener("click", async () => {
    const url = (qrUrlInput.value || "").trim();
    if (!url) {
      setImportStatus("Please enter a QR image URL", "error");
      return;
    }
    setImportStatus("Fetching QR image URL...");
    try {
      const response = await fetch(url);
      if (!response.ok) throw new Error("Could not download QR image URL");
      await importFromQrBlob(await response.blob(), "QR URL");
    } catch (error) {
      reportError("QR URL import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from URL"), "error");
    }
  });
  importClipboardBtn.addEventListener("click", async () => {
    setImportStatus("Reading clipboard...");
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
      if (uris.length === 0) throw new Error("Clipboard does not contain a valid OTP URI or QR image");
      openImportPreview(buildPreviewCandidatesFromUris(uris, "Clipboard"), "Clipboard");
    } catch (error) {
      reportError("Clipboard import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from clipboard"), "error");
    }
  });
  startCameraBtn.addEventListener("click", async () => {
    try {
      setImportStatus("Starting camera...");
      await startCameraScan();
      setImportStatus("Camera ready. Hold a QR code in front of it.", "");
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
    setImportStatus("Camera stopped");
  });
  clearAllBtn.addEventListener("click", async () => {
    try {
      if (entries.length === 0) {
        setImportStatus("No entries to clear", "warning");
        return;
      }
      const confirmed = await showConfirmDialog(
        "Clear all entries?",
        `This will permanently remove all ${entries.length} entr${entries.length === 1 ? "y" : "ies"} from your vault. This action cannot be undone.`
      );
      if (!confirmed) return;
      await replaceEntries([]);
      setImportStatus("All entries cleared", "success");
    } catch (error) {
      reportError("Clear all failed", error);
      setImportStatus(toUserMessage(error, "Could not clear entries"), "error");
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
      setImportStatus("Enter at least one tag for the selected entries", "warning");
      return;
    }
    try {
      await replaceEntries(entries.map((entry) => selectedEntryIds.has(entry.id) ? { ...entry, tags: normalizeTags([...entry.tags || [], ...extraTags]) } : entry));
      bulkTagInput.value = "";
      setImportStatus("Tags applied to selected entries", "success");
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
        "Remove selected entries?",
        `This will remove ${count} selected entr${count === 1 ? "y" : "ies"} from your vault. You can undo for 10 seconds.`
      );
      if (!confirmed) return;
      const removedItems = entries
        .map((entry, index) => ({ entry, index }))
        .filter(({ entry }) => selectedEntryIds.has(entry.id));
      await replaceEntries(entries.filter((entry) => !selectedEntryIds.has(entry.id)));
      selectedEntryIds.clear();
      renderBulkBar();
      setImportStatus("Selected entries removed", "success");
      await offerUndoDelete(removedItems);
    } catch (error) {
      reportError("Bulk remove failed", error);
      setImportStatus(toUserMessage(error, "Could not remove selected entries"), "error");
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
      setSettingsStatus("Backup exported", "success");
    } catch (error) {
      reportError("Backup export failed", error);
      setSettingsStatus(toUserMessage(error, "Could not export backup"), "error");
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
      setSettingsStatus("Vault passphrase updated", "success");
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
      setSettingsStatus(toUserMessage(error, "Could not import backup"), "error");
    } finally {
      importBackupInput.value = "";
    }
  });
  lockAppBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setSettingsStatus("Enable encrypted storage to use lock/unlock", "error");
      return;
    }
    lockVault();
  });
  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const guard = readUnlockGuard();
    const now = Date.now();
    if (guard.lockedUntil > now) {
      setUnlockStatus(`Too many failed attempts — unlock available in ${Math.ceil((guard.lockedUntil - now) / 1000)}s`, "error");
      return;
    }
    unlockBtn.disabled = true;
    operationDepth += 1;
    try {
      await unlockVault(unlockPassphraseInput.value);
      writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
      unlockPassphraseInput.value = "";
      setUnlockStatus("Vault unlocked", "success");
    } catch (error) {
      const attempts = guard.attempts + 1;
      const backoff = unlockBackoffSeconds(attempts);
      writeUnlockGuard({ attempts, lockedUntil: attempts >= 3 ? now + backoff * 1000 : 0 });
      const suffix = attempts >= 3 ? ` Locked for ${backoff}s.` : "";
      reportError("Vault unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted vault") + suffix, "error");
    } finally {
      operationDepth -= 1;
      unlockBtn.disabled = false;
    }
  });
  installAppBtn.addEventListener("click", async () => {
    if (!deferredInstallPrompt) {
      setSettingsStatus("Install prompt is not available yet on this browser", "error");
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
      setImportStatus(toUserMessage(error, "Could not import entries"), "error");
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
      setSettingsStatus(toUserMessage(error, "Could not import backup"), "error");
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
      setImportStatus("Entry updated", "success");
    } catch (error) {
      setStatus(editEntryStatus, toUserMessage(error, "Could not update entry"), "error");
    }
  });
  editEntryDialog?.addEventListener("close", () => {
    setStatus(editEntryStatus, "");
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
