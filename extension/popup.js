import {
  extractMigrationUris,
  extractOtpAuthUri,
  formatCode,
  generateHotp,
  generateTotp,
  getIssuerInitials,
  hasDuplicateEntry,
  normalizeEntries,
  normalizeEntry,
  normalizeTags,
  parseLabelParts,
  parseOtpAuthUri,
  reportError,
  toUserMessage,
} from "../lib/otp.js";
import {
  migrationToEntryCandidates,
  parseMigrationUri,
  stitchMigrationBatches,
} from "../lib/migration.js";
import {
  assessPassphraseStrength,
  createEncryptedBackup,
  createPlainBackup,
  decryptVaultEntries,
  decryptVaultEntriesWithKey,
  deriveVaultKeyFromPayload,
  encryptEntries,
  encryptEntriesWithDek,
  generateVaultDek,
  isDekEncryptedPayload,
  isLegacyEncryptedPayload,
  KDF_PARAMS_DEFAULT,
  normalizePassphrase,
  shouldWarnBackup,
  unwrapDekWithPassphrase,
  wrapDekWithPassphrase,
} from "../lib/vault.js";
import {
  deriveKek,
  enrollBiometricUnlock,
  fromB64u,
  prfCapable,
  runAssertCeremony,
  toB64u,
  unwrapDek,
  wrapDek,
} from "../lib/biometric.js";

const STORAGE_KEY = "otp_extension_entries_v3";
const LEGACY_STORAGE_KEY = "otp_extension_entries_v2";
const ENCRYPTED_KEY = "otp_extension_encrypted_v1";
const BIOMETRIC_KEY = "otp_extension_biometric_v1";
const SETTINGS_KEY = "otp_extension_settings_v1";
const UI_KEY = "otp_extension_ui_v1";
const SESSION_UNLOCK_KEY = "otp_extension_session_unlock_v1";
const UNLOCK_GUARD_KEY = "otp_extension_unlock_guard_v1";
const UNDO_TOMBSTONE_KEY = "otp_extension_undo_tombstone_v1";
const UNDO_TOMBSTONE_TTL_MS = 10 * 60 * 1000;
const UNDO_TOAST_MS = 10000;

const form = document.getElementById("entry-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const tagsInput = document.getElementById("tags");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
const entryTypeSelect = document.getElementById("entry-type");
const counterInput = document.getElementById("counter");
const algorithmSelect = document.getElementById("algorithm");
const qrFileInput = document.getElementById("qr-file");
const searchInput = document.getElementById("search");
const sortSelect = document.getElementById("sort-select");
const pasteUriBtn = document.getElementById("paste-uri");
const toggleFormBtn = document.getElementById("toggle-form");
const lockBtn = document.getElementById("lock-btn");
const statusNode = document.getElementById("status");
const entriesRoot = document.getElementById("entries");
const globalSeconds = document.getElementById("global-seconds");
const globalBar = document.getElementById("global-bar");
const template = document.getElementById("entry-template");
const unlockPanel = document.getElementById("unlock-panel");
const unlockPassphraseInput = document.getElementById("unlock-passphrase");
const unlockBtn = document.getElementById("unlock-btn");
const unlockStatus = document.getElementById("unlock-status");
const encryptToggle = document.getElementById("encrypt-toggle");
const passphraseFields = document.getElementById("passphrase-fields");
const passphraseGuidance = document.getElementById("passphrase-guidance");
const passphraseInput = document.getElementById("passphrase");
const passphraseConfirmInput = document.getElementById("passphrase-confirm");
const changePassphraseBtn = document.getElementById("change-passphrase-btn");
const changePassphraseForm = document.getElementById("change-passphrase-form");
const currentPassphraseInput = document.getElementById("current-passphrase");
const newPassphraseInput = document.getElementById("new-passphrase");
const newPassphraseConfirmInput = document.getElementById("new-passphrase-confirm");
const saveSecurityBtn = document.getElementById("save-security");
const copyHistoryRoot = document.getElementById("copy-history");
const unlockForm = document.getElementById("unlock-form");
const securityForm = document.getElementById("security-form");
const editEntryForm = document.getElementById("edit-entry-form");
const editEntryDialog = document.getElementById("edit-entry-dialog");
const editEntryIdInput = document.getElementById("edit-entry-id");
const editLabelInput = document.getElementById("edit-label");
const editSecretInput = document.getElementById("edit-secret");
const editTagsInput = document.getElementById("edit-tags");
const editDigitsInput = document.getElementById("edit-digits");
const editPeriodInput = document.getElementById("edit-period");
const editCounterInput = document.getElementById("edit-counter");
const editAlgorithmSelect = document.getElementById("edit-algorithm");
const editStatus = document.getElementById("edit-status");
const cancelEditBtn = document.getElementById("cancel-edit");
const saveEditBtn = document.getElementById("save-edit");
const confirmRemoveDialog = document.getElementById("confirm-remove-dialog");
const confirmRemoveMessage = document.getElementById("confirm-remove-message");
const pasteGaBtn = document.getElementById("paste-ga");
const exportBackupBtn = document.getElementById("export-backup");
const migrationPreviewDialog = document.getElementById("migration-preview-dialog");
const migrationPreviewForm = document.getElementById("migration-preview-form");
const migrationPreviewStatus = document.getElementById("migration-preview-status");
const migrationPreviewList = document.getElementById("migration-preview-list");

let entries = [];
let entryNodes = new Map();
let collapsed = false;
let settings = { encrypt: false, sortBy: "alpha" };
let currentPassphrase = "";
let heldDek = null;         // CryptoKey held between unlock and lock (biometric/DEK mode)
let dekEnvelopeMeta = null; // { salt, kdf, dek } — stable across DEK-mode saves
let biometricCapable = false;
let copyHistory = [];
let confirmRemoveCallback = null;
let lastActivity = Date.now();
let migrationPreviewState = null;
let undoTombstone = null; // live undo items offered on this popup open

initialize();

async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, sortBy: "alpha", autoLockMinutes: 15, timeDriftCheck: false, ...(stored[SETTINGS_KEY] || {}) };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
  const autoLockSelect = document.getElementById("auto-lock-select");
  if (autoLockSelect) autoLockSelect.value = String(settings.autoLockMinutes ?? 15);
  const timeDriftToggle = document.getElementById("time-drift-toggle");
  if (timeDriftToggle) timeDriftToggle.checked = Boolean(settings.timeDriftCheck);
  const hasExistingEncryptedVault = Boolean(settings.encrypt && stored[ENCRYPTED_KEY]);
  passphraseFields.classList.toggle("hidden", !settings.encrypt || hasExistingEncryptedVault);
  passphraseGuidance?.classList.toggle("hidden", !hasExistingEncryptedVault);
  applyUiState();

  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    // Session-cache fast path: a live cached CryptoKey decrypts without the
    // 600k PBKDF2 cost; in DEK mode the cached handle IS the vault DEK.
    const cached = await readSessionUnlock(stored[ENCRYPTED_KEY]);
    if (cached) {
      entries = cached.entries;
      currentPassphrase = cached.passphrase;
      if (isDekEncryptedPayload(stored[ENCRYPTED_KEY])) {
        heldDek = cached.keyHandle;
        dekEnvelopeMeta = extractDekEnvelopeMeta(stored[ENCRYPTED_KEY]);
      }
      if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
      setLocked(false);
      await offerUndoFromTombstone();
    } else {
      setLocked(true);
    }
  } else {
    // v3 authoritative; legacy v2 consulted only while v3 is absent (and
    // never deleted — older bundles may still read it).
    const rawEntries = stored[STORAGE_KEY] ?? stored[LEGACY_STORAGE_KEY];
    entries = normalizeEntries(rawEntries);
    if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
    setLocked(false);
    await offerUndoFromTombstone();
  }

  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    await reconcileOrphanedBiometricRecord();
  }
  bindEvents();
  bindPassphraseStrengthMeters();
  bindAutoLockActivity();
  renderEntries();
  renderCopyHistory();
  renderBackupReminder();
  renderBiometricControls();
  tick();
  setInterval(tick, 1000);
  prfCapable().then((capable) => {
    biometricCapable = capable;
    renderBiometricControls();
  }).catch(() => {
    biometricCapable = false;
    renderBiometricControls();
  });
}

async function readSessionUnlock(encryptedPayload) {
  try {
    const cached = (await chrome.storage.session.get(SESSION_UNLOCK_KEY))[SESSION_UNLOCK_KEY];
    if (!cached || !cached.keyHandle || typeof cached.passphrase !== "string") return null;
    const entriesDecrypted = await decryptVaultEntriesWithKey(cached.keyHandle, encryptedPayload);
    return { entries: entriesDecrypted, passphrase: cached.passphrase, keyHandle: cached.keyHandle };
  } catch (error) {
    reportError("Session unlock cache miss or invalid", error);
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
    return null;
  }
}

async function writeSessionUnlock(encryptedPayload, passphrase, keyHandle) {
  try {
    await chrome.storage.session.set({ [SESSION_UNLOCK_KEY]: { passphrase, keyHandle } });
  } catch (error) {
    reportError("Session unlock cache write failed", error);
  }
}

async function clearSessionUnlock() {
  try {
    await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
  } catch (error) {
    reportError("Session unlock cache clear failed", error);
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
async function readBiometricRecord() {
  try {
    const stored = await chrome.storage.local.get(BIOMETRIC_KEY);
    const record = stored[BIOMETRIC_KEY];
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
async function writeBiometricRecord(record) {
  await chrome.storage.local.set({ [BIOMETRIC_KEY]: record });
}
async function removeBiometricRecord() {
  await chrome.storage.local.remove(BIOMETRIC_KEY);
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
async function reconcileOrphanedBiometricRecord() {
  const record = await readBiometricRecord();
  if (!record) return;
  let payload = null;
  try {
    const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
    payload = stored[ENCRYPTED_KEY] ?? null;
  } catch {
    payload = null;
  }
  if (isDekEncryptedPayload(payload)) return;
  await removeBiometricRecord();
  renderBiometricControls();
}
// FR12: one passphrase re-entry per sensitive operation when the session is
// biometric-only (heldDek without currentPassphrase); verified fail-closed by
// unwrapping the DEK. The caller releases the passphrase after the operation.
async function requirePassphrase(actionLabel) {
  if (currentPassphrase) return currentPassphrase;
  if (!heldDek) return "";
  const candidate = window.prompt(`Enter your vault passphrase to ${actionLabel}:`);
  if (!candidate) throw new Error("Vault passphrase required for this action");
  const normalized = normalizePassphrase(candidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    throw new Error("Vault passphrase required for this action");
  }
  heldDek = await unwrapDekWithPassphrase(payload, normalized);
  dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  currentPassphrase = normalized;
  await writeSessionUnlock(payload, normalized, heldDek);
  return currentPassphrase;
}
function releasePassphrase(previousPassphrase) {
  if (!previousPassphrase) currentPassphrase = "";
}
// DEK-mode session cache: the cached handle is the DEK itself (passphrase may
// be empty after a biometric unlock), so a popup reopen skips the ceremony.
async function refreshSessionCacheForDek(payload) {
  if (!heldDek) return;
  await writeSessionUnlock(payload, currentPassphrase, heldDek);
}

function applyUiState() {
  document.body.classList.toggle("collapsed", collapsed);
  toggleFormBtn.textContent = collapsed ? "Show" : "Hide";
}

async function saveUiState() {
  await chrome.storage.local.set({ [UI_KEY]: { collapsed } });
}

function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success");
  if (tone) node.classList.add(tone);
}

function setMainStatus(message, tone = "") {
  setStatus(statusNode, message, tone);
}

function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
}

// The single lock path (manual Lock button AND idle auto-lock): clears the
// passphrase, the session-cache key, and sensitive in-memory state.
function lockVault() {
  currentPassphrase = "";
  heldDek = null;
  dekEnvelopeMeta = null;
  if (unlockPassphraseInput) unlockPassphraseInput.value = "";
  setUnlockStatus("");
  entries = [];
  if (settings.clearClipboard) {
    copyHistory = [];
    renderCopyHistory();
  }
  clearSessionUnlock();
  undoTombstone = null;
  purgeUndoTombstone();
  setLocked(true);
  renderEntries();
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
}

async function readUnlockGuard() {
  try {
    const stored = await chrome.storage.local.get(UNLOCK_GUARD_KEY);
    const parsed = stored[UNLOCK_GUARD_KEY];
    return { attempts: Number(parsed?.attempts) || 0, lockedUntil: Number(parsed?.lockedUntil) || 0 };
  } catch {
    return { attempts: 0, lockedUntil: 0 };
  }
}

function writeUnlockGuard(guard) {
  return chrome.storage.local.set({ [UNLOCK_GUARD_KEY]: guard });
}

function unlockBackoffSeconds(attempts) {
  return Math.min(60, 2 ** Math.max(0, attempts - 3));
}

// --- Google Authenticator migration import (Phase 4) ---

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
      if (hasDuplicateEntry(entries, entry) || candidates.some((existing) => existing.secret === entry.secret && existing.label === entry.label)) {
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

  openMigrationPreview({ candidates, skipped, invalid, warnings, sourceLabel });
}

function openMigrationPreview(previewResult) {
  migrationPreviewState = previewResult;
  renderMigrationPreview();
  migrationPreviewDialog?.showModal?.();
}

function renderMigrationPreview() {
  if (!migrationPreviewState || !migrationPreviewList) return;
  const { candidates, skipped, invalid, warnings, sourceLabel } = migrationPreviewState;

  let statusText = `${sourceLabel}: ${candidates.length} entr${candidates.length === 1 ? "y" : "ies"} found.`;
  if (skipped > 0) statusText += ` ${skipped} duplicate${skipped === 1 ? "" : "s"} pre-unchecked.`;
  if (invalid > 0) statusText += ` ${invalid} could not be mapped.`;
  if (warnings.length > 0) statusText += ` ${warnings.join(" ")}`;
  migrationPreviewStatus.textContent = statusText;
  migrationPreviewList.innerHTML = "";

  candidates.forEach((entry, index) => {
    const row = document.createElement("label");
    row.className = "toggle-row";
    row.dataset.index = String(index);

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "migration-include";
    checkbox.checked = !entry.duplicateHint;

    const summaryParts = [entry.label, `${entry.digits} digits`];
    if (entry.type === "hotp") summaryParts.push(`HOTP #${entry.counter}`);
    if (entry.algorithm && entry.algorithm !== "SHA1") summaryParts.push(entry.algorithm.replace(/^SHA/, "SHA-"));
    const text = document.createElement("span");
    text.textContent = entry.duplicateHint ? `${summaryParts.join(" • ")} (already in vault)` : summaryParts.join(" • ");

    row.append(checkbox, text);
    migrationPreviewList.appendChild(row);
  });
}

async function commitMigrationPreview() {
  if (!migrationPreviewState) return;
  const rows = [...migrationPreviewList.querySelectorAll(".toggle-row")];
  const nextOrder = nextOrderValueFrom(entries);
  const selected = rows.flatMap((row, index) => {
    const checkbox = row.querySelector(".migration-include");
    if (!checkbox?.checked) return [];
    const candidate = migrationPreviewState.candidates[index];
    return [normalizeEntry({ ...candidate, order: nextOrder + index })];
  });
  if (selected.length === 0) throw new Error("Select at least one entry to import");
  await replaceEntries([...entries, ...selected]);
  migrationPreviewState = null;
}

// --- Undo delete with pending-purge tombstone (Phase 5) ---
// The tombstone survives popup teardown: a freshly opened popup offers Undo
// from storage before the 10-minute purge.

async function writeUndoTombstone(items) {
  try {
    if (!settings.encrypt) {
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes: items.map((item) => item.index), entries: items.map((item) => item.entry) },
      });
      return;
    }
    const indexes = items.map((item) => item.index);
    const deletedEntries = items.map((item) => item.entry);
    if (currentPassphrase) {
      const vault = await encryptEntries(deletedEntries, currentPassphrase);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, vault },
      });
      return;
    }
    if (heldDek && dekEnvelopeMeta) {
      // Biometric-only session: encrypt under the held DEK (no passphrase).
      const dekVault = await encryptEntriesWithDek(deletedEntries, heldDek, dekEnvelopeMeta);
      await chrome.storage.local.set({
        [UNDO_TOMBSTONE_KEY]: { at: Date.now(), indexes, dekVault },
      });
    }
  } catch (error) {
    reportError("Undo tombstone write failed", error);
  }
}

async function purgeUndoTombstone() {
  await chrome.storage.local.remove(UNDO_TOMBSTONE_KEY);
}

async function readLiveUndoTombstone() {
  try {
    const stored = await chrome.storage.local.get(UNDO_TOMBSTONE_KEY);
    const tombstone = stored[UNDO_TOMBSTONE_KEY];
    if (!tombstone || typeof tombstone.at !== "number" || Date.now() - tombstone.at > UNDO_TOMBSTONE_TTL_MS) {
      await purgeUndoTombstone();
      return null;
    }
    let deletedEntries = tombstone.entries || [];
    if (tombstone.dekVault) {
      if (!heldDek) {
        await purgeUndoTombstone();
        return null;
      }
      deletedEntries = await decryptVaultEntriesWithKey(heldDek, tombstone.dekVault);
    } else if (tombstone.vault) {
      deletedEntries = await decryptVaultEntries(tombstone.vault, currentPassphrase);
    }
    if (!Array.isArray(deletedEntries) || deletedEntries.length === 0) {
      await purgeUndoTombstone();
      return null;
    }
    const indexes = Array.isArray(tombstone.indexes) ? tombstone.indexes : [];
    return deletedEntries.map((entry, position) => ({ entry, index: indexes[position] ?? position }));
  } catch (error) {
    reportError("Undo tombstone read failed", error);
    await purgeUndoTombstone();
    return null;
  }
}

async function undoDelete(items) {
  undoTombstone = null;
  await purgeUndoTombstone();
  let reinserted = 0;
  const nextEntries = [...entries];
  for (const { entry, index } of items) {
    if (nextEntries.some((existing) => existing.id === entry.id)) continue;
    nextEntries.splice(Math.min(Math.max(index, 0), nextEntries.length), 0, entry);
    reinserted += 1;
  }
  if (reinserted === 0) {
    setMainStatus("Nothing to undo — those entries already exist again", "warning");
    return;
  }
  await replaceEntries(nextEntries);
  setMainStatus(`Restored ${reinserted} entr${reinserted === 1 ? "y" : "ies"}`, "success");
}

async function offerUndoDelete(items) {
  await writeUndoTombstone(items);
  undoTombstone = items;
  setMainStatus(`${items.length === 1 ? "Entry removed" : `${items.length} entries removed`} — reopening this popup offers Undo for 10 minutes`, "warning");
  setTimeout(async () => {
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOAST_MS);
}

async function offerUndoFromTombstone() {
  if (undoTombstone || !unlockPanel.classList.contains("hidden")) return;
  const items = await readLiveUndoTombstone();
  if (!items) return;
  undoTombstone = items;
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = items.length === 1
    ? "An entry was deleted before this popup closed. Undo?"
    : `${items.length} entries were deleted before this popup closed. Undo?`;
  status.classList.add("error");
  const undoBtn = document.createElement("button");
  undoBtn.type = "button";
  undoBtn.className = "ghost-btn";
  undoBtn.textContent = "Undo delete";
  undoBtn.addEventListener("click", async () => {
    undoBtn.remove();
    await undoDelete(items);
  });
  status.appendChild(document.createElement("br"));
  status.appendChild(undoBtn);
  setTimeout(async () => {
    undoBtn.remove();
    if (undoTombstone === items) {
      undoTombstone = null;
      await purgeUndoTombstone();
    }
  }, UNDO_TOMBSTONE_TTL_MS);
}

// --- Backup export + reminder (Phase 5) ---

function parseTraceTimestamp(text) {
  const match = /(?:^|\n)ts=([0-9.]+)/.exec(text || "");
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) ? seconds * 1000 : null;
}

async function stampBackupExport(envelope) {
  settings.lastBackupAt = Date.now();
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(envelope.payload)));
  settings.lastBackupHash = [...new Uint8Array(digest)].map((part) => part.toString(16).padStart(2, "0")).join("");
  await persistSettings();
}

async function exportBackup() {
  const previousPassphrase = currentPassphrase;
  // FR12 gate. FR10: the passphrase path below always emits a standard
  // envelope (no `dek` block), restorable by passphrase alone on any version.
  await requirePassphrase("export a backup");
  try {
    let envelope;
    if (settings.encrypt) {
      if (!currentPassphrase) throw new Error("Unlock the extension vault before exporting an encrypted backup");
      const encryptedPayload = await encryptEntries(entries, currentPassphrase);
      envelope = await createEncryptedBackup(encryptedPayload);
    } else {
      envelope = await createPlainBackup(entries);
    }
    const blob = new Blob([JSON.stringify(envelope, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "otp-vault-extension-backup.json";
    link.click();
    URL.revokeObjectURL(url);
    await stampBackupExport(envelope);
  } finally {
    releasePassphrase(previousPassphrase);
  }
}

function renderBackupReminder() {
  const line = document.getElementById("last-export-line");
  if (!line) return;
  if (shouldWarnBackup(settings, entries.length)) {
    line.textContent = settings.lastBackupAt
      ? "No export in over 30 days — export a backup below."
      : entries.length > 0 ? "No export yet — back this vault up below." : "";
    line.classList.remove("hidden");
    return;
  }
  const days = Math.floor((Date.now() - Number(settings.lastBackupAt)) / 86400000);
  line.textContent = `Last export: ${days === 0 ? "today" : `${days} day${days === 1 ? "" : "s"} ago`} (checksum ${String(settings.lastBackupHash || "").slice(0, 8)}). A cancelled download cannot be detected.`;
}

// --- Time drift (Phase 5) ---

async function checkTimeDrift() {
  if (!settings.timeDriftCheck) return;
  try {
    const response = await fetch("https://www.cloudflare.com/cdn-cgi/trace", { cache: "no-store" });
    const serverMs = parseTraceTimestamp(await response.text());
    const skewMs = Number.isFinite(serverMs) ? Math.abs(Date.now() - serverMs) : null;
    const banner = document.getElementById("drift-banner");
    if (banner) {
      const skewMs2 = skewMs;
      banner.querySelector("#drift-skew").textContent = skewMs2 !== null ? `${(skewMs2 / 1000).toFixed(1)}s` : "";
      banner.classList.toggle("hidden", !(skewMs2 !== null && skewMs2 > 5000));
    }
  } catch (error) {
    // Local-first respect: a failed check is a silent skip.
    reportError("Extension time drift check skipped", error);
    document.getElementById("drift-banner")?.classList.add("hidden");
  }
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
  passphraseInput?.addEventListener("input", () => renderPassphraseStrength(passphraseInput, setMeter));
  passphraseConfirmInput?.addEventListener("input", () => renderPassphraseStrength(passphraseConfirmInput, setMeter));
}

async function changeVaultPassphrase(currentPassphraseCandidate, nextPassphraseCandidate, confirmPassphraseCandidate) {
  if (!settings.encrypt) {
    throw new Error("Enable encrypted storage before changing the extension passphrase");
  }
  const previousPassphrase = currentPassphrase;
  if (!previousPassphrase) {
    await requirePassphrase("change the extension passphrase");
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    releasePassphrase(previousPassphrase);
    throw new Error("Current passphrase is incorrect");
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    releasePassphrase(previousPassphrase);
    throw new Error("Passphrase confirmation does not match");
  }
  const normalizedNext = normalizePassphrase(nextPassphraseCandidate);
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && isDekEncryptedPayload(payload)) {
    // FR11 in DEK mode: re-wrap the SAME DEK under the new passphrase —
    // data, salt, and the biometric wrap stay untouched.
    try {
      const dek = await unwrapDekWithPassphrase(payload, currentPassphrase);
      const meta = extractDekEnvelopeMeta(payload);
      const nextDekBlock = await wrapDekWithPassphrase(dek, normalizedNext, base64ToBytes(meta.salt), meta.kdf);
      const envelope = await encryptEntriesWithDek(entries, dek, { ...meta, dek: nextDekBlock });
      await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
      heldDek = dek;
      dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
      currentPassphrase = normalizedNext;
      // The cached handle is the DEK — still valid; refresh the passphrase.
      await writeSessionUnlock(envelope, currentPassphrase, heldDek);
    } finally {
      releasePassphrase(previousPassphrase);
    }
    return;
  }
  currentPassphrase = normalizedNext;
  try {
    await persistEntries();
    // The cached session key is bound to the old passphrase — drop it.
    await clearSessionUnlock();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
  releasePassphrase(previousPassphrase);
}

function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  form.querySelectorAll("input, select, button").forEach((node) => {
    node.disabled = locked;
  });
  qrFileInput.disabled = locked;
  searchInput.disabled = locked;
  sortSelect.disabled = locked;
  pasteUriBtn.disabled = locked;
  lockBtn.disabled = locked || !settings.encrypt;
  changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || locked);
  if (locked) {
    changePassphraseForm.classList.add("hidden");
  }
}

function sortEntries(items) {
  const sorted = [...items];
  if (settings.sortBy === "custom") {
    return sorted.sort((left, right) => (left.order ?? 0) - (right.order ?? 0) || left.label.localeCompare(right.label, undefined, { sensitivity: "base" }));
  }
  if (settings.sortBy === "recent") {
    return sorted.sort((left, right) => right.createdAt - left.createdAt);
  }
  if (settings.sortBy === "period") {
    return sorted.sort((left, right) => left.period - right.period || left.label.localeCompare(right.label, undefined, { sensitivity: "base" }));
  }
  return sorted.sort((left, right) => left.label.localeCompare(right.label, undefined, { sensitivity: "base" }));
}

function filteredEntries() {
  const query = (searchInput.value || "").trim().toLowerCase();
  return sortEntries(entries).filter((entry) => (
    [entry.label, ...(entry.tags || [])].join(" ").toLowerCase().includes(query)
  ));
}

function refreshEntryNode(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".avatar").textContent = getIssuerInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits • ${entry.period}s`;

  const algoBadge = node.querySelector(".algo");
  if (algoBadge) {
    const showAlgo = entry.algorithm && entry.algorithm !== "SHA1";
    algoBadge.textContent = showAlgo ? entry.algorithm.replace(/^SHA/, "SHA-") : "";
    algoBadge.classList.toggle("hidden", !showAlgo);
  }
  const counterBadge = node.querySelector(".counter");
  if (counterBadge) {
    const isHotp = entry.type === "hotp";
    counterBadge.textContent = isHotp ? `#${entry.counter}` : "";
    counterBadge.classList.toggle("hidden", !isHotp);
  }

  const tagRoot = node.querySelector(".tags");
  tagRoot.innerHTML = "";
  for (const tag of entry.tags || []) {
    const chip = document.createElement("span");
    chip.className = "tag";
    chip.textContent = tag;
    tagRoot.appendChild(chip);
  }
}

function addCopyHistory(label, code) {
  copyHistory = [
    {
      label,
      code: formatCode(code),
      at: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
    ...copyHistory.filter((item) => item.label !== label),
  ].slice(0, 5);
  renderCopyHistory();
}

function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  copyHistoryRoot.innerHTML = "";
  if (copyHistory.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Copied OTPs will appear here.";
    copyHistoryRoot.appendChild(empty);
    return;
  }

  for (const item of copyHistory) {
    const row = document.createElement("div");
    row.className = "history-item";
    const strong = document.createElement("strong");
    strong.textContent = item.label;
    const span = document.createElement("span");
    span.textContent = `${item.code} • ${item.at}`;
    row.append(strong, span);
    copyHistoryRoot.appendChild(row);
  }
}

function nextOrderValue(items = entries) {
  if (items.length === 0) return 1;
  return Math.max(...items.map((entry) => Number(entry.order) || 0)) + 1;
}

function resequenceEntries(items) {
  return items.map((entry, index) => ({ ...entry, order: index + 1 }));
}

function resequenceIfUnordered(decrypted) {
  return decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
}

// FR3: biometric unlock — full UV ceremony every time; holds the DEK, never
// the passphrase. The throttle guard applies (biometrics must not bypass it).
async function unlockWithBiometrics() {
  const guard = await readUnlockGuard();
  if (guard.lockedUntil > Date.now()) {
    setUnlockStatus(`Too many failed attempts — unlock available in ${Math.ceil((guard.lockedUntil - Date.now()) / 1000)}s`, "error");
    return;
  }
  const record = await readBiometricRecord();
  if (!record) {
    setUnlockStatus("No biometric unlock is enrolled on this device", "error");
    return;
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload || !isDekEncryptedPayload(payload)) {
    await reconcileOrphanedBiometricRecord();
    setUnlockStatus("Biometric unlock is no longer available — use your passphrase", "error");
    return;
  }
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
    await writeSessionUnlock(payload, "", heldDek);
    await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
    setLocked(false);
    renderEntries();
    tick();
    setUnlockStatus("Vault unlocked with biometrics", "success");
    setMainStatus("Encrypted extension unlocked", "success");
  } catch (error) {
    reportError("Biometric unlock failed", error);
    setUnlockStatus(toUserMessage(error, "Biometric unlock failed — use your passphrase"), "error");
  }
}

// FR2: enrollment — TWO-STORE write: envelope first (passphrase-recoverable),
// biometric record second. Re-enrollment keeps DEK, data, and passphrase wrap
// untouched and swaps only the KEK copy. rp.id is omitted: the popup uses the
// extension origin by default (cross-origin credentials are impossible).
async function enrollVaultBiometrics() {
  if (!settings.encrypt) {
    throw new Error("Enable encrypted storage before enabling biometric unlock");
  }
  if (!currentPassphrase && !heldDek) {
    throw new Error("Unlock the extension vault before enabling biometric unlock");
  }
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (payload && !isDekEncryptedPayload(payload) && !currentPassphrase) {
    throw new Error("Unlock the extension vault before enabling biometric unlock");
  }
  const enrollment = await enrollBiometricUnlock({});
  const prfSalt = enrollment.prfSalt;
  const kek = await deriveKek(enrollment.firstPrfOutput, prfSalt);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));

  let dek;
  let envelope = null;
  if (payload && isDekEncryptedPayload(payload)) {
    dek = heldDek || await unwrapDekWithPassphrase(payload, currentPassphrase);
    dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
  } else {
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
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
  }
  await writeBiometricRecord(record);
  heldDek = dek;
  if (envelope) {
    dekEnvelopeMeta = extractDekEnvelopeMeta(envelope);
    await refreshSessionCacheForDek(envelope);
  }
  renderBiometricControls();
}

// FR5: disenroll — passphrase-verified, then re-encrypt data directly under
// the passphrase key (standard envelope) and delete the record.
async function disenrollVaultBiometrics() {
  const record = await readBiometricRecord();
  if (!record) {
    setMainStatus("Biometric unlock is not enabled", "error");
    return;
  }
  const confirmed = window.confirm("Disable biometric unlock? The vault returns to passphrase-only storage.");
  if (!confirmed) return;
  const previousPassphrase = currentPassphrase;
  await requirePassphrase("disable biometric unlock");
  try {
    const restored = await encryptEntries(entries, currentPassphrase);
    await chrome.storage.local.set({ [ENCRYPTED_KEY]: restored });
    await removeBiometricRecord();
    await clearSessionUnlock();
    heldDek = null;
    dekEnvelopeMeta = null;
    setMainStatus("Biometric unlock disabled — passphrase-only vault restored", "success");
  } finally {
    releasePassphrase(previousPassphrase);
  }
  renderBiometricControls();
}

// Phase 6 UI gating: visible iff the runtime proves PRF capability; the
// unlock button additionally requires an enrolled record.
function renderBiometricControls() {
  const section = document.getElementById("biometric-settings");
  if (!section) return;
  readBiometricRecord().then((record) => {
    section.classList.toggle("hidden", !biometricCapable);
    const enrollBtn = document.getElementById("enroll-biometric-btn");
    const disenrollBtn = document.getElementById("disenroll-biometric-btn");
    const statusLine = document.getElementById("biometric-status-line");
    if (enrollBtn) {
      enrollBtn.classList.toggle("hidden", !biometricCapable || Boolean(record) || !settings.encrypt);
    }
    if (disenrollBtn) {
      disenrollBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
    if (statusLine) {
      statusLine.textContent = !biometricCapable
        ? ""
        : record
          ? "Biometric unlock is enrolled. Your passphrase remains the recovery method."
          : settings.encrypt
            ? "Unlock with your platform authenticator instead of your passphrase."
            : "Enable encrypted storage first, then enroll biometric unlock.";
    }
    const unlockBiometricBtn = document.getElementById("biometric-unlock-btn");
    if (unlockBiometricBtn) {
      unlockBiometricBtn.classList.toggle("hidden", !biometricCapable || !record);
    }
  });
}

function openEditEntryDialog(entry) {
  if (!editEntryDialog?.showModal) return;
  editEntryIdInput.value = entry.id;
  editLabelInput.value = entry.label;
  editSecretInput.value = entry.secret;
  editTagsInput.value = (entry.tags || []).join(", ");
  editDigitsInput.value = String(entry.digits);
  editPeriodInput.value = String(entry.period);
  editAlgorithmSelect.value = entry.algorithm || "SHA1";
  editCounterInput?.classList.toggle("hidden", entry.type !== "hotp");
  if (editCounterInput) editCounterInput.value = String(entry.type === "hotp" ? entry.counter : 0);
  setStatus(editStatus, "");
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
    order: current.order,
  });

  if (entries.some((entry) => entry.id !== id && entry.secret === updated.secret && entry.digits === updated.digits && entry.period === updated.period)) {
    throw new Error("Another entry already uses this secret, digits, and period");
  }

  await replaceEntries(entries.map((entry) => (entry.id === id ? updated : entry)));
}

async function moveEntry(entryId, direction) {
  const ordered = sortEntries(entries);
  const index = ordered.findIndex((entry) => entry.id === entryId);
  const nextIndex = index + direction;
  if (index < 0 || nextIndex < 0 || nextIndex >= ordered.length) return;
  [ordered[index], ordered[nextIndex]] = [ordered[nextIndex], ordered[index]];
  await replaceEntries(resequenceEntries(ordered));
}

function showRemoveConfirmation(message) {
  if (!confirmRemoveDialog?.showModal) {
    return Promise.resolve(window.confirm(message));
  }
  confirmRemoveMessage.textContent = message;
  return new Promise((resolve) => {
    confirmRemoveCallback = resolve;
    confirmRemoveDialog.showModal();
  });
}

function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  refreshEntryNode(node, entry);

  node.querySelector(".copy").addEventListener("click", async () => {
    try {
      const otp = node.dataset.otp;
      if (!otp) return;
      await navigator.clipboard.writeText(otp);
      addCopyHistory(entry.label, otp);
      setMainStatus(`Copied ${parseLabelParts(entry.label).issuer} code`, "success");
      await consumeHotpCounter(entry);
    } catch (error) {
      reportError("Extension copy failed", error);
      setMainStatus(toUserMessage(error, "Could not copy OTP"), "error");
    }
  });

  // HOTP counter-increment-on-copy with visible failure toast (FR9).
  async function consumeHotpCounter(currentEntry) {
    if (currentEntry.type !== "hotp") return;
    try {
      await replaceEntries(entries.map((item) => item.id === currentEntry.id ? { ...item, counter: item.counter + 1 } : item));
    } catch (error) {
      reportError("HOTP counter persist failed (copy)", error);
      setMainStatus("Counter save failed — the next code may repeat. Edit the entry to set the counter manually.", "error");
    }
  }

  node.querySelector(".edit")?.addEventListener("click", () => {
    openEditEntryDialog(entry);
  });

  node.querySelector(".move-up")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, -1);
      setMainStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Extension move up failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });

  node.querySelector(".move-down")?.addEventListener("click", async () => {
    try {
      settings.sortBy = "custom";
      sortSelect.value = "custom";
      await persistSettings();
      await moveEntry(entry.id, 1);
      setMainStatus("Manual order updated", "success");
    } catch (error) {
      reportError("Extension move down failed", error);
      setMainStatus(toUserMessage(error, "Could not reorder entry"), "error");
    }
  });

  node.querySelector(".remove").addEventListener("click", async () => {
    try {
      const confirmed = await showRemoveConfirmation(`Remove "${entry.label}" from the extension vault? You can undo for 10 minutes by reopening the popup.`);
      if (!confirmed) return;
      const index = entries.findIndex((item) => item.id === entry.id);
      await replaceEntries(entries.filter((item) => item.id !== entry.id));
      setMainStatus("Removed entry", "success");
      if (index >= 0) await offerUndoDelete([{ entry, index }]);
    } catch (error) {
      reportError("Extension remove failed", error);
      setMainStatus(toUserMessage(error, "Could not remove entry"), "error");
    }
  });

  return node;
}

function renderEntries() {
  if (!unlockPanel.classList.contains("hidden")) {
    entriesRoot.innerHTML = '<div class="empty-state">Vault is locked. Unlock to view and use your codes.</div>';
    return;
  }

  const visible = filteredEntries();
  if (visible.length === 0) {
    entriesRoot.innerHTML = '<div class="empty-state">No entries yet. Add one, import a QR file, or paste an otpauth URI.</div>';
    return;
  }

  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();
  for (const entry of visible) {
    let node = entryNodes.get(entry.id);
    if (!node) {
      node = createEntryNode(entry);
      entryNodes.set(entry.id, node);
    }
    refreshEntryNode(node, entry);
    fragment.appendChild(node);
  }
  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }
  entriesRoot.appendChild(fragment);
}

async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  try {
    let code;
    if (entry.type === "hotp") {
      // HOTP renders the deterministic code for the persisted counter; the
      // counter advances only on copy (no rolling timer, FR8).
      node.querySelector(".seconds").textContent = `#${entry.counter}`;
      node.querySelector(".bar").style.transform = "scaleX(1)";
      node.classList.toggle("urgent", false);
      code = await generateHotp(entry.secret, entry.counter, entry.digits, entry.algorithm);
    } else {
      const remaining = entry.period - (now % entry.period);
      code = await generateTotp(entry.secret, entry.digits, entry.period, now, entry.algorithm);
      node.querySelector(".seconds").textContent = `${remaining}s`;
      node.querySelector(".bar").style.transform = `scaleX(${remaining / entry.period})`;
      node.classList.toggle("urgent", remaining <= 10);
    }
    node.dataset.otp = code;
    node.querySelector(".code").textContent = formatCode(code);
  } catch (error) {
    reportError("Extension OTP generation failed", error);
    node.querySelector(".code").textContent = "Invalid";
    node.dataset.otp = "";
  }
}

function updateGlobalTimer(now) {
  const visible = filteredEntries();
  const period = visible.length > 0 ? Math.min(...visible.map((entry) => entry.period)) : 30;
  const remaining = period - (now % period);
  globalSeconds.textContent = `${remaining}s`;
  globalBar.style.transform = `scaleX(${remaining / period})`;
}

async function tick() {
  const now = Math.floor(Date.now() / 1000);
  updateGlobalTimer(now);
  const vaultLocked = !unlockPanel.classList.contains("hidden");
  if (settings.encrypt && settings.autoLockMinutes > 0 && !vaultLocked
      && Date.now() - lastActivity >= settings.autoLockMinutes * 60000) {
    lockVault();
    return;
  }
  if (vaultLocked) {
    const guard = await readUnlockGuard();
    const remainingMs = guard.lockedUntil - Date.now();
    unlockBtn.disabled = remainingMs > 0;
    if (remainingMs > 0) {
      setUnlockStatus(`Too many failed attempts — unlock available in ${Math.ceil(remainingMs / 1000)}s`, "error");
    } else if (unlockStatus.classList.contains("error") && unlockStatus.textContent.startsWith("Too many failed attempts")) {
      setUnlockStatus("");
    }
    return;
  }
  await Promise.all(filteredEntries().map((entry) => updateEntryNode(entry, now)));
}

async function snapshotVaultArtifacts() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY]);
  return {
    plain: stored[STORAGE_KEY] ?? null,
    legacyPlain: stored[LEGACY_STORAGE_KEY] ?? null,
    encrypted: stored[ENCRYPTED_KEY] ?? null
  };
}

async function restoreVaultArtifacts(snapshot) {
  const updates = {};
  const removes = [];
  if (snapshot.plain === null) {
    removes.push(STORAGE_KEY);
  } else {
    updates[STORAGE_KEY] = snapshot.plain;
  }
  if (snapshot.legacyPlain === null) {
    removes.push(LEGACY_STORAGE_KEY);
  } else {
    updates[LEGACY_STORAGE_KEY] = snapshot.legacyPlain;
  }
  if (snapshot.encrypted === null) {
    removes.push(ENCRYPTED_KEY);
  } else {
    updates[ENCRYPTED_KEY] = snapshot.encrypted;
  }
  if (Object.keys(updates).length > 0) await chrome.storage.local.set(updates);
  if (removes.length > 0) await chrome.storage.local.remove(removes);
}

async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  await chrome.storage.local.set({ [ENCRYPTED_KEY]: encryptedPayload });
  await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
}

async function persistEntries() {
  const previousArtifacts = await snapshotVaultArtifacts();
  try {
    if (settings.encrypt) {
      if (heldDek) {
        // DEK mode (biometric unlock, FR8): re-encrypt data under the held
        // DEK — no passphrase involvement; salt/kdf/passphrase-wrap stable.
        const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
        const payload = stored[ENCRYPTED_KEY];
        if (!payload || !isDekEncryptedPayload(payload) || !dekEnvelopeMeta) {
          throw new Error("Biometric vault envelope is missing — unlock with your passphrase to restore it");
        }
        const envelope = await encryptEntriesWithDek(entries, heldDek, dekEnvelopeMeta);
        await chrome.storage.local.set({ [ENCRYPTED_KEY]: envelope });
        await chrome.storage.local.remove([STORAGE_KEY, LEGACY_STORAGE_KEY]);
        await refreshSessionCacheForDek(envelope);
        return;
      }
      if (!currentPassphrase) throw new Error("Unlock extension vault before saving encrypted entries");
      await saveEncryptedEntries(entries, currentPassphrase);
      return;
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: entries });
    await chrome.storage.local.remove(ENCRYPTED_KEY);
    await removeBiometricRecord();
    heldDek = null;
    dekEnvelopeMeta = null;
  } catch (error) {
    await restoreVaultArtifacts(previousArtifacts);
    throw error;
  }
}

async function persistSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);
  if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
  try {
    await persistEntries();
  } catch (error) {
    entries = previousEntries;
    renderEntries();
    await tick();
    throw error;
  }
  renderEntries();
  await tick();
}

async function addEntry(input) {
  const entry = normalizeEntry({ ...input, order: nextOrderValue() });
  if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
  await replaceEntries([...entries, entry]);
}

async function importFromQrFile(file) {
  if (typeof BarcodeDetector !== "function") {
    throw new Error("QR file import requires Chrome BarcodeDetector support");
  }
  const bitmap = await createImageBitmap(file);
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const results = await detector.detect(bitmap);
  bitmap.close();
  if (!results.length || !results[0].rawValue) {
    throw new Error("Could not detect a QR code in that file");
  }
  const uri = extractOtpAuthUri(results[0].rawValue);
  if (!uri) {
    throw new Error("QR code was detected but does not contain a valid OTP URI");
  }
  return normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
}

function bindEvents() {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        tags: normalizeTags(tagsInput.value),
        type: entryTypeSelect?.value || "totp",
        counter: entryTypeSelect?.value === "hotp" ? Number(counterInput?.value || 0) : 0,
        algorithm: algorithmSelect?.value || "SHA1",
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
      });
      form.reset();
      tagsInput.value = "";
      digitsInput.value = "6";
      periodInput.value = "30";
      counterInput?.classList.add("hidden");
      setMainStatus("Entry added", "success");
    } catch (error) {
      reportError("Extension manual entry failed", error);
      setMainStatus(toUserMessage(error, "Could not add entry"), "error");
    }
  });

  entryTypeSelect?.addEventListener("change", () => {
    counterInput?.classList.toggle("hidden", entryTypeSelect.value !== "hotp");
  });

  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    try {
      const entry = await importFromQrFile(file);
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setMainStatus("Imported QR entry", "success");
    } catch (error) {
      reportError("Extension QR import failed", error);
      setMainStatus(toUserMessage(error, "Could not import QR file"), "error");
    } finally {
      qrFileInput.value = "";
    }
  });

  pasteUriBtn.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error("Clipboard permission denied. Copy the URI into the secret field instead.");
      }
      const text = await navigator.clipboard.readText();
      // Google Authenticator migration exports take priority over plain URIs.
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length > 0) {
        stageMigrationPayloads(migration.payloads, "Clipboard");
        return;
      }
      const uri = extractOtpAuthUri(text);
      if (!uri) throw new Error("Clipboard does not contain a valid OTP URI");
      const entry = normalizeEntry({ ...parseOtpAuthUri(uri), order: nextOrderValue() });
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setMainStatus("Imported URI from clipboard", "success");
    } catch (error) {
      reportError("Extension clipboard import failed", error);
      setMainStatus(toUserMessage(error, "Could not import URI"), "error");
    }
  });

  pasteGaBtn?.addEventListener("click", async () => {
    try {
      let hasClipboardRead = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
      if (!hasClipboardRead) {
        hasClipboardRead = await chrome.permissions.request({ permissions: ["clipboardRead"] });
      }
      if (!hasClipboardRead) {
        throw new Error("Clipboard permission denied. Copy the export URI and try again.");
      }
      const text = await navigator.clipboard.readText();
      const migration = collectMigrationPayloads(text);
      if (migration.payloads.length === 0) {
        throw new Error(migration.warnings[0] || "Clipboard does not contain a Google Authenticator export");
      }
      stageMigrationPayloads(migration.payloads, "Google Authenticator");
    } catch (error) {
      reportError("Extension GA import failed", error);
      setMainStatus(toUserMessage(error, "Could not import the Google Authenticator export"), "error");
    }
  });

  migrationPreviewForm?.addEventListener("submit", async (event) => {
    if (event.submitter?.value !== "accept") return;
    event.preventDefault();
    try {
      await commitMigrationPreview();
      migrationPreviewDialog?.close("accept");
      setMainStatus("Google Authenticator entries imported", "success");
    } catch (error) {
      reportError("Extension GA preview commit failed", error);
      setMainStatus(toUserMessage(error, "Could not import entries"), "error");
    }
  });

  migrationPreviewDialog?.addEventListener("close", () => {
    migrationPreviewState = null;
  });

  exportBackupBtn?.addEventListener("click", async () => {
    try {
      await exportBackup();
      renderBackupReminder();
      setMainStatus("Backup exported", "success");
    } catch (error) {
      reportError("Extension backup export failed", error);
      setMainStatus(toUserMessage(error, "Could not export backup"), "error");
    }
  });

  document.getElementById("check-drift-btn")?.addEventListener("click", async () => {
    if (!settings.timeDriftCheck) {
      setMainStatus("Enable the time-drift check first", "warning");
      return;
    }
    await checkTimeDrift();
    setMainStatus("Time check complete — see the banner if your clock is off", "success");
  });
  document.getElementById("drift-dismiss")?.addEventListener("click", () => {
    document.getElementById("drift-banner")?.classList.add("hidden");
  });

  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });

  sortSelect.addEventListener("change", async () => {
    settings.sortBy = sortSelect.value;
    await persistSettings();
    renderEntries();
    tick();
  });

  toggleFormBtn.addEventListener("click", async () => {
    collapsed = !collapsed;
    applyUiState();
    await saveUiState();
  });

  encryptToggle.addEventListener("change", () => {
    passphraseFields.classList.toggle("hidden", !encryptToggle.checked);
  });

  changePassphraseBtn?.addEventListener("click", () => {
    changePassphraseForm.classList.toggle("hidden");
    currentPassphraseInput.value = "";
    newPassphraseInput.value = "";
    newPassphraseConfirmInput.value = "";
  });

  changePassphraseForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await changeVaultPassphrase(
        currentPassphraseInput.value.trim(),
        newPassphraseInput.value.trim(),
        newPassphraseConfirmInput.value.trim()
      );
      changePassphraseForm.classList.add("hidden");
      currentPassphraseInput.value = "";
      newPassphraseInput.value = "";
      newPassphraseConfirmInput.value = "";
      setMainStatus("Extension passphrase updated", "success");
    } catch (error) {
      reportError("Extension change passphrase failed", error);
      setMainStatus(toUserMessage(error, "Could not update passphrase"), "error");
    }
  });

  securityForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const previousSettings = { ...settings };
    const previousPassphrase = currentPassphrase;
    let previousArtifacts;
    try {
      previousArtifacts = await snapshotVaultArtifacts();
      settings.encrypt = encryptToggle.checked;
      const autoLockSelect = document.getElementById("auto-lock-select");
      if (autoLockSelect) settings.autoLockMinutes = Number(autoLockSelect.value) || 0;
      const timeDriftToggle = document.getElementById("time-drift-toggle");
      if (timeDriftToggle) settings.timeDriftCheck = timeDriftToggle.checked;
      if (settings.encrypt) {
        let nextPassphrase = currentPassphrase;
        if (!nextPassphrase) {
          if (previousSettings.encrypt) {
            passphraseInput.value = "";
            passphraseConfirmInput.value = "";
            await persistSettings();
            renderBiometricControls();
            setMainStatus("Encrypted extension vault saved", "success");
            return;
          }
          const first = passphraseInput.value.trim();
          const second = passphraseConfirmInput.value.trim();
          if (first !== second) throw new Error("Passphrase confirmation does not match");
          nextPassphrase = normalizePassphrase(first);
        }
        currentPassphrase = nextPassphrase;
        await saveEncryptedEntries(entries, currentPassphrase);
      } else {
        currentPassphrase = "";
        heldDek = null;
        dekEnvelopeMeta = null;
        await clearSessionUnlock();
        await removeBiometricRecord();
        await chrome.storage.local.set({ [STORAGE_KEY]: entries });
        await chrome.storage.local.remove(ENCRYPTED_KEY);
      }
      await persistSettings();
      passphraseInput.value = "";
      passphraseConfirmInput.value = "";
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      const encryptedVaultExists = Boolean(settings.encrypt && (currentPassphrase || previousArtifacts?.encrypted));
      passphraseFields.classList.toggle("hidden", !settings.encrypt || encryptedVaultExists);
      passphraseGuidance?.classList.toggle("hidden", !encryptedVaultExists);
      setMainStatus(
        encryptedVaultExists ? "Encrypted extension vault saved. Use Change Passphrase to rotate your extension secret." : settings.encrypt ? "Encrypted extension vault saved" : "Extension storage is now plain local storage",
        "success"
      );
      renderBiometricControls();
    } catch (error) {
      settings = previousSettings;
      currentPassphrase = previousPassphrase;
      if (previousArtifacts) await restoreVaultArtifacts(previousArtifacts);
      encryptToggle.checked = settings.encrypt;
      passphraseFields.classList.toggle("hidden", !settings.encrypt);
      lockBtn.disabled = !settings.encrypt;
      changePassphraseBtn.classList.toggle("hidden", !settings.encrypt || !unlockPanel.classList.contains("hidden"));
      reportError("Extension save security failed", error);
      setMainStatus(toUserMessage(error, "Could not save security settings"), "error");
    }
  });

  lockBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setMainStatus("Enable encrypted storage first", "error");
      return;
    }
    lockVault();
  });

  document.getElementById("biometric-unlock-btn")?.addEventListener("click", () => {
    unlockWithBiometrics();
  });
  document.getElementById("enroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await enrollVaultBiometrics();
      setMainStatus("Biometric unlock enabled on this device", "success");
    } catch (error) {
      reportError("Biometric enrollment failed", error);
      setMainStatus(toUserMessage(error, "Could not enable biometric unlock"), "error");
      renderBiometricControls();
    }
  });
  document.getElementById("disenroll-biometric-btn")?.addEventListener("click", async () => {
    try {
      await disenrollVaultBiometrics();
    } catch (error) {
      reportError("Biometric disenroll failed", error);
      setMainStatus(toUserMessage(error, "Could not disable biometric unlock"), "error");
    }
  });

  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const guard = await readUnlockGuard();
    const now = Date.now();
    if (guard.lockedUntil > now) {
      setUnlockStatus(`Too many failed attempts — unlock available in ${Math.ceil((guard.lockedUntil - now) / 1000)}s`, "error");
      return;
    }
    unlockBtn.disabled = true;
    try {
      const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
      const payload = stored[ENCRYPTED_KEY];
      // One consistent read: the input can be retyped during the ~400ms KDF,
      // and derive/decrypt must never see different passphrases.
      const candidate = unlockPassphraseInput.value;
      let keyHandle;
      if (isDekEncryptedPayload(payload)) {
        // Passphrase recovery in DEK mode (FR4): unwrap + hold the DEK so
        // saves keep working; the DEK itself is the session-cache handle.
        heldDek = await unwrapDekWithPassphrase(payload, normalizePassphrase(candidate));
        dekEnvelopeMeta = extractDekEnvelopeMeta(payload);
        keyHandle = heldDek;
        entries = resequenceIfUnordered(await decryptVaultEntriesWithKey(heldDek, payload));
      } else {
        heldDek = null;
        dekEnvelopeMeta = null;
        keyHandle = await deriveVaultKeyFromPayload(payload, normalizePassphrase(candidate));
        entries = resequenceIfUnordered(await decryptVaultEntries(payload, candidate));
      }
      currentPassphrase = normalizePassphrase(candidate);
      // Legacy (pre-600k) envelopes re-encrypt at the current default right
      // after a successful unlock; failure leaves the old envelope intact.
      if (isLegacyEncryptedPayload(payload)) {
        await persistEntries();
      }
      // Session cache: derive the AES-GCM key once and cache the CryptoKey
      // (structured-cloneable) so the next popup open skips the 600k KDF.
      await writeSessionUnlock(payload, currentPassphrase, keyHandle);
      await writeUnlockGuard({ attempts: 0, lockedUntil: 0 });
      unlockPassphraseInput.value = "";
      setLocked(false);
      renderEntries();
      tick();
      setUnlockStatus("Vault unlocked", "success");
      setMainStatus("Encrypted extension unlocked", "success");
    } catch (error) {
      const attempts = guard.attempts + 1;
      const backoff = unlockBackoffSeconds(attempts);
      await writeUnlockGuard({ attempts, lockedUntil: attempts >= 3 ? now + backoff * 1000 : 0 });
      const suffix = attempts >= 3 ? ` Locked for ${backoff}s.` : "";
      reportError("Extension unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted data") + suffix, "error");
    } finally {
      unlockBtn.disabled = false;
    }
  });

  cancelEditBtn.addEventListener("click", () => {
    editEntryDialog.close("cancel");
  });

  editEntryForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await saveEditedEntry();
      editEntryDialog.close("accept");
      setMainStatus("Entry updated", "success");
    } catch (error) {
      setStatus(editStatus, toUserMessage(error, "Could not update entry"), "error");
    }
  });

  confirmRemoveDialog?.addEventListener("close", () => {
    if (!confirmRemoveCallback) return;
    const accepted = confirmRemoveDialog.returnValue === "accept";
    confirmRemoveCallback(accepted);
    confirmRemoveCallback = null;
  });
}
