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
  decryptVaultEntries,
  decryptVaultEntriesWithKey,
  deriveVaultKeyFromPayload,
  encryptEntries,
  isLegacyEncryptedPayload,
  normalizePassphrase,
} from "../lib/vault.js";

const STORAGE_KEY = "otp_extension_entries_v3";
const LEGACY_STORAGE_KEY = "otp_extension_entries_v2";
const ENCRYPTED_KEY = "otp_extension_encrypted_v1";
const SETTINGS_KEY = "otp_extension_settings_v1";
const UI_KEY = "otp_extension_ui_v1";
const SESSION_UNLOCK_KEY = "otp_extension_session_unlock_v1";
const UNLOCK_GUARD_KEY = "otp_extension_unlock_guard_v1";

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
const migrationPreviewDialog = document.getElementById("migration-preview-dialog");
const migrationPreviewForm = document.getElementById("migration-preview-form");
const migrationPreviewStatus = document.getElementById("migration-preview-status");
const migrationPreviewList = document.getElementById("migration-preview-list");

let entries = [];
let entryNodes = new Map();
let collapsed = false;
let settings = { encrypt: false, sortBy: "alpha" };
let currentPassphrase = "";
let copyHistory = [];
let confirmRemoveCallback = null;
let lastActivity = Date.now();
let migrationPreviewState = null;

initialize();

async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, LEGACY_STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, sortBy: "alpha", autoLockMinutes: 15, ...(stored[SETTINGS_KEY] || {}) };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
  const autoLockSelect = document.getElementById("auto-lock-select");
  if (autoLockSelect) autoLockSelect.value = String(settings.autoLockMinutes ?? 15);
  const hasExistingEncryptedVault = Boolean(settings.encrypt && stored[ENCRYPTED_KEY]);
  passphraseFields.classList.toggle("hidden", !settings.encrypt || hasExistingEncryptedVault);
  passphraseGuidance?.classList.toggle("hidden", !hasExistingEncryptedVault);
  applyUiState();

  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    // Session-cache fast path: a live cached CryptoKey decrypts without the
    // 600k PBKDF2 cost; without it the popup stays locked.
    const cached = await readSessionUnlock(stored[ENCRYPTED_KEY]);
    if (cached) {
      entries = cached.entries;
      currentPassphrase = cached.passphrase;
      if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
      setLocked(false);
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
  }

  bindEvents();
  bindPassphraseStrengthMeters();
  bindAutoLockActivity();
  renderEntries();
  renderCopyHistory();
  tick();
  setInterval(tick, 1000);
}

async function readSessionUnlock(encryptedPayload) {
  try {
    const cached = (await chrome.storage.session.get(SESSION_UNLOCK_KEY))[SESSION_UNLOCK_KEY];
    if (!cached?.passphrase || !cached?.keyHandle) return null;
    const entriesDecrypted = await decryptVaultEntriesWithKey(cached.keyHandle, encryptedPayload);
    return { entries: entriesDecrypted, passphrase: cached.passphrase };
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
  if (unlockPassphraseInput) unlockPassphraseInput.value = "";
  setUnlockStatus("");
  entries = [];
  if (settings.clearClipboard) {
    copyHistory = [];
    renderCopyHistory();
  }
  clearSessionUnlock();
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
  if (!currentPassphrase) {
    throw new Error("Unlock the extension vault before changing the passphrase");
  }
  if (currentPassphraseCandidate !== currentPassphrase) {
    throw new Error("Current passphrase is incorrect");
  }
  if (nextPassphraseCandidate !== confirmPassphraseCandidate) {
    throw new Error("Passphrase confirmation does not match");
  }
  const previousPassphrase = currentPassphrase;
  currentPassphrase = normalizePassphrase(nextPassphraseCandidate);
  try {
    await persistEntries();
    // The cached session key is bound to the old passphrase — drop it.
    await clearSessionUnlock();
  } catch (error) {
    currentPassphrase = previousPassphrase;
    throw error;
  }
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
      const confirmed = await showRemoveConfirmation(`Remove "${entry.label}" from the extension vault? This action cannot be undone.`);
      if (!confirmed) return;
      await replaceEntries(entries.filter((item) => item.id !== entry.id));
      setMainStatus("Removed entry", "success");
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
      if (!currentPassphrase) throw new Error("Unlock extension vault before saving encrypted entries");
      await saveEncryptedEntries(entries, currentPassphrase);
      return;
    }
    await chrome.storage.local.set({ [STORAGE_KEY]: entries });
    await chrome.storage.local.remove(ENCRYPTED_KEY);
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
      if (settings.encrypt) {
        let nextPassphrase = currentPassphrase;
        if (!nextPassphrase) {
          if (previousSettings.encrypt) {
            passphraseInput.value = "";
            passphraseConfirmInput.value = "";
            await persistSettings();
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
        await clearSessionUnlock();
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
      const decrypted = await decryptVaultEntries(stored[ENCRYPTED_KEY], unlockPassphraseInput.value);
      entries = decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
      currentPassphrase = normalizePassphrase(unlockPassphraseInput.value);
      // Legacy (pre-600k) envelopes re-encrypt at the current default right
      // after a successful unlock; failure leaves the old envelope intact.
      if (isLegacyEncryptedPayload(stored[ENCRYPTED_KEY])) {
        await persistEntries();
      }
      // Session cache: derive the AES-GCM key once and cache the CryptoKey
      // (structured-cloneable) so the next popup open skips the 600k KDF.
      const keyHandle = await deriveVaultKeyFromPayload(stored[ENCRYPTED_KEY], currentPassphrase);
      await writeSessionUnlock(stored[ENCRYPTED_KEY], currentPassphrase, keyHandle);
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
