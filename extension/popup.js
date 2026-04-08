import {
  extractOtpAuthUri,
  formatCode,
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
  decryptVaultEntries,
  encryptEntries,
  normalizePassphrase,
} from "../lib/vault.js";

const STORAGE_KEY = "otp_extension_entries_v2";
const ENCRYPTED_KEY = "otp_extension_encrypted_v1";
const SETTINGS_KEY = "otp_extension_settings_v1";
const UI_KEY = "otp_extension_ui_v1";

const form = document.getElementById("entry-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const tagsInput = document.getElementById("tags");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
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
const passphraseInput = document.getElementById("passphrase");
const passphraseConfirmInput = document.getElementById("passphrase-confirm");
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
const editStatus = document.getElementById("edit-status");
const cancelEditBtn = document.getElementById("cancel-edit");
const saveEditBtn = document.getElementById("save-edit");

let entries = [];
let entryNodes = new Map();
let collapsed = false;
let settings = { encrypt: false, sortBy: "alpha" };
let currentPassphrase = "";
let copyHistory = [];

initialize();

async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, sortBy: "alpha", ...(stored[SETTINGS_KEY] || {}) };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
  passphraseFields.classList.toggle("hidden", !settings.encrypt);
  applyUiState();

  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    setLocked(true);
  } else {
    entries = normalizeEntries(stored[STORAGE_KEY]);
    if (entries.every((entry) => !entry.order)) entries = resequenceEntries(entries);
    setLocked(false);
  }

  bindEvents();
  renderEntries();
  renderCopyHistory();
  tick();
  setInterval(tick, 1000);
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
  if (copyHistory.length === 0) {
    copyHistoryRoot.innerHTML = '<div class="empty-state">Copied OTPs will appear here.</div>';
    return;
  }

  copyHistoryRoot.innerHTML = copyHistory
    .map((item) => `<div class="history-item"><strong>${item.label}</strong><span>${item.code} • ${item.at}</span></div>`)
    .join("");
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
    } catch (error) {
      reportError("Extension copy failed", error);
      setMainStatus(toUserMessage(error, "Could not copy OTP"), "error");
    }
  });

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
    const remaining = entry.period - (now % entry.period);
    const code = await generateTotp(entry.secret, entry.digits, entry.period, now);
    node.dataset.otp = code;
    node.querySelector(".code").textContent = formatCode(code);
    node.querySelector(".seconds").textContent = `${remaining}s`;
    node.querySelector(".bar").style.transform = `scaleX(${remaining / entry.period})`;
    node.classList.toggle("urgent", remaining <= 10);
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
  if (!unlockPanel.classList.contains("hidden")) return;
  await Promise.all(filteredEntries().map((entry) => updateEntryNode(entry, now)));
}

async function snapshotVaultArtifacts() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, ENCRYPTED_KEY]);
  return {
    plain: stored[STORAGE_KEY] ?? null,
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
  await chrome.storage.local.remove(STORAGE_KEY);
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
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
      });
      form.reset();
      tagsInput.value = "";
      digitsInput.value = "6";
      periodInput.value = "30";
      setMainStatus("Entry added", "success");
    } catch (error) {
      reportError("Extension manual entry failed", error);
      setMainStatus(toUserMessage(error, "Could not add entry"), "error");
    }
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
      const text = await navigator.clipboard.readText();
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

  securityForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const previousSettings = { ...settings };
    const previousPassphrase = currentPassphrase;
    let previousArtifacts;
    try {
      previousArtifacts = await snapshotVaultArtifacts();
      settings.encrypt = encryptToggle.checked;
      if (settings.encrypt) {
        let nextPassphrase = currentPassphrase;
        if (!nextPassphrase) {
          const first = passphraseInput.value.trim();
          const second = passphraseConfirmInput.value.trim();
          if (first !== second) throw new Error("Passphrase confirmation does not match");
          nextPassphrase = normalizePassphrase(first);
        }
        currentPassphrase = nextPassphrase;
        await saveEncryptedEntries(entries, currentPassphrase);
      } else {
        currentPassphrase = "";
        await chrome.storage.local.set({ [STORAGE_KEY]: entries });
        await chrome.storage.local.remove(ENCRYPTED_KEY);
      }
      await persistSettings();
      passphraseInput.value = "";
      passphraseConfirmInput.value = "";
      lockBtn.disabled = !settings.encrypt;
      setMainStatus(settings.encrypt ? "Encrypted extension vault saved" : "Extension storage is now plain local storage", "success");
    } catch (error) {
      settings = previousSettings;
      currentPassphrase = previousPassphrase;
      if (previousArtifacts) await restoreVaultArtifacts(previousArtifacts);
      encryptToggle.checked = settings.encrypt;
      passphraseFields.classList.toggle("hidden", !settings.encrypt);
      lockBtn.disabled = !settings.encrypt;
      reportError("Extension save security failed", error);
      setMainStatus(toUserMessage(error, "Could not save security settings"), "error");
    }
  });

  lockBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setMainStatus("Enable encrypted storage first", "error");
      return;
    }
    entries = [];
    setLocked(true);
    renderEntries();
  });

  unlockForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
      const decrypted = await decryptVaultEntries(stored[ENCRYPTED_KEY], unlockPassphraseInput.value);
      entries = decrypted.every((entry) => !entry.order) ? resequenceEntries(decrypted) : decrypted;
      currentPassphrase = normalizePassphrase(unlockPassphraseInput.value);
      unlockPassphraseInput.value = "";
      setLocked(false);
      renderEntries();
      tick();
      setUnlockStatus("Vault unlocked", "success");
      setMainStatus("Encrypted extension unlocked", "success");
    } catch (error) {
      reportError("Extension unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted data"), "error");
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
}
