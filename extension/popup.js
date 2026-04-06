import {
  extractOtpAuthUri,
  formatCode,
  generateTotp,
  getIssuerInitials,
  hasDuplicateEntry,
  normalizeEntries,
  normalizeEntry,
  parseLabelParts,
  parseOtpAuthUri,
  reportError,
  toUserMessage,
} from "./lib/otp.js";
import {
  decryptVaultEntries,
  encryptEntries,
  normalizePassphrase,
} from "./lib/vault.js";

const STORAGE_KEY = "otp_extension_entries_v2";
const ENCRYPTED_KEY = "otp_extension_encrypted_v1";
const SETTINGS_KEY = "otp_extension_settings_v1";
const UI_KEY = "otp_extension_ui_v1";

const form = document.getElementById("entry-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
const qrFileInput = document.getElementById("qr-file");
const searchInput = document.getElementById("search");
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

let entries = [];
let entryNodes = new Map();
let collapsed = false;
let settings = { encrypt: false };
let currentPassphrase = "";

initialize();

async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, ...(stored[SETTINGS_KEY] || {}) };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  passphraseFields.classList.toggle("hidden", !settings.encrypt);
  applyUiState();

  if (settings.encrypt && stored[ENCRYPTED_KEY]) {
    setLocked(true);
  } else {
    entries = normalizeEntries(stored[STORAGE_KEY]);
    setLocked(false);
  }

  bindEvents();
  renderEntries();
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

function setStatus(message, tone = "") {
  statusNode.textContent = message;
  statusNode.classList.remove("error", "success");
  if (tone) statusNode.classList.add(tone);
}

function setUnlockStatus(message, tone = "") {
  unlockStatus.textContent = message;
  unlockStatus.classList.remove("error", "success");
  if (tone) unlockStatus.classList.add(tone);
}

function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  form.querySelectorAll("input, select, button").forEach((node) => {
    node.disabled = locked;
  });
  qrFileInput.disabled = locked;
  searchInput.disabled = locked;
  pasteUriBtn.disabled = locked;
  lockBtn.disabled = locked || !settings.encrypt;
}

function filteredEntries() {
  const query = (searchInput.value || "").trim().toLowerCase();
  return [...entries]
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: "base" }))
    .filter((entry) => entry.label.toLowerCase().includes(query));
}

function refreshEntryNode(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".avatar").textContent = getIssuerInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits • ${entry.period}s`;
}

function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  refreshEntryNode(node, entry);

  node.querySelector(".copy").addEventListener("click", async () => {
    try {
      const otp = node.dataset.otp;
      if (!otp) return;
      await navigator.clipboard.writeText(otp);
      setStatus(`Copied ${parseLabelParts(entry.label).issuer} code`, "success");
    } catch (error) {
      reportError("Extension copy failed", error);
      setStatus(toUserMessage(error, "Could not copy OTP"), "error");
    }
  });

  node.querySelector(".remove").addEventListener("click", async () => {
    try {
      await replaceEntries(entries.filter((item) => item.id !== entry.id));
      setStatus("Removed entry", "success");
    } catch (error) {
      reportError("Extension remove failed", error);
      setStatus(toUserMessage(error, "Could not remove entry"), "error");
    }
  });

  return node;
}

function renderEntries() {
  if (!unlockPanel.classList.contains("hidden")) {
    entriesRoot.innerHTML = '<div class="empty-state">Vault is locked. Unlock to view extension codes.</div>';
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

async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  await chrome.storage.local.set({ [ENCRYPTED_KEY]: encryptedPayload });
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function persistEntries() {
  if (settings.encrypt) {
    if (!currentPassphrase) throw new Error("Unlock extension vault before saving encrypted entries");
    await saveEncryptedEntries(entries, currentPassphrase);
    return;
  }

  await chrome.storage.local.set({ [STORAGE_KEY]: entries });
  await chrome.storage.local.remove(ENCRYPTED_KEY);
}

async function persistSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function replaceEntries(nextEntries) {
  const previousEntries = entries;
  entries = normalizeEntries(nextEntries);

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
  const entry = normalizeEntry(input);
  if (hasDuplicateEntry(entries, entry)) {
    throw new Error("This account already exists");
  }
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
  return parseOtpAuthUri(uri);
}

function bindEvents() {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
      });
      form.reset();
      digitsInput.value = "6";
      periodInput.value = "30";
      setStatus("Entry added", "success");
    } catch (error) {
      reportError("Extension manual entry failed", error);
      setStatus(toUserMessage(error, "Could not add entry"), "error");
    }
  });

  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;

    try {
      const entry = await importFromQrFile(file);
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setStatus("Imported QR entry", "success");
    } catch (error) {
      reportError("Extension QR import failed", error);
      setStatus(toUserMessage(error, "Could not import QR file"), "error");
    } finally {
      qrFileInput.value = "";
    }
  });

  pasteUriBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      const uri = extractOtpAuthUri(text);
      if (!uri) throw new Error("Clipboard does not contain a valid OTP URI");
      const entry = parseOtpAuthUri(uri);
      if (hasDuplicateEntry(entries, entry)) throw new Error("This account already exists");
      await replaceEntries([...entries, entry]);
      setStatus("Imported URI from clipboard", "success");
    } catch (error) {
      reportError("Extension clipboard import failed", error);
      setStatus(toUserMessage(error, "Could not import URI"), "error");
    }
  });

  searchInput.addEventListener("input", () => {
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

  saveSecurityBtn.addEventListener("click", async () => {
    try {
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
      setStatus(settings.encrypt ? "Encrypted extension vault saved" : "Extension storage is now plain local storage", "success");
    } catch (error) {
      reportError("Extension save security failed", error);
      setStatus(toUserMessage(error, "Could not save security settings"), "error");
    }
  });

  lockBtn.addEventListener("click", () => {
    if (!settings.encrypt) {
      setStatus("Enable encrypted storage first", "error");
      return;
    }
    entries = [];
    setLocked(true);
    renderEntries();
  });

  unlockBtn.addEventListener("click", async () => {
    try {
      const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
      const decrypted = await decryptVaultEntries(stored[ENCRYPTED_KEY], unlockPassphraseInput.value);
      entries = decrypted;
      currentPassphrase = normalizePassphrase(unlockPassphraseInput.value);
      unlockPassphraseInput.value = "";
      setLocked(false);
      renderEntries();
      tick();
      setUnlockStatus("Vault unlocked", "success");
      setStatus("Encrypted extension unlocked", "success");
    } catch (error) {
      reportError("Extension unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted data"), "error");
    }
  });
}
