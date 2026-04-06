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
  createEncryptedBackup,
  createPlainBackup,
  decryptVaultEntries,
  encryptEntries,
  normalizePassphrase,
  parseBackupFile,
} from "./lib/vault.js";

const STORAGE_KEY = "personal_otp_vault_entries_v2";
const SETTINGS_KEY = "personal_otp_vault_settings_v2";
const WARNING_KEY = "personal_otp_vault_persist_warning_seen_v1";
const ENCRYPTED_VAULT_KEY = "personal_otp_vault_encrypted_v1";

const form = document.getElementById("otp-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
const uriInput = document.getElementById("uri");
const parseUriBtn = document.getElementById("parse-uri");
const importClipboardBtn = document.getElementById("import-clipboard");
const qrFileInput = document.getElementById("qr-file");
const qrUrlInput = document.getElementById("qr-url");
const importQrUrlBtn = document.getElementById("import-qr-url");
const startCameraBtn = document.getElementById("start-camera");
const stopCameraBtn = document.getElementById("stop-camera");
const cameraPreview = document.getElementById("camera-preview");
const clearAllBtn = document.getElementById("clear-all");
const importStatus = document.getElementById("import-status");
const searchInput = document.getElementById("search");
const entriesRoot = document.getElementById("entries");
const template = document.getElementById("entry-template");
const timerValue = document.getElementById("timer-value");
const timerBar = document.getElementById("timer-bar");
const persistToggle = document.getElementById("persist-toggle");
const encryptToggle = document.getElementById("encrypt-toggle");
const unlockOnLoadToggle = document.getElementById("unlock-on-load");
const blurCodesToggle = document.getElementById("blur-codes-toggle");
const clearClipboardToggle = document.getElementById("clear-clipboard-toggle");
const encryptionFields = document.getElementById("encryption-fields");
const vaultPassphraseInput = document.getElementById("vault-passphrase");
const vaultPassphraseConfirmInput = document.getElementById("vault-passphrase-confirm");
const saveSettingsBtn = document.getElementById("save-settings");
const settingsStatus = document.getElementById("settings-status");
const exportBackupBtn = document.getElementById("export-backup");
const importBackupInput = document.getElementById("import-backup");
const installAppBtn = document.getElementById("install-app");
const lockAppBtn = document.getElementById("lock-app");
const unlockPanel = document.getElementById("unlock-panel");
const unlockPassphraseInput = document.getElementById("unlock-passphrase");
const unlockBtn = document.getElementById("unlock-btn");
const unlockStatus = document.getElementById("unlock-status");
const privacyDialog = document.getElementById("privacy-dialog");

const defaultSettings = {
  persist: false,
  encrypt: false,
  unlockOnLoad: false,
  blurCodes: false,
  clearClipboard: false,
};

let settings = loadSettings();
let entries = [];
let entryNodes = new Map();
let currentPassphrase = "";
let cameraStream = null;
let cameraScanTimer = null;
let deferredInstallPrompt = null;
let cameraDetection = { uri: "", hits: 0 };

initialize();

function initialize() {
  syncSettingsUI();
  applyVisualSettings();
  loadVaultOnStartup();
  renderEntries();
  tick();
  bindEvents();
  setInterval(tick, 1000);
  registerPwaSupport();
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
  unlockOnLoadToggle.checked = settings.unlockOnLoad;
  blurCodesToggle.checked = settings.blurCodes;
  clearClipboardToggle.checked = settings.clearClipboard;
  encryptionFields.classList.toggle("hidden", !settings.encrypt);
}

function applyVisualSettings() {
  document.body.classList.toggle("blur-codes", settings.blurCodes);
}

function setStatus(node, message, tone = "") {
  node.textContent = message;
  node.classList.remove("error", "success");
  if (tone) node.classList.add(tone);
}

function setImportStatus(message, tone = "") {
  setStatus(importStatus, message, tone);
}

function setSettingsStatus(message, tone = "") {
  setStatus(settingsStatus, message, tone);
}

function setUnlockStatus(message, tone = "") {
  setStatus(unlockStatus, message, tone);
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
    entries = [];
    setLocked(true);
    if (!settings.unlockOnLoad && !localStorage.getItem(ENCRYPTED_VAULT_KEY)) {
      setLocked(false);
    }
    return;
  }

  entries = loadPlainEntries();
  setLocked(false);
}

function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  lockAppBtn.disabled = locked;
  form.querySelectorAll("input, button, select").forEach((el) => {
    if (el.id === "unlock-passphrase" || el.id === "unlock-btn") return;
    el.disabled = locked;
  });
  searchInput.disabled = locked;
}

function loadPlainEntries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return normalizeEntries(JSON.parse(raw));
  } catch (error) {
    reportError("Failed to load plain entries", error);
    return [];
  }
}

function savePlainEntries() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

function clearPersistedEntries() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
}

function sortedEntries() {
  return [...entries].sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return a.label.localeCompare(b.label, undefined, { sensitivity: "base" });
  });
}

function getVisibleEntries() {
  const query = (searchInput.value || "").trim().toLowerCase();
  const ordered = sortedEntries();
  if (!query) return ordered;
  return ordered.filter((entry) => entry.label.toLowerCase().includes(query));
}

function showEmptyState(message) {
  entriesRoot.innerHTML = "";
  const empty = document.createElement("p");
  empty.className = "helper-text";
  empty.textContent = message;
  entriesRoot.appendChild(empty);
}

function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  const avatar = node.querySelector(".entry-avatar");
  const label = node.querySelector(".entry-label");
  const account = node.querySelector(".entry-account");
  const meta = node.querySelector(".entry-meta");
  const copyBtn = node.querySelector(".copy");
  const revealBtn = node.querySelector(".reveal");
  const pinBtn = node.querySelector(".pin");
  const removeBtn = node.querySelector(".remove");

  avatar.textContent = getIssuerInitials(entry.label);
  refreshEntryMetadata(node, entry);

  copyBtn.onclick = async () => {
    try {
      const latestCode = node.dataset.otp;
      if (!latestCode) return;
      await navigator.clipboard.writeText(latestCode);
      copyBtn.textContent = "Copied";
      if (settings.clearClipboard) {
        setTimeout(() => {
          navigator.clipboard.writeText("").catch((error) => reportError("Clipboard clear failed", error));
        }, 30000);
      }
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1000);
    } catch (error) {
      reportError("Copy failed", error);
      setImportStatus(toUserMessage(error, "Could not copy OTP to clipboard"), "error");
    }
  };

  revealBtn.onclick = () => {
    node.classList.toggle("revealed");
    revealBtn.textContent = node.classList.contains("revealed") ? "Hide" : "Reveal";
  };

  pinBtn.onclick = async () => {
    try {
      await replaceEntries(entries.map((item) => (
        item.id === entry.id ? { ...item, pinned: !item.pinned } : item
      )));
      setImportStatus("Entry order updated", "success");
    } catch (error) {
      reportError("Pin toggle failed", error);
      setImportStatus(toUserMessage(error, "Could not update entry order"), "error");
    }
  };

  removeBtn.onclick = async () => {
    try {
      const nextEntries = entries.filter((item) => item.id !== entry.id);
      await replaceEntries(nextEntries);
      setImportStatus("Entry removed", "success");
    } catch (error) {
      reportError("Entry removal failed", error);
      setImportStatus(toUserMessage(error, "Could not remove entry"), "error");
    }
  };

  return node;
}

function refreshEntryMetadata(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".entry-label").textContent = parts.issuer;
  node.querySelector(".entry-account").textContent = parts.account;
  node.querySelector(".entry-meta").textContent = `${entry.digits} digits • ${entry.period}s`;
}

function renderEntries() {
  if (!unlockPanel.classList.contains("hidden") && settings.encrypt) {
    showEmptyState("Vault is locked. Unlock to view your codes.");
    return;
  }

  if (entries.length === 0) {
    entryNodes.clear();
    showEmptyState("No entries yet. Import a URI, scan a QR, or add one manually.");
    return;
  }

  const visibleEntries = getVisibleEntries();
  if (visibleEntries.length === 0) {
    showEmptyState("No matching entries.");
    return;
  }

  entriesRoot.innerHTML = "";
  const fragment = document.createDocumentFragment();

  for (const entry of visibleEntries) {
    let node = entryNodes.get(entry.id);
    if (!node) {
      node = createEntryNode(entry);
      entryNodes.set(entry.id, node);
    }
    refreshEntryMetadata(node, entry);
    node.classList.toggle("pinned", entry.pinned);
    node.querySelector(".pin").textContent = entry.pinned ? "Unpin" : "Pin";
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

  const code = node.querySelector(".entry-code");
  const seconds = node.querySelector(".entry-seconds");
  const bar = node.querySelector(".entry-bar");
  const copyBtn = node.querySelector(".copy");
  const remaining = entry.period - (now % entry.period);
  seconds.textContent = `${remaining}s left`;
  bar.style.transform = `scaleX(${remaining / entry.period})`;
  node.classList.toggle("urgent", remaining <= 10);

  try {
    const otp = await generateTotp(entry.secret, entry.digits, entry.period, now);
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
  const remaining = period - (now % period);
  timerValue.textContent = `${remaining}s`;
  timerBar.style.transform = `scaleX(${remaining / period})`;
}

async function tick() {
  const now = Math.floor(Date.now() / 1000);
  updateTimer(now);
  if (!unlockPanel.classList.contains("hidden") && settings.encrypt) return;
  await updateAllEntries(now);
}

async function saveEncryptedEntries(payloadEntries, passphrase) {
  const encryptedPayload = await encryptEntries(payloadEntries, passphrase);
  localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(encryptedPayload));
  return encryptedPayload;
}

async function decryptStoredEntries(passphrase) {
  const raw = localStorage.getItem(ENCRYPTED_VAULT_KEY);
  if (!raw) return [];

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    throw new Error("Encrypted data is unreadable", { cause: error });
  }

  return decryptVaultEntries(payload, passphrase);
}

async function persistEntries() {
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
    return;
  }

  savePlainEntries();
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
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

function buildManualEntry(input) {
  const entry = normalizeEntry({ ...input, pinned: false });
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

async function importOtpAuthUri(otpUri, sourceLabel = "Import") {
  const parsed = parseOtpAuthUri(otpUri);
  if (hasDuplicateEntry(entries, parsed)) {
    throw new Error("This account already exists");
  }
  await replaceEntries([...entries, parsed]);
  setImportStatus(`${sourceLabel}: account imported`, "success");
}

async function decodeQrFromBlob(blob) {
  if (typeof window.jsQR !== "function") {
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
  const result = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  if (!result?.data) {
    throw new Error("Could not detect a QR code in that image");
  }
  return result.data;
}

async function importFromQrBlob(blob, sourceLabel) {
  const qrText = await decodeQrFromBlob(blob);
  const otpUri = extractOtpAuthUri(qrText);
  if (!otpUri) {
    throw new Error("QR code was detected but does not contain a valid OTP URI");
  }
  await importOtpAuthUri(otpUri, sourceLabel);
}

async function unlockVault(passphrase) {
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const decrypted = await decryptStoredEntries(normalizedPassphrase);
  currentPassphrase = normalizedPassphrase;
  entries = decrypted;
  setLocked(false);
  renderEntries();
  await tick();
}

async function handleSaveSettings() {
  if (persistToggle.checked && !hasSeenPersistWarning()) {
    if (typeof privacyDialog.showModal === "function") {
      privacyDialog.showModal();
      return;
    }
  }

  const nextSettings = {
    persist: persistToggle.checked,
    encrypt: encryptToggle.checked,
    unlockOnLoad: unlockOnLoadToggle.checked,
    blurCodes: blurCodesToggle.checked,
    clearClipboard: clearClipboardToggle.checked,
  };

  let nextPassphrase = currentPassphrase;
  if (nextSettings.encrypt) {
    const first = vaultPassphraseInput.value.trim();
    const second = vaultPassphraseConfirmInput.value.trim();

    if (!currentPassphrase && !first) {
      throw new Error("Enter a passphrase to enable encryption");
    }
    if (first || second) {
      if (first !== second) {
        throw new Error("Passphrase confirmation does not match");
      }
      nextPassphrase = normalizePassphrase(first);
    }
  } else {
    nextPassphrase = "";
  }

  settings = nextSettings;
  currentPassphrase = nextPassphrase;
  saveSettings();
  syncSettingsUI();
  applyVisualSettings();

  if (!settings.persist) {
    clearPersistedEntries();
    setLocked(false);
    setSettingsStatus("Entries are now session-only", "success");
    vaultPassphraseInput.value = "";
    vaultPassphraseConfirmInput.value = "";
    return;
  }

  await persistEntries();
  setLocked(false);
  setSettingsStatus(settings.encrypt ? "Encrypted vault saved" : "Device storage updated", "success");
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
  if (settings.encrypt) {
    if (!currentPassphrase) {
      throw new Error("Unlock the vault before exporting encrypted backup");
    }
    const encryptedPayload = await encryptEntries(entries, currentPassphrase);
    downloadJson("otp-vault-backup.json", createEncryptedBackup(encryptedPayload));
    return;
  }

  downloadJson("otp-vault-backup.json", createPlainBackup(entries));
}

async function importBackupFile(file) {
  const text = await file.text();

  let backup;
  try {
    backup = parseBackupFile(JSON.parse(text));
  } catch (error) {
    throw new Error(toUserMessage(error, "Backup file is invalid"));
  }

  if (backup.encrypted) {
    const passphrase = window.prompt("Backup is encrypted. Enter the backup passphrase:");
    if (!passphrase) throw new Error("Backup import cancelled");
    const decrypted = await decryptVaultEntries(backup.vault, passphrase);
    if (settings.encrypt) {
      currentPassphrase = normalizePassphrase(passphrase);
    }
    await replaceEntries(decrypted);
    return;
  }

  await replaceEntries(backup.entries);
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
    if (!cameraPreview.videoWidth || !cameraPreview.videoHeight || typeof window.jsQR !== "function") return;

    canvas.width = cameraPreview.videoWidth;
    canvas.height = cameraPreview.videoHeight;
    ctx.drawImage(cameraPreview, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const result = window.jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
    const otpUri = extractOtpAuthUri(result?.data || "");
    if (!otpUri) {
      cameraDetection = { uri: "", hits: 0 };
      return;
    }

    if (!registerCameraDetection(otpUri)) {
      setImportStatus("Potential OTP QR detected. Confirming with another frame...", "success");
      return;
    }

    try {
      await importOtpAuthUri(otpUri, "Camera");
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
}

function bindEvents() {
  encryptToggle.addEventListener("change", () => {
    encryptionFields.classList.toggle("hidden", !encryptToggle.checked);
  });

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
      syncSettingsUI();
      setImportStatus("Entry added", "success");
    } catch (error) {
      reportError("Manual entry failed", error);
      setImportStatus(toUserMessage(error, "Could not add entry"), "error");
    }
  });

  parseUriBtn.addEventListener("click", async () => {
    try {
      const otpUri = extractOtpAuthUri(uriInput.value);
      if (!otpUri) throw new Error("No valid otpauth:// URI found");
      await importOtpAuthUri(otpUri, "URI");
      uriInput.value = "";
    } catch (error) {
      reportError("URI import failed", error);
      setImportStatus(toUserMessage(error, "Invalid URI"), "error");
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
      const otpUri = extractOtpAuthUri(text);
      if (!otpUri) throw new Error("Clipboard does not contain a valid OTP URI or QR image");
      await importOtpAuthUri(otpUri, "Clipboard");
    } catch (error) {
      reportError("Clipboard import failed", error);
      setImportStatus(toUserMessage(error, "Failed to import from clipboard"), "error");
    }
  });

  startCameraBtn.addEventListener("click", async () => {
    try {
      setImportStatus("Starting camera...");
      await startCameraScan();
      setImportStatus("Camera ready. Hold a QR code in front of it.", "success");
    } catch (error) {
      reportError("Camera start failed", error);
      setImportStatus(toUserMessage(error, "Could not start camera"), "error");
    }
  });

  stopCameraBtn.addEventListener("click", () => {
    stopCameraScan();
    setImportStatus("Camera stopped");
  });

  clearAllBtn.addEventListener("click", async () => {
    try {
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

  saveSettingsBtn.addEventListener("click", async () => {
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

  importBackupInput.addEventListener("change", async () => {
    const [file] = importBackupInput.files || [];
    if (!file) return;

    try {
      await importBackupFile(file);
      setSettingsStatus("Backup imported", "success");
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
    entries = [];
    setLocked(true);
    renderEntries();
  });

  unlockBtn.addEventListener("click", async () => {
    try {
      await unlockVault(unlockPassphraseInput.value);
      unlockPassphraseInput.value = "";
      setUnlockStatus("Vault unlocked", "success");
    } catch (error) {
      reportError("Vault unlock failed", error);
      setUnlockStatus(toUserMessage(error, "Incorrect passphrase or unreadable encrypted vault"), "error");
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
}

window.otpVaultDebug = {
  extractOtpAuthUri,
  parseLabelParts,
  parseOtpAuthUri,
};
