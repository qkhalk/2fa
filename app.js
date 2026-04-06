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
  } catch {
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
  encryptionFields.classList.toggle("hidden", !encryptToggle.checked);
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
  ensureEntryShape();
  setLocked(false);
}

function setLocked(locked) {
  unlockPanel.classList.toggle("hidden", !locked);
  lockAppBtn.disabled = locked;
  form.querySelectorAll("input, button, select").forEach((el) => {
    if (el.id === "unlock-passphrase") return;
    if (el.id === "unlock-btn") return;
    el.disabled = locked;
  });
  searchInput.disabled = locked;
}

function loadPlainEntries() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
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

function sanitizeBase32(value) {
  return value.toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}

function generateEntryId() {
  return `entry_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function normalizeEntry(entry) {
  const label = (entry.label || "").trim() || createFallbackLabel(entry.secret || "");
  return {
    id: entry.id || generateEntryId(),
    label,
    secret: sanitizeBase32(entry.secret || ""),
    digits: entry.digits === 8 ? 8 : 6,
    period: Math.max(15, Math.min(120, Number(entry.period) || 30)),
    pinned: Boolean(entry.pinned),
  };
}

function ensureEntryShape() {
  entries = entries.map(normalizeEntry);
}

function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}

function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };

  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(":").trim() || "No account label",
    };
  }

  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(" - ").trim() || "No account label",
    };
  }

  return { issuer: clean, account: "No account label" };
}

function getIssuerInitials(label) {
  const issuer = parseLabelParts(label).issuer;
  const parts = issuer.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "OT";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
}

function sortedEntries() {
  return [...entries].sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return a.label.localeCompare(b.label, undefined, { sensitivity: "base" });
  });
}

function getVisibleEntries() {
  const q = (searchInput.value || "").trim().toLowerCase();
  const ordered = sortedEntries();
  if (!q) return ordered;
  return ordered.filter((entry) => entry.label.toLowerCase().includes(q));
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
  const parts = parseLabelParts(entry.label);

  avatar.textContent = getIssuerInitials(entry.label);
  label.textContent = parts.issuer;
  account.textContent = parts.account;
  meta.textContent = `${entry.digits} digits • ${entry.period}s`;

  copyBtn.onclick = async () => {
    const latestCode = node.dataset.otp;
    if (!latestCode) return;
    await navigator.clipboard.writeText(latestCode);
    copyBtn.textContent = "Copied";
    if (settings.clearClipboard) {
      setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 30000);
    }
    setTimeout(() => {
      copyBtn.textContent = "Copy";
    }, 1000);
  };

  revealBtn.onclick = () => {
    node.classList.toggle("revealed");
    revealBtn.textContent = node.classList.contains("revealed") ? "Hide" : "Reveal";
  };

  pinBtn.onclick = () => {
    const target = entries.find((item) => item.id === entry.id);
    if (!target) return;
    target.pinned = !target.pinned;
    persistEntries().catch(() => {});
    renderEntries();
    tick();
  };

  removeBtn.onclick = () => {
    entries = entries.filter((item) => item.id !== entry.id);
    persistEntries().catch(() => {});
    renderEntries();
    tick();
  };

  return node;
}

function renderEntries() {
  if (unlockPanel && !unlockPanel.classList.contains("hidden") && settings.encrypt) {
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
  const activeIds = new Set();

  for (const entry of visibleEntries) {
    activeIds.add(entry.id);
    let node = entryNodes.get(entry.id);
    if (!node) {
      node = createEntryNode(entry);
      entryNodes.set(entry.id, node);
    }
    node.classList.toggle("pinned", entry.pinned);
    node.querySelector(".pin").textContent = entry.pinned ? "Unpin" : "Pin";
    fragment.appendChild(node);
  }

  for (const [id] of entryNodes) {
    if (!entries.some((entry) => entry.id === id)) entryNodes.delete(id);
  }

  entriesRoot.appendChild(fragment);
}

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();

  let bits = "";
  for (const char of clean) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error("Secret contains invalid Base32 characters");
    bits += idx.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let temp = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

async function generateTotp(secret, digits, period, now) {
  const counter = Math.floor(now / period);
  const secretBytes = base32ToBytes(secret);
  const digest = await hmacSha1(secretBytes, toCounterBytes(counter));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  return (binary % (10 ** digits)).toString().padStart(digits, "0");
}

function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;
  const code = node.querySelector(".entry-code");
  const seconds = node.querySelector(".entry-seconds");
  const bar = node.querySelector(".entry-bar");
  const copyBtn = node.querySelector(".copy");

  const remaining = entry.period - (now % entry.period);
  const ratio = remaining / entry.period;
  seconds.textContent = `${remaining}s left`;
  bar.style.transform = `scaleX(${ratio})`;
  node.classList.toggle("urgent", remaining <= 10);

  try {
    const otp = await generateTotp(entry.secret, entry.digits, entry.period, now);
    code.textContent = formatCode(otp);
    node.dataset.otp = otp;
    copyBtn.disabled = false;
  } catch {
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

function parseOtpAuthUri(uri) {
  if (!uri.startsWith("otpauth://")) throw new Error("URI must start with otpauth://");
  const parsed = new URL(uri);
  if (parsed.hostname !== "totp") throw new Error("Only TOTP URIs are supported");
  return {
    label: decodeURIComponent(parsed.pathname.replace(/^\//, "")) || "Imported Account",
    secret: parsed.searchParams.get("secret") || "",
    digits: Number(parsed.searchParams.get("digits") || 6) === 8 ? 8 : 6,
    period: Number(parsed.searchParams.get("period") || 30),
  };
}

function normalizeUriCandidate(raw) {
  return (raw || "").trim().replace(/[)\],.;]+$/, "");
}

function findOtpAuthUri(rawText) {
  const text = normalizeUriCandidate(rawText);
  if (!text) return "";
  if (text.startsWith("otpauth://")) return text;
  const match = text.match(/otpauth:\/\/[^\s"']+/i);
  if (match) return normalizeUriCandidate(match[0]);
  try {
    const decoded = decodeURIComponent(text);
    if (decoded.startsWith("otpauth://")) return normalizeUriCandidate(decoded);
    const decodedMatch = decoded.match(/otpauth:\/\/[^\s"']+/i);
    return decodedMatch ? normalizeUriCandidate(decodedMatch[0]) : "";
  } catch {
    return "";
  }
}

function hasDuplicateEntry(secret, digits, period) {
  const cleanSecret = sanitizeBase32(secret);
  return entries.some((entry) => entry.secret === cleanSecret && entry.digits === digits && entry.period === period);
}

async function persistEntries() {
  if (!settings.persist) {
    clearPersistedEntries();
    return;
  }

  if (settings.encrypt) {
    if (!currentPassphrase) throw new Error("Unlock or set a passphrase before saving encrypted entries");
    await saveEncryptedEntries(entries, currentPassphrase);
    localStorage.removeItem(STORAGE_KEY);
    return;
  }

  savePlainEntries();
  localStorage.removeItem(ENCRYPTED_VAULT_KEY);
}

function addEntry({ label, secret, digits, period }) {
  const normalized = normalizeEntry({ label, secret, digits, period, pinned: false });
  if (hasDuplicateEntry(normalized.secret, normalized.digits, normalized.period)) {
    throw new Error("This account already exists");
  }
  entries.push(normalized);
}

function importOtpAuthUri(otpUri, sourceLabel = "Import") {
  const parsed = parseOtpAuthUri(otpUri);
  addEntry(parsed);
  persistEntries().catch((error) => setImportStatus(error.message || "Could not save imported entry", "error"));
  renderEntries();
  tick();
  setImportStatus(`${sourceLabel}: account imported`, "success");
}

async function decodeQrFromBlob(blob) {
  if (typeof jsQR !== "function") throw new Error("QR scanner library failed to load");
  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const result = jsQR(imageData.data, imageData.width, imageData.height, { inversionAttempts: "attemptBoth" });
  if (!result || !result.data) throw new Error("Could not detect a QR code in that image");
  return result.data;
}

async function importFromQrBlob(blob, sourceLabel) {
  const qrText = await decodeQrFromBlob(blob);
  const otpUri = findOtpAuthUri(qrText);
  if (!otpUri) throw new Error("QR does not contain an otpauth:// URI");
  importOtpAuthUri(otpUri, sourceLabel);
}

function bytesToBase64(uint8) {
  return btoa(String.fromCharCode(...uint8));
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

async function deriveVaultKey(passphrase, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function saveEncryptedEntries(payloadEntries, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(passphrase, salt);
  const encoded = new TextEncoder().encode(JSON.stringify(payloadEntries));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify({
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    data: bytesToBase64(new Uint8Array(cipher)),
  }));
}

async function decryptStoredEntries(passphrase) {
  const raw = localStorage.getItem(ENCRYPTED_VAULT_KEY);
  if (!raw) return [];
  const payload = JSON.parse(raw);
  const salt = base64ToBytes(payload.salt);
  const iv = base64ToBytes(payload.iv);
  const data = base64ToBytes(payload.data);
  const key = await deriveVaultKey(passphrase, salt);
  const decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  const parsed = JSON.parse(new TextDecoder().decode(decoded));
  return Array.isArray(parsed) ? parsed.map(normalizeEntry) : [];
}

async function unlockVault(passphrase) {
  const decrypted = await decryptStoredEntries(passphrase);
  currentPassphrase = passphrase;
  entries = decrypted;
  ensureEntryShape();
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
    if (!currentPassphrase && !first) throw new Error("Enter a passphrase to enable encryption");
    if (first || second) {
      if (first.length < 8) throw new Error("Use a passphrase with at least 8 characters");
      if (first !== second) throw new Error("Passphrase confirmation does not match");
      nextPassphrase = first;
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
    if (!currentPassphrase) throw new Error("Unlock the vault before exporting encrypted backup");
    await saveEncryptedEntries(entries, currentPassphrase);
    const encrypted = JSON.parse(localStorage.getItem(ENCRYPTED_VAULT_KEY) || "{}");
    downloadJson("otp-vault-backup.json", {
      version: 1,
      encrypted: true,
      createdAt: new Date().toISOString(),
      vault: encrypted,
    });
    return;
  }

  downloadJson("otp-vault-backup.json", {
    version: 1,
    encrypted: false,
    createdAt: new Date().toISOString(),
    entries,
  });
}

async function importBackupFile(file) {
  const text = await file.text();
  const backup = JSON.parse(text);
  if (backup.encrypted) {
    const passphrase = window.prompt("Backup is encrypted. Enter the backup passphrase:");
    if (!passphrase) throw new Error("Backup import cancelled");
    localStorage.setItem(ENCRYPTED_VAULT_KEY, JSON.stringify(backup.vault));
    const decrypted = await decryptStoredEntries(passphrase);
    currentPassphrase = settings.encrypt ? passphrase : currentPassphrase;
    entries = decrypted;
  } else {
    entries = Array.isArray(backup.entries) ? backup.entries.map(normalizeEntry) : [];
  }

  ensureEntryShape();
  await persistEntries().catch(() => {});
  renderEntries();
  await tick();
}

async function startCameraScan() {
  if (cameraStream) return;
  cameraStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
  cameraPreview.srcObject = cameraStream;
  await cameraPreview.play();
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });

  cameraScanTimer = setInterval(async () => {
    if (!cameraPreview.videoWidth || !cameraPreview.videoHeight) return;
    canvas.width = cameraPreview.videoWidth;
    canvas.height = cameraPreview.videoHeight;
    ctx.drawImage(cameraPreview, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const result = typeof jsQR === "function" ? jsQR(imageData.data, imageData.width, imageData.height) : null;
    if (!result || !result.data) return;
    const otpUri = findOtpAuthUri(result.data);
    if (!otpUri) return;
    importOtpAuthUri(otpUri, "Camera");
    stopCameraScan();
  }, 900);
}

function stopCameraScan() {
  if (cameraScanTimer) clearInterval(cameraScanTimer);
  cameraScanTimer = null;
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
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  }
}

function bindEvents() {
  encryptToggle.addEventListener("change", () => {
    encryptionFields.classList.toggle("hidden", !encryptToggle.checked);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      addEntry({
        label: labelInput.value,
        secret: secretInput.value,
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
      });
      await persistEntries();
      form.reset();
      digitsInput.value = "6";
      periodInput.value = "30";
      syncSettingsUI();
      renderEntries();
      await tick();
      setImportStatus("Entry added", "success");
    } catch (error) {
      setImportStatus(error.message || "Could not add entry", "error");
    }
  });

  parseUriBtn.addEventListener("click", () => {
    try {
      const otpUri = findOtpAuthUri(uriInput.value);
      if (!otpUri) throw new Error("No otpauth:// URI found");
      importOtpAuthUri(otpUri, "URI");
      uriInput.value = "";
    } catch (error) {
      setImportStatus(error.message || "Invalid URI", "error");
    }
  });

  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    setImportStatus("Reading QR file...");
    try {
      await importFromQrBlob(file, "QR file");
    } catch (error) {
      setImportStatus(error.message || "Failed to import QR file", "error");
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
      setImportStatus(error.message || "Failed to import from URL", "error");
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
      const otpUri = findOtpAuthUri(text);
      if (!otpUri) throw new Error("Clipboard has no otpauth:// URI or QR image");
      importOtpAuthUri(otpUri, "Clipboard");
    } catch (error) {
      setImportStatus(error.message || "Failed to import from clipboard", "error");
    }
  });

  startCameraBtn.addEventListener("click", async () => {
    try {
      setImportStatus("Starting camera...");
      await startCameraScan();
      setImportStatus("Camera ready. Hold a QR code in front of it.", "success");
    } catch (error) {
      setImportStatus(error.message || "Could not start camera", "error");
    }
  });

  stopCameraBtn.addEventListener("click", () => {
    stopCameraScan();
    setImportStatus("Camera stopped");
  });

  clearAllBtn.addEventListener("click", async () => {
    entries = [];
    await persistEntries().catch(() => {});
    renderEntries();
    await tick();
    setImportStatus("All entries cleared");
  });

  searchInput.addEventListener("input", () => {
    renderEntries();
    tick();
  });

  saveSettingsBtn.addEventListener("click", async () => {
    try {
      await handleSaveSettings();
    } catch (error) {
      setSettingsStatus(error.message || "Could not save settings", "error");
    }
  });

  exportBackupBtn.addEventListener("click", async () => {
    try {
      await exportBackup();
      setSettingsStatus("Backup exported", "success");
    } catch (error) {
      setSettingsStatus(error.message || "Could not export backup", "error");
    }
  });

  importBackupInput.addEventListener("change", async () => {
    const [file] = importBackupInput.files || [];
    if (!file) return;
    try {
      await importBackupFile(file);
      setSettingsStatus("Backup imported", "success");
    } catch (error) {
      setSettingsStatus(error.message || "Could not import backup", "error");
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
    } catch {
      setUnlockStatus("Incorrect passphrase or unreadable encrypted vault", "error");
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
        setSettingsStatus(error.message || "Could not save settings", "error");
      });
    } else {
      persistToggle.checked = settings.persist;
    }
  });
}

window.otpVaultDebug = {
  parseLabelParts,
  findOtpAuthUri,
};
