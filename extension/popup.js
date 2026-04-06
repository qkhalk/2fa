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
    entries = Array.isArray(stored[STORAGE_KEY]) ? stored[STORAGE_KEY].map(normalizeEntry) : [];
    setLocked(false);
  }

  bindEvents();
  renderEntries();
  tick();
  setInterval(tick, 1000);
}

function normalizeEntry(entry) {
  return {
    id: entry.id || `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    label: (entry.label || "Manual Entry").trim() || "Manual Entry",
    secret: sanitizeBase32(entry.secret || ""),
    digits: entry.digits === 8 ? 8 : 6,
    period: Math.max(15, Math.min(120, Number(entry.period) || 30)),
  };
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

function sanitizeBase32(value) {
  return value.toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}

function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };
  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return { issuer: issuer.trim() || clean, account: rest.join(":").trim() || "No account label" };
  }
  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return { issuer: issuer.trim() || clean, account: rest.join(" - ").trim() || "No account label" };
  }
  return { issuer: clean, account: "No account label" };
}

function getInitials(label) {
  const issuer = parseLabelParts(label).issuer;
  const parts = issuer.split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "OT";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
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

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = sanitizeBase32(base32);
  let bits = "";
  for (const char of clean) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) throw new Error("Invalid Base32 secret");
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

async function generateTotp(entry, now) {
  const digest = await hmacSha1(base32ToBytes(entry.secret), toCounterBytes(Math.floor(now / entry.period)));
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  return (binary % (10 ** entry.digits)).toString().padStart(entry.digits, "0");
}

function formatCode(code) {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : `${code.slice(0, 4)} ${code.slice(4)}`;
}

function parseOtpAuthUri(uri) {
  const parsed = new URL(uri);
  return normalizeEntry({
    label: decodeURIComponent(parsed.pathname.replace(/^\//, "")) || "Imported",
    secret: parsed.searchParams.get("secret") || "",
    digits: Number(parsed.searchParams.get("digits") || 6),
    period: Number(parsed.searchParams.get("period") || 30),
  });
}

function findOtpUri(text) {
  const match = (text || "").trim().match(/otpauth:\/\/[^\s"']+/i);
  return match ? match[0] : "";
}

function filteredEntries() {
  const q = (searchInput.value || "").trim().toLowerCase();
  return [...entries]
    .sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: "base" }))
    .filter((entry) => entry.label.toLowerCase().includes(q));
}

function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  const parts = parseLabelParts(entry.label);

  node.querySelector(".avatar").textContent = getInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits • ${entry.period}s`;

  node.querySelector(".copy").addEventListener("click", async () => {
    const otp = node.dataset.otp;
    if (!otp) return;
    await navigator.clipboard.writeText(otp);
    setStatus(`Copied ${parts.issuer} code`, "success");
  });

  node.querySelector(".remove").addEventListener("click", async () => {
    entries = entries.filter((item) => item.id !== entry.id);
    await persistEntries();
    renderEntries();
    tick();
    setStatus(`Removed ${parts.issuer}`);
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
    const code = await generateTotp(entry, now);
    node.dataset.otp = code;
    node.querySelector(".code").textContent = formatCode(code);
    node.querySelector(".seconds").textContent = `${remaining}s`;
    node.querySelector(".bar").style.transform = `scaleX(${remaining / entry.period})`;
    node.classList.toggle("urgent", remaining <= 10);
  } catch {
    node.querySelector(".code").textContent = "Invalid";
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

function bytesToBase64(uint8) {
  return btoa(String.fromCharCode(...uint8));
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

async function deriveVaultKey(passphrase, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function saveEncryptedEntries(passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(passphrase, salt);
  const payload = new TextEncoder().encode(JSON.stringify(entries));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  await chrome.storage.local.set({
    [ENCRYPTED_KEY]: {
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      data: bytesToBase64(new Uint8Array(encrypted)),
    },
  });
  await chrome.storage.local.remove(STORAGE_KEY);
}

async function decryptEntries(passphrase) {
  const stored = await chrome.storage.local.get(ENCRYPTED_KEY);
  const payload = stored[ENCRYPTED_KEY];
  if (!payload) return [];
  const key = await deriveVaultKey(passphrase, base64ToBytes(payload.salt));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(payload.iv) },
    key,
    base64ToBytes(payload.data)
  );
  return JSON.parse(new TextDecoder().decode(decrypted)).map(normalizeEntry);
}

async function persistEntries() {
  if (settings.encrypt) {
    if (!currentPassphrase) throw new Error("Unlock extension vault before saving encrypted entries");
    await saveEncryptedEntries(currentPassphrase);
    return;
  }
  await chrome.storage.local.set({ [STORAGE_KEY]: entries });
  await chrome.storage.local.remove(ENCRYPTED_KEY);
}

async function persistSettings() {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function importFromQrFile(file) {
  if (typeof BarcodeDetector !== "function") {
    throw new Error("QR file import requires Chrome BarcodeDetector support");
  }
  const bitmap = await createImageBitmap(file);
  const detector = new BarcodeDetector({ formats: ["qr_code"] });
  const results = await detector.detect(bitmap);
  bitmap.close();
  if (!results.length || !results[0].rawValue) throw new Error("Could not detect a QR code in that file");
  const uri = findOtpUri(results[0].rawValue);
  if (!uri) throw new Error("QR file does not contain an otpauth URI");
  return parseOtpAuthUri(uri);
}

function bindEvents() {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const entry = normalizeEntry({
        label: labelInput.value,
        secret: secretInput.value,
        digits: Number(digitsInput.value),
        period: Number(periodInput.value),
      });
      const duplicate = entries.some((item) => item.secret === entry.secret && item.digits === entry.digits && item.period === entry.period);
      if (duplicate) throw new Error("This entry already exists");
      entries.push(entry);
      await persistEntries();
      form.reset();
      digitsInput.value = "6";
      periodInput.value = "30";
      renderEntries();
      tick();
      setStatus("Entry added", "success");
    } catch (error) {
      setStatus(error.message || "Could not add entry", "error");
    }
  });

  qrFileInput.addEventListener("change", async () => {
    const [file] = qrFileInput.files || [];
    if (!file) return;
    try {
      const entry = await importFromQrFile(file);
      const duplicate = entries.some((item) => item.secret === entry.secret && item.digits === entry.digits && item.period === entry.period);
      if (duplicate) throw new Error("This entry already exists");
      entries.push(entry);
      await persistEntries();
      renderEntries();
      tick();
      setStatus("Imported QR entry", "success");
    } catch (error) {
      setStatus(error.message || "Could not import QR file", "error");
    } finally {
      qrFileInput.value = "";
    }
  });

  pasteUriBtn.addEventListener("click", async () => {
    try {
      const text = await navigator.clipboard.readText();
      const uri = findOtpUri(text);
      if (!uri) throw new Error("Clipboard does not contain an otpauth URI");
      const entry = parseOtpAuthUri(uri);
      const duplicate = entries.some((item) => item.secret === entry.secret && item.digits === entry.digits && item.period === entry.period);
      if (duplicate) throw new Error("This entry already exists");
      entries.push(entry);
      await persistEntries();
      renderEntries();
      tick();
      setStatus("Imported URI from clipboard", "success");
    } catch (error) {
      setStatus(error.message || "Could not import URI", "error");
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
          if (first.length < 8) throw new Error("Use at least 8 characters for the passphrase");
          if (first !== second) throw new Error("Passphrase confirmation does not match");
          nextPassphrase = first;
        }
        currentPassphrase = nextPassphrase;
        await saveEncryptedEntries(currentPassphrase);
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
      setStatus(error.message || "Could not save security settings", "error");
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
      entries = await decryptEntries(unlockPassphraseInput.value);
      currentPassphrase = unlockPassphraseInput.value;
      unlockPassphraseInput.value = "";
      setLocked(false);
      renderEntries();
      tick();
      setUnlockStatus("Vault unlocked", "success");
      setStatus("Encrypted extension unlocked", "success");
    } catch {
      setUnlockStatus("Incorrect passphrase or unreadable encrypted data", "error");
    }
  });
}
