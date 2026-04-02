const STORAGE_KEY = "personal_otp_vault_entries_v1";
const PERSIST_KEY = "personal_otp_vault_persist_v1";
const PERSIST_WARNING_KEY = "personal_otp_vault_persist_warning_seen_v1";

const form = document.getElementById("otp-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
const uriInput = document.getElementById("uri");
const persistToggle = document.getElementById("persist-toggle");
const privacyDialog = document.getElementById("privacy-dialog");
const parseUriBtn = document.getElementById("parse-uri");
const importClipboardBtn = document.getElementById("import-clipboard");
const qrFileInput = document.getElementById("qr-file");
const qrUrlInput = document.getElementById("qr-url");
const importQrUrlBtn = document.getElementById("import-qr-url");
const clearAllBtn = document.getElementById("clear-all");
const entriesRoot = document.getElementById("entries");
const template = document.getElementById("entry-template");
const searchInput = document.getElementById("search");
const importStatus = document.getElementById("import-status");
const timerValue = document.getElementById("timer-value");
const timerBar = document.getElementById("timer-bar");

let persistEnabled = loadPersistPreference();
let entries = loadEntries();
let entryNodes = new Map();

ensureEntryIds();

function loadPersistPreference() {
  return localStorage.getItem(PERSIST_KEY) === "true";
}

function hasSeenPersistWarning() {
  return localStorage.getItem(PERSIST_WARNING_KEY) === "true";
}

function markPersistWarningSeen() {
  localStorage.setItem(PERSIST_WARNING_KEY, "true");
}

function loadEntries() {
  if (!persistEnabled) return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveEntries() {
  if (!persistEnabled) return;
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

function clearStoredEntries() {
  localStorage.removeItem(STORAGE_KEY);
}

function sanitizeBase32(value) {
  return value.toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}

function base32ToBytes(base32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();

  let bits = "";
  for (const char of clean) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) {
      throw new Error("Secret contains invalid Base32 characters");
    }
    bits += idx.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  return new Uint8Array(bytes);
}

function toUint8Array(counter) {
  const bytes = new Uint8Array(8);
  let temp = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

function bytesToLatin1(uint8) {
  let out = "";
  for (const byte of uint8) out += String.fromCharCode(byte);
  return out;
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

async function generateTotp(secret, digits, period) {
  const now = Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / period);
  const secretBytes = base32ToBytes(secret);
  const digest = await hmacSha1(secretBytes, toUint8Array(counter));

  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | (digest[offset + 1] << 16)
    | (digest[offset + 2] << 8)
    | digest[offset + 3];
  const otp = (binary % (10 ** digits)).toString().padStart(digits, "0");

  return otp;
}

function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function parseOtpAuthUri(uri) {
  if (!uri.startsWith("otpauth://")) {
    throw new Error("URI must start with otpauth://");
  }

  const parsed = new URL(uri);
  if (parsed.hostname !== "totp") {
    throw new Error("Only TOTP URIs are supported");
  }

  const label = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  const secret = parsed.searchParams.get("secret") || "";
  const digits = Number(parsed.searchParams.get("digits") || 6);
  const period = Number(parsed.searchParams.get("period") || 30);

  if (!secret) {
    throw new Error("URI is missing secret");
  }

  return {
    label: label || "Imported Account",
    secret,
    digits: digits === 8 ? 8 : 6,
    period: Number.isFinite(period) && period > 0 ? period : 30,
  };
}

function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}

function sortedEntries() {
  return [...entries].sort((a, b) => a.label.localeCompare(b.label, undefined, { sensitivity: "base" }));
}

function normalizedLabel(value) {
  return (value || "").trim().toLowerCase();
}

function getVisibleEntries() {
  const q = normalizedLabel(searchInput.value);
  const sorted = sortedEntries();
  if (!q) return sorted;
  return sorted.filter((entry) => normalizedLabel(entry.label).includes(q));
}

function getIssuerInitials(label) {
  const clean = (label || "").trim();
  if (!clean) return "OT";

  const issuer = clean.includes(":") ? clean.split(":")[0] : clean.split("-")[0];
  const parts = issuer.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return clean.slice(0, 2).toUpperCase();
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return `${parts[0][0] || ""}${parts[1][0] || ""}`.toUpperCase();
}

function generateEntryId() {
  return `entry_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function ensureEntryIds() {
  let changed = false;
  entries = entries.map((entry) => {
    if (entry.id) return entry;
    changed = true;
    return { ...entry, id: generateEntryId() };
  });
  if (changed) saveEntries();
}

function showEmptyState() {
  entriesRoot.innerHTML = "";
  const empty = document.createElement("p");
  empty.style.margin = "0.2rem 0 0";
  empty.style.color = "var(--muted)";
  empty.textContent = "No entries yet. Add one above to start generating codes.";
  entriesRoot.appendChild(empty);
}

function setImportStatus(message, tone = "") {
  importStatus.textContent = message;
  importStatus.classList.remove("error", "success");
  if (tone) importStatus.classList.add(tone);
}

function normalizeUriCandidate(raw) {
  return (raw || "").trim().replace(/[)\],.;]+$/, "");
}

function findOtpAuthUri(rawText) {
  const text = normalizeUriCandidate(rawText);
  if (!text) return "";
  if (text.startsWith("otpauth://")) return text;

  const directMatch = text.match(/otpauth:\/\/[^\s"']+/i);
  if (directMatch) return normalizeUriCandidate(directMatch[0]);

  try {
    const decoded = decodeURIComponent(text);
    if (decoded.startsWith("otpauth://")) return normalizeUriCandidate(decoded);
    const decodedMatch = decoded.match(/otpauth:\/\/[^\s"']+/i);
    if (decodedMatch) return normalizeUriCandidate(decodedMatch[0]);
  } catch {
    return "";
  }

  return "";
}

function hasDuplicateEntry(secret, digits, period) {
  const cleanSecret = sanitizeBase32(secret);
  return entries.some((entry) => {
    return entry.secret === cleanSecret && entry.digits === digits && entry.period === period;
  });
}

function importOtpAuthUri(otpUri, sourceLabel = "Import") {
  const parsed = parseOtpAuthUri(otpUri);
  if (hasDuplicateEntry(parsed.secret, parsed.digits, parsed.period)) {
    setImportStatus(`${sourceLabel}: this account already exists`, "error");
    return;
  }

  addEntry({
    label: parsed.label,
    secret: parsed.secret,
    digits: parsed.digits,
    period: parsed.period,
  });
  renderEntries();
  tick();
  setImportStatus(`${sourceLabel}: account imported`, "success");
}

async function decodeQrFromBlob(blob) {
  if (typeof jsQR !== "function") {
    throw new Error("QR library failed to load");
  }

  const bitmap = await createImageBitmap(blob);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const code = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth",
  });

  if (!code || !code.data) {
    throw new Error("Could not detect a QR code in that image");
  }

  return code.data;
}

async function importFromQrBlob(blob, sourceLabel) {
  const qrText = await decodeQrFromBlob(blob);
  const otpUri = findOtpAuthUri(qrText);
  if (!otpUri) {
    throw new Error("QR does not contain an otpauth:// URI");
  }
  importOtpAuthUri(otpUri, sourceLabel);
}

function showNoMatchState() {
  entriesRoot.innerHTML = "";
  const empty = document.createElement("p");
  empty.style.margin = "0.2rem 0 0";
  empty.style.color = "var(--muted)";
  empty.textContent = "No matching entries.";
  entriesRoot.appendChild(empty);
}

function createEntryNode(entry) {
  const node = template.content.firstElementChild.cloneNode(true);
  const avatar = node.querySelector(".entry-avatar");
  const label = node.querySelector(".entry-label");
  const meta = node.querySelector(".entry-meta");
  const copyBtn = node.querySelector(".copy");
  const removeBtn = node.querySelector(".remove");

  avatar.textContent = getIssuerInitials(entry.label);
  label.textContent = entry.label;
  meta.textContent = `${entry.digits} digits • ${entry.period}s`;

  copyBtn.onclick = async () => {
    const latestCode = node.dataset.otp;
    if (!latestCode) return;

    try {
      await navigator.clipboard.writeText(latestCode);
      copyBtn.textContent = "Copied";
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1000);
    } catch {
      copyBtn.textContent = "Failed";
      setTimeout(() => {
        copyBtn.textContent = "Copy";
      }, 1000);
    }
  };

  removeBtn.onclick = () => {
    entries = entries.filter((item) => item.id !== entry.id);
    saveEntries();
    renderEntries();
    tick();
  };

  return node;
}

function renderEntries() {
  if (entries.length === 0) {
    entryNodes.clear();
    showEmptyState();
    return;
  }

  const visibleEntries = getVisibleEntries();
  if (visibleEntries.length === 0) {
    showNoMatchState();
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
    fragment.appendChild(node);
  }

  for (const [id] of entryNodes) {
    if (!activeIds.has(id)) {
      entryNodes.delete(id);
    }
  }

  entriesRoot.appendChild(fragment);
}

async function updateEntryNode(entry, now) {
  const node = entryNodes.get(entry.id);
  if (!node) return;

  const code = node.querySelector(".entry-code");
  const copyBtn = node.querySelector(".copy");
  const seconds = node.querySelector(".entry-seconds");
  const bar = node.querySelector(".entry-bar");

  const remaining = entry.period - (now % entry.period);
  const ratio = remaining / entry.period;

  seconds.textContent = `${remaining}s left`;
  bar.style.transform = `scaleX(${ratio})`;
  node.classList.toggle("urgent", remaining <= 10);

  try {
    const otp = await generateTotp(entry.secret, entry.digits, entry.period);
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
  let period = 30;
  const visibleEntries = getVisibleEntries();
  if (visibleEntries.length > 0) {
    period = Math.min(...visibleEntries.map((entry) => entry.period));
  }

  const remaining = period - (now % period);
  const ratio = remaining / period;

  timerValue.textContent = `${remaining}s`;
  timerBar.style.transform = `scaleX(${ratio})`;
}

async function tick() {
  const now = Math.floor(Date.now() / 1000);
  updateTimer(now);
  await updateAllEntries(now);
}

function addEntry({ label, secret, digits, period }) {
  const cleanedSecret = sanitizeBase32(secret);
  const finalLabel = label.trim() || createFallbackLabel(cleanedSecret);
  const normalizedDigits = digits === 8 ? 8 : 6;
  const normalizedPeriod = Math.max(15, Math.min(120, Number(period) || 30));

  if (hasDuplicateEntry(cleanedSecret, normalizedDigits, normalizedPeriod)) {
    throw new Error("This account already exists");
  }

  entries.push({
    id: generateEntryId(),
    label: finalLabel,
    secret: cleanedSecret,
    digits: normalizedDigits,
    period: normalizedPeriod,
  });
  saveEntries();
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  try {
    addEntry({
      label: labelInput.value,
      secret: secretInput.value,
      digits: Number(digitsInput.value),
      period: Number(periodInput.value),
    });
    form.reset();
    persistToggle.checked = persistEnabled;
    digitsInput.value = "6";
    periodInput.value = "30";
    renderEntries();
    tick();
  } catch (error) {
    alert(error.message || "Could not add entry");
  }
});

parseUriBtn.addEventListener("click", () => {
  try {
    const otpUri = findOtpAuthUri(uriInput.value);
    if (!otpUri) {
      throw new Error("No otpauth:// URI found");
    }
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
    const blob = await response.blob();
    await importFromQrBlob(blob, "QR URL");
  } catch (error) {
    setImportStatus(
      error.message || "Failed to import from URL (remote image may block cross-origin access)",
      "error"
    );
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
        const blob = await item.getType(imageType);
        await importFromQrBlob(blob, "Clipboard image");
        return;
      }
    }

    const text = await navigator.clipboard.readText();
    const otpUri = findOtpAuthUri(text);
    if (!otpUri) {
      throw new Error("Clipboard has no otpauth:// URI or QR image");
    }
    importOtpAuthUri(otpUri, "Clipboard");
  } catch (error) {
    setImportStatus(error.message || "Failed to import from clipboard", "error");
  }
});

clearAllBtn.addEventListener("click", () => {
  entries = [];
  setImportStatus("", "");
  if (persistEnabled) {
    saveEntries();
  } else {
    clearStoredEntries();
  }
  renderEntries();
  tick();
});

searchInput.addEventListener("input", () => {
  renderEntries();
  tick();
});

persistToggle.addEventListener("change", () => {
  if (persistToggle.checked && !persistEnabled && !hasSeenPersistWarning()) {
    if (typeof privacyDialog.showModal === "function") {
      privacyDialog.showModal();
      return;
    }
    const accepted = window.confirm(
      "Enabling device storage saves 2FA secrets in localStorage. Continue only on a trusted personal device."
    );
    if (!accepted) {
      persistToggle.checked = false;
      return;
    }
    markPersistWarningSeen();
  }

  persistEnabled = persistToggle.checked;
  localStorage.setItem(PERSIST_KEY, String(persistEnabled));

  if (persistEnabled) {
    saveEntries();
  } else {
    clearStoredEntries();
  }
});

privacyDialog.addEventListener("close", () => {
  if (!privacyDialog.returnValue) return;

  if (privacyDialog.returnValue === "accept") {
    markPersistWarningSeen();
    persistEnabled = true;
    persistToggle.checked = true;
    localStorage.setItem(PERSIST_KEY, "true");
    saveEntries();
  } else {
    persistToggle.checked = false;
  }
});

setInterval(tick, 1000);

renderEntries();
tick();

persistToggle.checked = persistEnabled;

window.otpDebug = {
  base32ToBytes,
  bytesToLatin1,
};
