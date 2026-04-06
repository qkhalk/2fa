// extension/popup.js
var BASE32_REGEX = /^[A-Z2-7]+$/;
var OTP_URI_REGEX = /otpauth:\/\/[^\s"'<>]+/gi;
var MIN_PERIOD = 15;
var MAX_PERIOD = 120;
var OtpVaultError = class extends Error {
  constructor(message, { code = "OTP_VAULT_ERROR", cause } = {}) {
    super(message, cause ? { cause } : void 0);
    this.name = "OtpVaultError";
    this.code = code;
  }
};
function reportError(context, error) {
  console.error(`[OTP Vault] ${context}`, error);
}
function toUserMessage(error, fallback = "Something went wrong") {
  if (error instanceof Error && error.message) return error.message;
  return fallback;
}
function sanitizeBase32(value) {
  return (value || "").toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
}
function normalizeTags(value) {
  const raw = Array.isArray(value) ? value : String(value || "").split(",");
  return [...new Set(
    raw.map((tag) => String(tag).trim().replace(/\s+/g, " ")).filter(Boolean).map((tag) => tag.slice(0, 24))
  )];
}
function generateEntryId() {
  return `entry_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}
function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
function ensureBase32Secret(secret) {
  const clean = sanitizeBase32(secret);
  if (!clean) {
    throw new OtpVaultError("Secret is required", { code: "SECRET_REQUIRED" });
  }
  if (!BASE32_REGEX.test(clean)) {
    throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
  }
  if (base32ToBytes(clean).length === 0) {
    throw new OtpVaultError("Secret is too short to decode", { code: "SECRET_TOO_SHORT" });
  }
  return clean;
}
function ensureDigits(digits) {
  const value = Number(digits);
  if (value !== 6 && value !== 8) {
    throw new OtpVaultError("Only 6-digit and 8-digit OTP codes are supported", { code: "DIGITS_UNSUPPORTED" });
  }
  return value;
}
function ensurePeriod(period) {
  const value = Number(period);
  if (!Number.isInteger(value) || value < MIN_PERIOD || value > MAX_PERIOD) {
    throw new OtpVaultError(`Period must be an integer between ${MIN_PERIOD} and ${MAX_PERIOD} seconds`, {
      code: "PERIOD_INVALID"
    });
  }
  return value;
}
function createFallbackLabel(secret) {
  const clean = sanitizeBase32(secret);
  if (clean.length <= 8) return `Secret ${clean || "entry"}`;
  return `Secret ${clean.slice(0, 4)}...${clean.slice(-4)}`;
}
function normalizeLabel(label, secret) {
  const clean = (label || "").trim();
  return clean || createFallbackLabel(secret);
}
function normalizeEntry(entry) {
  const secret = ensureBase32Secret(entry.secret || "");
  return {
    id: entry.id || generateEntryId(),
    label: normalizeLabel(entry.label, secret),
    secret,
    digits: ensureDigits(entry.digits ?? 6),
    period: ensurePeriod(entry.period ?? 30),
    pinned: Boolean(entry.pinned),
    tags: normalizeTags(entry.tags),
    createdAt: typeof entry.createdAt === "number" ? entry.createdAt : Date.now()
  };
}
function normalizeEntries(entries2) {
  if (!Array.isArray(entries2)) return [];
  return entries2.flatMap((entry) => {
    try {
      return [normalizeEntry(entry)];
    } catch {
      return [];
    }
  });
}
function parseLabelParts(label) {
  const clean = (label || "").trim();
  if (!clean) return { issuer: "Unknown", account: "No account label" };
  if (clean.includes(":")) {
    const [issuer, ...rest] = clean.split(":");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(":").trim() || "No account label"
    };
  }
  if (clean.includes(" - ")) {
    const [issuer, ...rest] = clean.split(" - ");
    return {
      issuer: issuer.trim() || clean,
      account: rest.join(" - ").trim() || "No account label"
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
function normalizeOtpUriCandidate(value) {
  return safeDecode((value || "").trim()).replace(/[)\],.;]+$/, "");
}
function parseOtpAuthUri(uri) {
  let parsed;
  try {
    parsed = new URL(uri);
  } catch (error) {
    throw new OtpVaultError("OTP URI is not a valid URL", { code: "URI_INVALID", cause: error });
  }
  if (parsed.protocol !== "otpauth:") {
    throw new OtpVaultError("URI must start with otpauth://", { code: "URI_PROTOCOL" });
  }
  if (parsed.hostname.toLowerCase() !== "totp") {
    throw new OtpVaultError("Only TOTP URIs are supported", { code: "URI_TYPE" });
  }
  const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
  if (algorithm !== "SHA1") {
    throw new OtpVaultError("Only SHA1 TOTP URIs are supported", { code: "URI_ALGORITHM" });
  }
  const issuerParam = safeDecode(parsed.searchParams.get("issuer") || "").trim();
  const rawLabel = safeDecode(parsed.pathname.replace(/^\/+/, "")).trim();
  const labelParts = parseLabelParts(rawLabel);
  if (issuerParam && rawLabel && labelParts.issuer !== "Unknown" && labelParts.account !== "No account label") {
    if (labelParts.issuer.toLowerCase() !== issuerParam.toLowerCase()) {
      throw new OtpVaultError("OTP URI issuer does not match the label", { code: "URI_ISSUER_MISMATCH" });
    }
  }
  const label = rawLabel ? rawLabel.includes(":") || !issuerParam ? rawLabel : `${issuerParam}:${rawLabel}` : issuerParam ? `${issuerParam}:Imported Account` : "Imported Account";
  return normalizeEntry({
    label,
    secret: parsed.searchParams.get("secret") || "",
    digits: parsed.searchParams.has("digits") ? Number(parsed.searchParams.get("digits")) : 6,
    period: parsed.searchParams.has("period") ? Number(parsed.searchParams.get("period")) : 30
  });
}
function extractOtpAuthUri(rawText) {
  return extractOtpAuthUris(rawText)[0] || "";
}
function extractOtpAuthUris(rawText) {
  const candidates = /* @__PURE__ */ new Set();
  const raw = (rawText || "").trim();
  if (!raw) return [];
  candidates.add(normalizeOtpUriCandidate(raw));
  for (const match of raw.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const decoded = safeDecode(raw);
  candidates.add(normalizeOtpUriCandidate(decoded));
  for (const match of decoded.matchAll(OTP_URI_REGEX)) {
    candidates.add(normalizeOtpUriCandidate(match[0]));
  }
  const valid = [];
  for (const candidate of candidates) {
    if (!candidate.startsWith("otpauth://")) continue;
    try {
      parseOtpAuthUri(candidate);
      valid.push(candidate);
    } catch {
      continue;
    }
  }
  return valid;
}
function hasDuplicateEntry(entries2, candidate) {
  return entries2.some((entry) => entry.secret === candidate.secret && entry.digits === candidate.digits && entry.period === candidate.period);
}
function base32ToBytes(base32) {
  const clean = sanitizeBase32(base32);
  if (!clean) return new Uint8Array();
  let bits = "";
  for (const char of clean) {
    const idx = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char);
    if (idx === -1) {
      throw new OtpVaultError("Secret contains invalid Base32 characters", { code: "SECRET_INVALID" });
    }
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return new Uint8Array(bytes);
}
function toCounterBytes(counter) {
  const bytes = new Uint8Array(8);
  let value = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}
async function hmacSha1(keyBytes, messageBytes, cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle) {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  const key = await cryptoApi.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const signature = await cryptoApi.subtle.sign("HMAC", key, messageBytes);
  return new Uint8Array(signature);
}
async function generateTotp(secret, digits, period, now, cryptoApi = globalThis.crypto) {
  const normalizedSecret = ensureBase32Secret(secret);
  const normalizedDigits = ensureDigits(digits);
  const normalizedPeriod = ensurePeriod(period);
  const counter = Math.floor(now / normalizedPeriod);
  const digest = await hmacSha1(base32ToBytes(normalizedSecret), toCounterBytes(counter), cryptoApi);
  const offset = digest[digest.length - 1] & 15;
  const binary = (digest[offset] & 127) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3];
  return (binary % 10 ** normalizedDigits).toString().padStart(normalizedDigits, "0");
}
function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
var encoder = new TextEncoder();
var decoder = new TextDecoder();
function toBase64(uint8) {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(uint8).toString("base64");
  }
  return btoa(String.fromCharCode(...uint8));
}
function fromBase64(base64) {
  try {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(base64, "base64"));
    }
    return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  } catch (error) {
    throw new OtpVaultError("Encrypted data is unreadable", { code: "VAULT_BASE64", cause: error });
  }
}
function requireCrypto(cryptoApi = globalThis.crypto) {
  if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== "function") {
    throw new OtpVaultError("Browser crypto support is unavailable", { code: "CRYPTO_UNAVAILABLE" });
  }
  return cryptoApi;
}
function normalizePassphrase(passphrase) {
  const clean = (passphrase || "").trim();
  if (clean.length < 8) {
    throw new OtpVaultError("Use a passphrase with at least 8 characters", { code: "PASSPHRASE_TOO_SHORT" });
  }
  return clean;
}
async function deriveVaultKey(passphrase, salt, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const material = await safeCrypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return safeCrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 15e4, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptEntries(entries2, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const salt = safeCrypto.getRandomValues(new Uint8Array(16));
  const iv = safeCrypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(normalizedPassphrase, salt, safeCrypto);
  const payload = encoder.encode(JSON.stringify(entries2));
  const encrypted = await safeCrypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    data: toBase64(new Uint8Array(encrypted))
  };
}
function validateEncryptedPayload(payload) {
  if (!payload || typeof payload !== "object") {
    throw new OtpVaultError("Encrypted data is missing or invalid", { code: "VAULT_INVALID" });
  }
  if (typeof payload.salt !== "string" || typeof payload.iv !== "string" || typeof payload.data !== "string") {
    throw new OtpVaultError("Encrypted data is missing required fields", { code: "VAULT_FIELDS" });
  }
  return payload;
}
async function decryptVaultEntries(payload, passphrase, cryptoApi = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoApi);
  const normalizedPassphrase = normalizePassphrase(passphrase);
  const normalizedPayload = validateEncryptedPayload(payload);
  try {
    const key = await deriveVaultKey(normalizedPassphrase, fromBase64(normalizedPayload.salt), safeCrypto);
    const decrypted = await safeCrypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(normalizedPayload.iv) },
      key,
      fromBase64(normalizedPayload.data)
    );
    const parsed = JSON.parse(decoder.decode(decrypted));
    return normalizeEntries(parsed);
  } catch (error) {
    if (error instanceof OtpVaultError) throw error;
    throw new OtpVaultError("Incorrect passphrase or unreadable encrypted data", {
      code: "VAULT_DECRYPT_FAILED",
      cause: error
    });
  }
}
var STORAGE_KEY = "otp_extension_entries_v2";
var ENCRYPTED_KEY = "otp_extension_encrypted_v1";
var SETTINGS_KEY = "otp_extension_settings_v1";
var UI_KEY = "otp_extension_ui_v1";
var form = document.getElementById("entry-form");
var labelInput = document.getElementById("label");
var secretInput = document.getElementById("secret");
var tagsInput = document.getElementById("tags");
var digitsInput = document.getElementById("digits");
var periodInput = document.getElementById("period");
var qrFileInput = document.getElementById("qr-file");
var searchInput = document.getElementById("search");
var sortSelect = document.getElementById("sort-select");
var pasteUriBtn = document.getElementById("paste-uri");
var toggleFormBtn = document.getElementById("toggle-form");
var lockBtn = document.getElementById("lock-btn");
var statusNode = document.getElementById("status");
var entriesRoot = document.getElementById("entries");
var globalSeconds = document.getElementById("global-seconds");
var globalBar = document.getElementById("global-bar");
var template = document.getElementById("entry-template");
var unlockPanel = document.getElementById("unlock-panel");
var unlockPassphraseInput = document.getElementById("unlock-passphrase");
var unlockBtn = document.getElementById("unlock-btn");
var unlockStatus = document.getElementById("unlock-status");
var encryptToggle = document.getElementById("encrypt-toggle");
var passphraseFields = document.getElementById("passphrase-fields");
var passphraseInput = document.getElementById("passphrase");
var passphraseConfirmInput = document.getElementById("passphrase-confirm");
var saveSecurityBtn = document.getElementById("save-security");
var copyHistoryRoot = document.getElementById("copy-history");
var entries = [];
var entryNodes = /* @__PURE__ */ new Map();
var collapsed = false;
var settings = { encrypt: false, sortBy: "alpha" };
var currentPassphrase = "";
var copyHistory = [];
initialize();
async function initialize() {
  const stored = await chrome.storage.local.get([STORAGE_KEY, ENCRYPTED_KEY, SETTINGS_KEY, UI_KEY]);
  settings = { encrypt: false, ...stored[SETTINGS_KEY] || {} };
  collapsed = Boolean(stored[UI_KEY]?.collapsed);
  encryptToggle.checked = settings.encrypt;
  sortSelect.value = settings.sortBy || "alpha";
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
  renderCopyHistory();
  tick();
  setInterval(tick, 1e3);
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
  return [...entries].sort((a, b) => {
    if (settings.sortBy === "recent") return b.createdAt - a.createdAt;
    if (settings.sortBy === "period") return a.period - b.period || a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
    return a.label.localeCompare(b.label, void 0, { sensitivity: "base" });
  }).filter((entry) => [entry.label, ...entry.tags || []].join(" ").toLowerCase().includes(query));
}
function refreshEntryNode(node, entry) {
  const parts = parseLabelParts(entry.label);
  node.querySelector(".avatar").textContent = getIssuerInitials(entry.label);
  node.querySelector(".issuer").textContent = parts.issuer;
  node.querySelector(".account").textContent = parts.account;
  node.querySelector(".meta").textContent = `${entry.digits} digits \u2022 ${entry.period}s`;
  const tagRoot = node.querySelector(".tags");
  if (tagRoot) {
    tagRoot.innerHTML = "";
    for (const tag of entry.tags || []) {
      const chip = document.createElement("span");
      chip.className = "tag";
      chip.textContent = tag;
      tagRoot.appendChild(chip);
    }
  }
}
function addCopyHistory(label, code) {
  copyHistory = [{
    label,
    code: formatCode(code),
    at: (/* @__PURE__ */ new Date()).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }, ...copyHistory.filter((item) => item.label !== label)].slice(0, 5);
  renderCopyHistory();
}
function renderCopyHistory() {
  if (!copyHistoryRoot) return;
  if (copyHistory.length === 0) {
    copyHistoryRoot.innerHTML = '<div class="empty-state">Copied OTPs will appear here.</div>';
    return;
  }
  copyHistoryRoot.innerHTML = copyHistory.map((item) => `<div class="history-item"><strong>${item.label}</strong><span>${item.code} \u2022 ${item.at}</span></div>`).join("");
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
    const remaining = entry.period - now % entry.period;
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
  const remaining = period - now % period;
  globalSeconds.textContent = `${remaining}s`;
  globalBar.style.transform = `scaleX(${remaining / period})`;
}
async function tick() {
  const now = Math.floor(Date.now() / 1e3);
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
        tags: normalizeTags(tagsInput.value),
        digits: Number(digitsInput.value),
        period: Number(periodInput.value)
      });
      form.reset();
      tagsInput.value = "";
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
