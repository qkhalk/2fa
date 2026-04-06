const STORAGE_KEY = "otp_extension_entries_v1";

const form = document.getElementById("entry-form");
const labelInput = document.getElementById("label");
const secretInput = document.getElementById("secret");
const digitsInput = document.getElementById("digits");
const periodInput = document.getElementById("period");
const searchInput = document.getElementById("search");
const pasteUriBtn = document.getElementById("paste-uri");
const statusNode = document.getElementById("status");
const entriesRoot = document.getElementById("entries");

let entries = [];

initialize();

async function initialize() {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  entries = Array.isArray(stored[STORAGE_KEY]) ? stored[STORAGE_KEY] : [];
  render();
}

function setStatus(message) {
  statusNode.textContent = message;
}

function sanitizeBase32(value) {
  return value.toUpperCase().replace(/\s+/g, "").replace(/=+$/g, "");
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
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function hmacSha1(keyBytes, msgBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, msgBytes);
  return new Uint8Array(sig);
}

async function generateTotp(entry) {
  const now = Math.floor(Date.now() / 1000);
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

async function saveEntries() {
  await chrome.storage.local.set({ [STORAGE_KEY]: entries });
}

function parseOtpAuthUri(uri) {
  const parsed = new URL(uri);
  return {
    label: decodeURIComponent(parsed.pathname.replace(/^\//, "")) || "Imported",
    secret: sanitizeBase32(parsed.searchParams.get("secret") || ""),
    digits: Number(parsed.searchParams.get("digits") || 6) === 8 ? 8 : 6,
    period: Number(parsed.searchParams.get("period") || 30),
  };
}

function filteredEntries() {
  const q = (searchInput.value || "").trim().toLowerCase();
  return [...entries]
    .sort((a, b) => a.label.localeCompare(b.label))
    .filter((entry) => entry.label.toLowerCase().includes(q));
}

async function render() {
  const visible = filteredEntries();
  entriesRoot.innerHTML = "";
  if (visible.length === 0) {
    entriesRoot.textContent = "No entries yet.";
    return;
  }

  for (const entry of visible) {
    const card = document.createElement("article");
    card.className = "entry";
    const code = await generateTotp(entry);
    card.innerHTML = `
      <div class="entry-head">
        <div>
          <h2>${entry.label}</h2>
          <p class="meta">${entry.digits} digits • ${entry.period}s</p>
        </div>
      </div>
      <p class="code">${formatCode(code)}</p>
      <div class="entry-actions">
        <button data-copy="${code}">Copy</button>
        <button data-remove="${entry.id}">Remove</button>
      </div>
    `;
    card.querySelector("[data-copy]").addEventListener("click", async () => {
      await navigator.clipboard.writeText(code);
      setStatus("Copied code");
    });
    card.querySelector("[data-remove]").addEventListener("click", async () => {
      entries = entries.filter((item) => item.id !== entry.id);
      await saveEntries();
      render();
    });
    entriesRoot.appendChild(card);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  entries.push({
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
    label: labelInput.value.trim() || "Manual Entry",
    secret: sanitizeBase32(secretInput.value),
    digits: Number(digitsInput.value) === 8 ? 8 : 6,
    period: Math.max(15, Math.min(120, Number(periodInput.value) || 30)),
  });
  await saveEntries();
  form.reset();
  digitsInput.value = "6";
  periodInput.value = "30";
  setStatus("Entry added");
  render();
});

pasteUriBtn.addEventListener("click", async () => {
  try {
    const text = await navigator.clipboard.readText();
    const match = text.match(/otpauth:\/\/[^\s"']+/i);
    if (!match) throw new Error("Clipboard does not contain an otpauth URI");
    entries.push({ id: `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`, ...parseOtpAuthUri(match[0]) });
    await saveEntries();
    setStatus("Imported URI from clipboard");
    render();
  } catch (error) {
    setStatus(error.message || "Could not import URI");
  }
});

searchInput.addEventListener("input", () => {
  render();
});

setInterval(render, 1000);
