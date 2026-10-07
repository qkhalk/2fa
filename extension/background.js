// Clears the in-memory session unlock cache so an idle browser locks even
// when the popup is closed. chrome.storage.session is memory-only and is
// wiped on browser exit/update; idle/alarms cover the "browser left open" case.
const SESSION_UNLOCK_KEY = "otp_extension_session_unlock_v1";
const AUTOLOCK_ALARM = "otp-extension-autolock";

async function clearSessionUnlock() {
  await chrome.storage.session.remove(SESSION_UNLOCK_KEY);
  await chrome.alarms.clear(AUTOLOCK_ALARM);
}

async function scheduleFromSettings() {
  const { otp_extension_settings_v1: settings } = await chrome.storage.local.get("otp_extension_settings_v1");
  const minutes = Number(settings?.autoLockMinutes ?? 15);
  await chrome.alarms.clear(AUTOLOCK_ALARM);
  if (!settings?.encrypt || minutes <= 0) return;
  chrome.alarms.create(AUTOLOCK_ALARM, { delayInMinutes: minutes });
}

chrome.runtime.onInstalled.addListener(() => {
  scheduleFromSettings();
});

chrome.runtime.onStartup.addListener(() => {
  scheduleFromSettings();
});

chrome.idle.onStateChanged.addListener((state) => {
  // Any non-active state (idle/locked) drops the session unlock material.
  if (state !== "active") clearSessionUnlock();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) clearSessionUnlock();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "session") return;
  if (changes[SESSION_UNLOCK_KEY] && !changes[SESSION_UNLOCK_KEY].newValue) {
    chrome.alarms.clear(AUTOLOCK_ALARM);
    return;
  }
  if (changes[SESSION_UNLOCK_KEY]?.newValue) scheduleFromSettings();
});
