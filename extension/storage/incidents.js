/**
 * Sentinel — incident storage.
 *
 * Thin wrapper around chrome.storage.local so every other file (popup,
 * dashboard, background) reads/writes incidents the same way. Enforces
 * the MAX_STORED_INCIDENTS cap so a noisy page can't grow storage
 * unbounded.
 */
(function (global) {
  const { STORAGE_KEYS, MAX_STORED_INCIDENTS, DEFAULT_SETTINGS } = global.Sentinel;
  const hasChromeStorage = typeof chrome !== "undefined" && chrome.storage?.local;

  async function storageGet(key) {
    if (hasChromeStorage) return chrome.storage.local.get(key);
    try {
      const value = JSON.parse(global.localStorage.getItem(key));
      return { [key]: value };
    } catch {
      return {};
    }
  }

  async function storageSet(values) {
    if (hasChromeStorage) return chrome.storage.local.set(values);
    for (const [key, value] of Object.entries(values)) {
      global.localStorage.setItem(key, JSON.stringify(value));
    }
  }

  async function getIncidents() {
    const result = await storageGet(STORAGE_KEYS.INCIDENTS);
    return Array.isArray(result[STORAGE_KEYS.INCIDENTS]) ? result[STORAGE_KEYS.INCIDENTS] : [];
  }

  /** Prepends a new incident (most-recent-first) and enforces the storage cap. */
  async function addIncident(incident) {
    const incidents = await getIncidents();
    incidents.unshift(incident);
    if (incidents.length > MAX_STORED_INCIDENTS) incidents.length = MAX_STORED_INCIDENTS;
    await storageSet({ [STORAGE_KEYS.INCIDENTS]: incidents });
    return incident;
  }

  async function updateIncident(id, patch) {
    const incidents = await getIncidents();
    const idx = incidents.findIndex((i) => i.id === id);
    if (idx === -1) return null;
    incidents[idx] = { ...incidents[idx], ...patch };
    await storageSet({ [STORAGE_KEYS.INCIDENTS]: incidents });
    return incidents[idx];
  }

  async function clearIncidents() {
    await storageSet({ [STORAGE_KEYS.INCIDENTS]: [] });
  }

  async function getSettings() {
    const result = await storageGet(STORAGE_KEYS.SETTINGS);
    return { ...DEFAULT_SETTINGS, ...(result[STORAGE_KEYS.SETTINGS] || {}) };
  }

  async function updateSettings(patch) {
    const current = await getSettings();
    const next = { ...current, ...patch };
    await storageSet({ [STORAGE_KEYS.SETTINGS]: next });
    return next;
  }

  global.Sentinel = global.Sentinel || {};
  Object.assign(global.Sentinel, {
    getIncidents,
    addIncident,
    updateIncident,
    clearIncidents,
    getSettings,
    updateSettings,
  });
})(typeof self !== "undefined" ? self : globalThis);
