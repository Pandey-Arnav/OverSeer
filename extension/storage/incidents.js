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

  async function getIncidents() {
    const result = await chrome.storage.local.get(STORAGE_KEYS.INCIDENTS);
    return Array.isArray(result[STORAGE_KEYS.INCIDENTS]) ? result[STORAGE_KEYS.INCIDENTS] : [];
  }

  /** Prepends a new incident (most-recent-first) and enforces the storage cap. */
  async function addIncident(incident) {
    const incidents = await getIncidents();
    incidents.unshift(incident);
    if (incidents.length > MAX_STORED_INCIDENTS) incidents.length = MAX_STORED_INCIDENTS;
    await chrome.storage.local.set({ [STORAGE_KEYS.INCIDENTS]: incidents });
    return incident;
  }

  async function updateIncident(id, patch) {
    const incidents = await getIncidents();
    const idx = incidents.findIndex((i) => i.id === id);
    if (idx === -1) return null;
    incidents[idx] = { ...incidents[idx], ...patch };
    await chrome.storage.local.set({ [STORAGE_KEYS.INCIDENTS]: incidents });
    return incidents[idx];
  }

  async function clearIncidents() {
    await chrome.storage.local.set({ [STORAGE_KEYS.INCIDENTS]: [] });
  }

  async function getSettings() {
    const result = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
    return { ...DEFAULT_SETTINGS, ...(result[STORAGE_KEYS.SETTINGS] || {}) };
  }

  async function updateSettings(patch) {
    const current = await getSettings();
    const next = { ...current, ...patch };
    await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: next });
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
