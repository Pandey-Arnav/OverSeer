/**
 * Sentinel Agent — local JSON-file persistence.
 *
 * Replaces chrome.storage.local from the browser-extension prototype —
 * there's no browser here, so incidents/settings live in a plain JSON
 * file under ~/.sentinel/. A simple in-process write queue (rather than
 * a real DB) avoids concurrent read-modify-write races between the
 * network monitor, USB monitor, and API routes, while keeping
 * dependencies minimal.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { DEFAULT_SETTINGS, MAX_STORED_INCIDENTS } from "../shared/constants.ts";
import type { Incident, Settings } from "../shared/types.ts";

const DATA_DIR = process.env["SENTINEL_DATA_DIR"] || path.join(os.homedir(), ".sentinel");
const INCIDENTS_FILE = path.join(DATA_DIR, "incidents.json");
const SETTINGS_FILE = path.join(DATA_DIR, "settings.json");

let ready = false;
async function ensureDataDir(): Promise<void> {
  if (ready) return;
  await mkdir(DATA_DIR, { recursive: true });
  ready = true;
}

async function readJson<T>(file: string, fallback: T): Promise<T> {
  await ensureDataDir();
  try {
    const raw = await readFile(file, "utf8");
    return JSON.parse(raw) as T;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return fallback;
    console.error(`[Sentinel] failed to read ${file}, using fallback:`, (err as Error).message);
    return fallback;
  }
}

// Chains writes to the same file so concurrent callers can't interleave
// a read-modify-write and clobber each other — good enough for a
// single-process daemon with a handful of writers, without adding a real
// database dependency.
const writeQueues = new Map<string, Promise<void>>();

async function writeJsonQueued(file: string, data: unknown): Promise<void> {
  await ensureDataDir();
  const previous = writeQueues.get(file) ?? Promise.resolve();
  const next = previous
    .catch(() => {})
    .then(() => writeFile(file, JSON.stringify(data, null, 2), "utf8"));
  writeQueues.set(file, next);
  return next;
}

export async function getIncidents(): Promise<Incident[]> {
  return readJson<Incident[]>(INCIDENTS_FILE, []);
}

export async function addIncident(incident: Incident): Promise<Incident> {
  const incidents = await getIncidents();
  incidents.unshift(incident);
  if (incidents.length > MAX_STORED_INCIDENTS) incidents.length = MAX_STORED_INCIDENTS;
  await writeJsonQueued(INCIDENTS_FILE, incidents);
  return incident;
}

export async function updateIncident(id: string, patch: Partial<Incident>): Promise<Incident | null> {
  const incidents = await getIncidents();
  const idx = incidents.findIndex((i) => i.id === id);
  if (idx === -1) return null;
  const existing = incidents[idx]!;
  const updated = { ...existing, ...patch };
  incidents[idx] = updated;
  await writeJsonQueued(INCIDENTS_FILE, incidents);
  return updated;
}

export async function clearIncidents(): Promise<void> {
  await writeJsonQueued(INCIDENTS_FILE, []);
}

export async function getSettings(): Promise<Settings> {
  const stored = await readJson<Partial<Settings>>(SETTINGS_FILE, {});
  return { ...DEFAULT_SETTINGS, ...stored };
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await writeJsonQueued(SETTINGS_FILE, next);
  return next;
}

export function dataDir(): string {
  return DATA_DIR;
}
