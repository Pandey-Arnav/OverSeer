/**
 * Sentinel Agent — network connection monitor.
 *
 * Polls `lsof -i -P -n` (parsing verified against real output on this
 * machine — see the format notes below) and diffs against the previous
 * snapshot so each established connection or newly-opened listening port
 * is evaluated and logged exactly once, not on every poll while it stays
 * open. Process identity (name/user/signing/path) is cached briefly per
 * PID to avoid re-running `codesign`/`ps` on every tick for a long-lived
 * connection.
 *
 * lsof NAME column format (whitespace-split, everything after the fixed
 * 8 columns re-joined):
 *   ESTABLISHED: "10.0.0.5:52962->134.224.4.134:443 (ESTABLISHED)"
 *   LISTEN:      "127.0.0.1:60782 (LISTEN)"   or   "*:52960 (LISTEN)"
 *   IPv6 addresses are bracketed: "[fe80::1]:1024->[fe80::2]:1025"
 * Only TCP rows are considered — UDP has no comparable
 * established/listening distinction and is out of scope for this MVP.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evaluateRisk, buildIncident } from "../risk/engine.ts";
import { getProcessInfo, isSafeToTerminate } from "./process-info.ts";
import { addIncident, getSettings } from "../storage/store.ts";
import { TUNING } from "../shared/constants.ts";
import { randomUUID } from "node:crypto";
import type { EvalContext, Incident, ProcessInfo, RemediationInfo, SentinelEvent } from "../shared/types.ts";

const execFileAsync = promisify(execFile);

interface ParsedConnection {
  command: string;
  pid: number;
  user: string;
  state: "ESTABLISHED" | "LISTEN";
  localPort?: number;
  remoteAddress?: string;
  remotePort?: number;
}

function parseHostPort(segment: string): { host: string; port: number } | null {
  const bracketed = segment.match(/^\[(.+)\]:(\d+)$/);
  if (bracketed) return { host: bracketed[1]!, port: Number(bracketed[2]) };
  const plain = segment.match(/^(.+):(\d+)$/);
  if (plain) return { host: plain[1]!, port: Number(plain[2]) };
  return null;
}

function parseLsofOutput(stdout: string): ParsedConnection[] {
  const lines = stdout.split("\n").slice(1); // skip header
  const connections: ParsedConnection[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 9) continue;
    const [command, pidStr, user, , , , , node, ...rest] = parts;
    if (node !== "TCP" || !command || !pidStr || !user) continue;

    const name = rest.join(" ");
    const stateMatch = name.match(/\((\w+)\)\s*$/);
    if (!stateMatch) continue;
    const state = stateMatch[1];
    if (state !== "ESTABLISHED" && state !== "LISTEN") continue;

    const addressPart = name.slice(0, name.lastIndexOf("(")).trim();
    const pid = Number(pidStr);
    if (!Number.isFinite(pid)) continue;

    if (state === "LISTEN") {
      const local = parseHostPort(addressPart);
      if (!local) continue;
      connections.push({ command, pid, user, state: "LISTEN", localPort: local.port });
    } else {
      const [localSeg, remoteSeg] = addressPart.split("->");
      if (!localSeg || !remoteSeg) continue;
      const local = parseHostPort(localSeg);
      const remote = parseHostPort(remoteSeg);
      if (!remote) continue;
      connections.push({
        command,
        pid,
        user,
        state: "ESTABLISHED",
        localPort: local?.port,
        remoteAddress: remote.host,
        remotePort: remote.port,
      });
    }
  }
  return connections;
}

async function listConnections(): Promise<ParsedConnection[]> {
  try {
    const { stdout } = await execFileAsync("lsof", ["-i", "-P", "-n"], { maxBuffer: 10 * 1024 * 1024 });
    return parseLsofOutput(stdout);
  } catch (err) {
    // lsof exits non-zero if it finds nothing to report on some systems —
    // stdout may still be usable; only truly fail if there's no stdout.
    const stdout = (err as { stdout?: string }).stdout;
    if (typeof stdout === "string") return parseLsofOutput(stdout);
    console.error("[Sentinel] lsof failed:", (err as Error).message);
    return [];
  }
}

interface ProcessCacheEntry {
  info: ProcessInfo;
  cachedAt: number;
}
const PROCESS_CACHE_TTL_MS = 60_000;
const processCache = new Map<number, ProcessCacheEntry>();

async function getCachedProcessInfo(pid: number, name: string, user: string): Promise<ProcessInfo> {
  const cached = processCache.get(pid);
  if (cached && Date.now() - cached.cachedAt < PROCESS_CACHE_TTL_MS && cached.info.name === name) {
    return cached.info;
  }
  const info = await getProcessInfo(pid, name, user);
  processCache.set(pid, { info, cachedAt: Date.now() });
  return info;
}

// State carried across polls (module-level: one monitor instance per process).
const activeEstablished = new Set<string>(); // "processName|remoteAddress:remotePort"
const activeListening = new Set<string>(); // "processName|localPort"
const seenRemoteHostsByProcess = new Map<string, Set<string>>(); // processName -> Set<"remoteAddress:remotePort">
const newHostTimestampsByProcess = new Map<string, number[]>();

function recordNewHostContact(processName: string, now: number): number {
  const timestamps = newHostTimestampsByProcess.get(processName) ?? [];
  timestamps.push(now);
  const cutoff = now - TUNING.MULTIPLE_NEW_HOSTS_WINDOW_MS;
  const recent = timestamps.filter((t) => t >= cutoff);
  newHostTimestampsByProcess.set(processName, recent);
  return recent.length;
}

async function buildRemediation(process: ProcessInfo | undefined): Promise<RemediationInfo | null> {
  if (!process) return null;
  const safety = isSafeToTerminate(process);
  return {
    available: safety.safe,
    action: safety.safe ? "terminate_process" : null,
    reason: safety.reason,
    pid: process.pid,
    applied: false,
    appliedAt: null,
  };
}

/** Runs one poll cycle: lists connections, evaluates anything new, persists incidents. Returns newly-created incidents. */
export async function runNetworkMonitorTick(): Promise<Incident[]> {
  const settings = await getSettings();
  if (!settings.protectionEnabled) return [];

  const connections = await listConnections();
  const newIncidents: Incident[] = [];
  const now = Date.now();

  const currentEstablishedKeys = new Set<string>();
  const currentListeningKeys = new Set<string>();

  for (const conn of connections) {
    const process = await getCachedProcessInfo(conn.pid, conn.command, conn.user);

    if (conn.state === "LISTEN") {
      const key = `${conn.command}|${conn.localPort}`;
      currentListeningKeys.add(key);
      if (activeListening.has(key)) continue; // already seen this poll-to-poll — don't re-evaluate

      const event: SentinelEvent = {
        category: "network_connection",
        timestamp: now,
        process,
        localPort: conn.localPort,
        connectionState: "LISTEN",
        isNewListeningPort: true,
      };
      const evaluation = evaluateRisk(event, {}, (await isSafeToTerminate(process)).safe);
      const remediation = await buildRemediation(process);
      const incident = buildIncident(event, evaluation, remediation, randomUUID(), new Date(now).toISOString());
      await addIncident(incident);
      newIncidents.push(incident);
      continue;
    }

    // ESTABLISHED
    const hostKey = `${conn.remoteAddress}:${conn.remotePort}`;
    const connKey = `${conn.command}|${hostKey}`;
    currentEstablishedKeys.add(connKey);
    if (activeEstablished.has(connKey)) continue; // steady-state connection, already logged

    const seenHosts = seenRemoteHostsByProcess.get(conn.command) ?? new Set<string>();
    const context: EvalContext = { seenRemoteHosts: seenHosts };
    const isNewHost = !seenHosts.has(hostKey);
    const distinctRemoteHostsInWindow = isNewHost ? recordNewHostContact(conn.command, now) : undefined;

    const event: SentinelEvent = {
      category: "network_connection",
      timestamp: now,
      process,
      remoteAddress: conn.remoteAddress,
      remotePort: conn.remotePort,
      localPort: conn.localPort,
      connectionState: "ESTABLISHED",
      distinctRemoteHostsInWindow,
    };
    const remediable = (await isSafeToTerminate(process)).safe;
    const evaluation = evaluateRisk(event, context, remediable);
    const remediation = await buildRemediation(process);
    const incident = buildIncident(event, evaluation, remediation, randomUUID(), new Date(now).toISOString());
    await addIncident(incident);
    newIncidents.push(incident);

    seenHosts.add(hostKey);
    seenRemoteHostsByProcess.set(conn.command, seenHosts);
  }

  activeEstablished.clear();
  currentEstablishedKeys.forEach((k) => activeEstablished.add(k));
  activeListening.clear();
  currentListeningKeys.forEach((k) => activeListening.add(k));

  return newIncidents;
}
