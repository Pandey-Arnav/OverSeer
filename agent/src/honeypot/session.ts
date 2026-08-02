/**
 * Sentinel Agent — BadUSB honeypot command gate.
 *
 * Orchestrates the two-layer check described in the project's honeypot
 * design (timing, then intent) before a command typed into the decoy
 * terminal (public/honeypot.html) is allowed to actually execute on the
 * real machine. Kept separate from server/app.ts so the gate logic is
 * testable without spinning up Express.
 */
import { randomUUID } from "node:crypto";
import { evaluateRisk, buildIncident } from "../risk/engine.ts";
import { addIncident } from "../storage/store.ts";
import { computeKeystrokeStats, isBotLikeTiming } from "../monitors/keystroke-honeypot.ts";
import { classifyCommand } from "./command-classifier.ts";
import { executeHoneypotCommand, isCatastrophicCommand } from "./executor.ts";
import type { SentinelEvent } from "../shared/types.ts";

export interface HoneypotCommandResult {
  allowed: boolean;
  reason?: string;
  stdout?: string;
  stderr?: string;
}

async function logBlockedIncident(event: SentinelEvent): Promise<void> {
  const evaluation = evaluateRisk(event, {}, true);
  const incident = buildIncident(event, evaluation, null, randomUUID(), new Date(event.timestamp).toISOString());
  await addIncident(incident);
}

export async function handleHoneypotCommand(commandText: string, keyTimestamps: number[]): Promise<HoneypotCommandResult> {
  const now = Date.now();

  // Layer 1: timing. Never executes, never calls the classifier — a scripted
  // HID replay is rejected purely on how uniformly fast it typed.
  const stats = computeKeystrokeStats(keyTimestamps);
  if (stats && isBotLikeTiming(stats)) {
    await logBlockedIncident({ category: "usb_badusb_keystroke", timestamp: now, keystrokeStats: stats, honeypotCommand: commandText });
    return { allowed: false, reason: "Input timing was too uniform and fast to be human typing — blocked." };
  }

  // Layer 2: intent. Typed at a human-plausible pace, so judge what it
  // actually says before letting it near a real shell.
  const verdict = await classifyCommand(commandText);
  if (verdict.malicious) {
    await logBlockedIncident({ category: "honeypot_malicious_command", timestamp: now, honeypotCommand: commandText, scriptFindings: verdict.findings });
    return { allowed: false, reason: `Blocked: ${verdict.findings.join("; ") || "classified as malicious"}` };
  }

  // Backstop: only reachable on a classifier false negative, since
  // passing commands now execute for real on the actual machine.
  if (isCatastrophicCommand(commandText)) {
    await logBlockedIncident({
      category: "honeypot_malicious_command",
      timestamp: now,
      honeypotCommand: commandText,
      scriptFindings: ["matched a hard-coded catastrophic-command pattern (rm -rf /, disk format, fork bomb, etc.)"],
    });
    return { allowed: false, reason: "Blocked: matched a hard-coded catastrophic-command safety pattern." };
  }

  const result = await executeHoneypotCommand(commandText);
  return { allowed: true, stdout: result.stdout, stderr: result.stderr };
}
