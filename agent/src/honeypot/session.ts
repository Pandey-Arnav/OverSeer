/**
 * BadUSB honeypot command gate.
 *
 * Every submitted command is assessed by timing and intent, recorded as
 * evidence when suspicious/harmful, and contained inside the decoy. Nothing
 * typed into the honeypot is executed on the host.
 */
import { randomUUID } from "node:crypto";
import { evaluateRisk, buildIncident } from "../risk/engine.ts";
import { addIncident } from "../storage/store.ts";
import { computeKeystrokeStats, isBotLikeTiming } from "../monitors/keystroke-honeypot.ts";
import { classifyCommand, type CommandVerdict } from "./command-classifier.ts";
import { isCatastrophicCommand } from "./executor.ts";
import { createHardwareAssessment, recordHardwareAssessment } from "../hardware/hid-assessment.ts";
import type { HardwareAssessment, HidDeviceContext, SentinelEvent } from "../shared/types.ts";

export interface HoneypotCommandResult {
  allowed: boolean;
  reason?: string;
  stdout?: string;
  stderr?: string;
  assessment?: HardwareAssessment;
}

async function logBlockedIncident(event: SentinelEvent): Promise<void> {
  const evaluation = evaluateRisk(event, {}, true);
  const incident = buildIncident(event, evaluation, null, randomUUID(), new Date(event.timestamp).toISOString());
  await addIncident(incident);
}

export function assessHoneypotBehavior(
  botLikeTiming: boolean,
  verdict: CommandVerdict,
  catastrophic: boolean,
  now = new Date()
): HardwareAssessment {
  if (catastrophic || verdict.malicious) {
    const findings = verdict.findings.length > 0 ? verdict.findings : ["matched a catastrophic command safety pattern"];
    return createHardwareAssessment(
      "harmful",
      "Malicious command intent was detected and contained before execution.",
      findings,
      "high",
      now
    );
  }
  if (botLikeTiming) {
    return createHardwareAssessment(
      "suspicious",
      "The device produced fast, highly uniform scripted input, but the command itself was not classified as harmful.",
      ["BadUSB-like keystroke timing", "command contained in decoy"],
      "high",
      now
    );
  }
  return createHardwareAssessment(
    "no_harmful_behavior_observed",
    "The observed input had human-plausible timing and no harmful command intent. The command was still contained in the decoy.",
    ["human-plausible timing", "no malicious command pattern", "command not executed"],
    "medium",
    now
  );
}

export async function handleHoneypotCommand(
  commandText: string,
  keyTimestamps: number[],
  deviceContext?: HidDeviceContext
): Promise<HoneypotCommandResult> {
  const now = Date.now();
  const stats = computeKeystrokeStats(keyTimestamps);
  const botLikeTiming = Boolean(stats && isBotLikeTiming(stats));
  const catastrophic = isCatastrophicCommand(commandText);
  const verdict: CommandVerdict = catastrophic
    ? { malicious: true, findings: ["matched a catastrophic command safety pattern"] }
    : await classifyCommand(commandText);
  const assessment = assessHoneypotBehavior(botLikeTiming, verdict, catastrophic, new Date(now));
  if (deviceContext) await recordHardwareAssessment(deviceContext, assessment);

  const deviceFields = deviceContext
    ? {
        deviceKey: deviceContext.deviceKey,
        deviceName: deviceContext.deviceName,
        vendorId: deviceContext.vendorId,
        productId: deviceContext.productId,
      }
    : {};

  if (assessment.verdict === "harmful") {
    await logBlockedIncident({
      category: "honeypot_malicious_command",
      timestamp: now,
      honeypotCommand: commandText,
      scriptFindings: assessment.evidence,
      hardwareAssessment: assessment,
      ...deviceFields,
    });
    return {
      allowed: false,
      reason: `Harmful behavior detected and contained: ${assessment.evidence.join("; ")}`,
      assessment,
    };
  }

  if (assessment.verdict === "suspicious") {
    await logBlockedIncident({
      category: "usb_badusb_keystroke",
      timestamp: now,
      keystrokeStats: stats ?? undefined,
      hardwareAssessment: assessment,
      ...deviceFields,
    });
    return {
      allowed: false,
      reason: "Suspicious scripted input detected and contained; no harmful command intent was found.",
      assessment,
    };
  }

  return {
    allowed: false,
    reason: "No harmful behavior was observed. The command was contained in the decoy and was not executed.",
    assessment,
  };
}
