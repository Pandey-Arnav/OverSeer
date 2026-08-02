"use strict";

const crypto = require("node:crypto");
const express = require("express");
const { callAegis } = require("./forkguard");
const { evaluateHardwareRisk } = require("../services/hardware-risk");
const { HardwareStore } = require("../services/hardware-store");

const router = express.Router();
const store = new HardwareStore();
const agents = new Map();
const FORBIDDEN_KEYS = new Set([
  "password",
  "cookie",
  "cookies",
  "token",
  "authorization",
  "contents",
  "content",
  "rawbody",
  "body",
  "files",
  "paths",
  "serialnumber",
]);

function containsForbiddenKey(value, depth = 0) {
  if (depth > 6 || !value || typeof value !== "object") return false;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) return true;
    if (containsForbiddenKey(child, depth + 1)) return true;
  }
  return false;
}

function boundedInteger(value, maximum = 10_000_000) {
  return Number.isInteger(value) && value >= 0 && value <= maximum;
}

function requireAgentToken(req, res, next) {
  const expected = process.env.GHOSTSHIELD_AGENT_TOKEN;
  if (!expected) return next();
  const supplied = req.get("X-GhostShield-Agent-Token") || "";
  const expectedBuffer = Buffer.from(expected);
  const suppliedBuffer = Buffer.from(supplied);
  if (expectedBuffer.length !== suppliedBuffer.length || !crypto.timingSafeEqual(expectedBuffer, suppliedBuffer)) {
    return res.status(401).json({ error: "USB agent authentication failed" });
  }
  next();
}

function validateHardwareReport(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "Request body must be a JSON object";
  if (containsForbiddenKey(body)) return "Hardware reports must not include raw file contents, paths, credentials, or device serial numbers";
  if (typeof body.agentId !== "string" || !/^[a-f0-9]{64}$/i.test(body.agentId)) return "agentId must be a SHA-256 identifier";
  if (!body.device || typeof body.device !== "object" || Array.isArray(body.device)) return "device metadata is required";
  if (typeof body.device.deviceIdHash !== "string" || !/^[a-f0-9]{64}$/i.test(body.device.deviceIdHash)) return "deviceIdHash must be a SHA-256 identifier";
  if (typeof body.device.driveLetter !== "string" || !/^[A-Z]:\\$/i.test(body.device.driveLetter)) return "driveLetter must be a removable-drive root";
  if (typeof body.device.displayName !== "string" || body.device.displayName.length > 160) return "displayName must be a short string";
  if (!body.inventory || typeof body.inventory !== "object" || Array.isArray(body.inventory)) return "inventory summary is required";
  for (const key of ["totalFiles", "executableCount", "scriptCount", "shortcutCount", "archiveCount"]) {
    if (!boundedInteger(body.inventory[key])) return `${key} must be a non-negative bounded integer`;
  }
  if (typeof body.inventory.autorunPresent !== "boolean" || typeof body.inventory.truncated !== "boolean") {
    return "inventory flags must be boolean values";
  }
  if (!body.defender || typeof body.defender !== "object" || Array.isArray(body.defender)) return "Defender scan summary is required";
  if (typeof body.defender.available !== "boolean" || typeof body.defender.completed !== "boolean") return "Defender availability flags must be boolean values";
  if (!boundedInteger(body.defender.threatCount, 1000)) return "threatCount must be a non-negative bounded integer";
  return null;
}

function validateHeartbeat(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "Request body must be a JSON object";
  if (typeof body.agentId !== "string" || !/^[a-f0-9]{64}$/i.test(body.agentId)) return "agentId must be a SHA-256 identifier";
  if (typeof body.status !== "string" || body.status.length > 40) return "status must be a short string";
  if (!boundedInteger(body.currentVolumeCount, 100)) return "currentVolumeCount must be between 0 and 100";
  return null;
}

function sanitizedHardwareReport(body) {
  return {
    agentId: body.agentId.toLowerCase(),
    testMode: body.testMode === true,
    device: {
      deviceIdHash: body.device.deviceIdHash.toLowerCase(),
      driveLetter: body.device.driveLetter.toUpperCase(),
      displayName: body.device.displayName.slice(0, 160),
      fileSystem: typeof body.device.fileSystem === "string" ? body.device.fileSystem.slice(0, 32) : "unknown",
      sizeBytes: boundedInteger(body.device.sizeBytes, Number.MAX_SAFE_INTEGER) ? body.device.sizeBytes : 0,
      busType: "USB",
    },
    inventory: {
      totalFiles: body.inventory.totalFiles,
      executableCount: body.inventory.executableCount,
      scriptCount: body.inventory.scriptCount,
      shortcutCount: body.inventory.shortcutCount,
      archiveCount: body.inventory.archiveCount,
      autorunPresent: body.inventory.autorunPresent,
      truncated: body.inventory.truncated,
    },
    defender: {
      available: body.defender.available,
      completed: body.defender.completed,
      threatCount: body.defender.threatCount,
      remediationSuccessful: body.defender.remediationSuccessful === true,
      status: typeof body.defender.status === "string" ? body.defender.status.slice(0, 100) : "unknown",
    },
    scanStartedAt: typeof body.scanStartedAt === "string" ? body.scanStartedAt.slice(0, 40) : null,
    scanCompletedAt: typeof body.scanCompletedAt === "string" ? body.scanCompletedAt.slice(0, 40) : null,
  };
}

router.post("/heartbeat", requireAgentToken, (req, res) => {
  const validationError = validateHeartbeat(req.body);
  if (validationError) return res.status(400).json({ error: validationError });
  const state = {
    agentId: req.body.agentId.toLowerCase(),
    status: req.body.status,
    currentVolumeCount: req.body.currentVolumeCount,
    version: typeof req.body.version === "string" ? req.body.version.slice(0, 40) : "unknown",
    lastSeen: new Date().toISOString(),
  };
  agents.set(state.agentId, state);
  res.json({ status: "ok", receivedAt: state.lastSeen });
});

router.get("/health", (_req, res) => {
  const now = Date.now();
  const agentStates = [...agents.values()].map((agent) => ({
    ...agent,
    online: now - Date.parse(agent.lastSeen) < 30_000,
  }));
  res.json({
    status: "ok",
    platform: "windows-usb-agent",
    online: agentStates.some((agent) => agent.online),
    agents: agentStates,
  });
});

router.get("/incidents", async (req, res, next) => {
  try {
    const requestedLimit = Number.parseInt(req.query.limit, 10);
    const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 500)) : 500;
    res.json({ incidents: await store.list(limit) });
  } catch (error) {
    next(error);
  }
});

router.delete("/incidents", async (_req, res, next) => {
  try {
    await store.clear();
    res.json({ status: "cleared" });
  } catch (error) {
    next(error);
  }
});

router.post("/incidents", requireAgentToken, async (req, res, next) => {
  const validationError = validateHardwareReport(req.body);
  if (validationError) return res.status(400).json({ error: validationError });

  try {
    const report = sanitizedHardwareReport(req.body);
    const risk = evaluateHardwareRisk(report);
    const id = `hardware-${crypto.randomUUID()}`;
    const destinationOrigin = `usb://${report.device.deviceIdHash.slice(0, 24)}`;
    let forkguardAnalysis = null;
    let forkguardError = null;

    try {
      forkguardAnalysis = await callAegis({
        incidentId: id,
        eventType: "usb_scan_result",
        pageOrigin: "hardware://windows-agent",
        destinationOrigin,
        score: risk.score,
        decision: risk.decision,
        blockable: false,
        reasons: risk.reasons,
      });
    } catch (error) {
      forkguardError = error.message;
    }

    const incident = {
      id,
      source: "hardware",
      timestamp: report.scanCompletedAt || new Date().toISOString(),
      pageUrl: "hardware://windows-agent",
      pageOrigin: "hardware://windows-agent",
      destinationUrl: destinationOrigin,
      destinationOrigin,
      eventType: "usb_scan_result",
      method: "device_scan",
      payloadSize: null,
      score: risk.score,
      severity: risk.severity,
      decision: risk.decision,
      reasons: risk.reasons,
      hardware: report,
      simulated: report.testMode,
      forkguardAnalysis,
      forkguardError,
    };

    await store.append(incident);
    res.status(201).json({ incident });
  } catch (error) {
    next(error);
  }
});

module.exports = {
  router,
  validateHardwareReport,
  validateHeartbeat,
  sanitizedHardwareReport,
  containsForbiddenKey,
  requireAgentToken,
};
