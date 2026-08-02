"use strict";

const express = require("express");

const router = express.Router();
const AEGIS_URL = process.env.AEGIS_URL || "http://127.0.0.1:8012";

const VALID_EVENT_TYPES = new Set([
  "fetch_request",
  "xhr_request",
  "send_beacon",
  "form_submission",
  "redirect",
  "history_change",
  "clipboard_access",
  "hidden_iframe",
  "usb_scan_result",
]);
const VALID_DECISIONS = new Set([
  "allow",
  "warn",
  "blocked",
  "detected_not_blocked",
]);
const BLOCKABLE_EVENT_TYPES = new Set([
  "fetch_request",
  "xhr_request",
  "form_submission",
  "clipboard_access",
]);
const FORBIDDEN_KEYS = new Set([
  "password",
  "cookie",
  "cookies",
  "token",
  "authorization",
  "formData",
  "rawBody",
  "body",
  "value",
]);

function validateForkGuardRequest(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Request body must be a JSON object";
  }
  for (const key of FORBIDDEN_KEYS) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      return `Request must not include a "${key}" field`;
    }
  }
  if (!VALID_EVENT_TYPES.has(body.eventType)) {
    return `eventType must be one of: ${[...VALID_EVENT_TYPES].join(", ")}`;
  }
  if (typeof body.score !== "number" || !Number.isFinite(body.score) || body.score < 0 || body.score > 100) {
    return "score must be a finite number between 0 and 100";
  }
  if (!VALID_DECISIONS.has(body.decision)) {
    return `decision must be one of: ${[...VALID_DECISIONS].join(", ")}`;
  }
  if (typeof body.pageOrigin !== "string" || body.pageOrigin.length > 2048) {
    return "pageOrigin must be a string no longer than 2048 characters";
  }
  if (body.destinationOrigin != null && (typeof body.destinationOrigin !== "string" || body.destinationOrigin.length > 2048)) {
    return "destinationOrigin must be null or a string no longer than 2048 characters";
  }
  if (!Array.isArray(body.reasons) || body.reasons.length > 32) {
    return "reasons must be an array with at most 32 findings";
  }
  for (const reason of body.reasons) {
    if (!reason || typeof reason !== "object" || Array.isArray(reason)) {
      return "every reason must be an object";
    }
    if (typeof reason.label !== "string" || reason.label.length > 500) {
      return "every reason label must be a string no longer than 500 characters";
    }
    if (typeof reason.points !== "number" || !Number.isFinite(reason.points)) {
      return "every reason points value must be a finite number";
    }
  }
  return null;
}

function sanitizedPayload(body) {
  return {
    incidentId: typeof body.incidentId === "string" ? body.incidentId.slice(0, 200) : "sentinel-incident",
    eventType: body.eventType,
    pageOrigin: body.pageOrigin,
    destinationOrigin: body.destinationOrigin || "",
    score: Math.round(body.score),
    decision: body.decision,
    blockable: BLOCKABLE_EVENT_TYPES.has(body.eventType),
    reasons: body.reasons.map((reason) => ({
      ruleId: typeof reason.ruleId === "string" ? reason.ruleId.slice(0, 200) : "sentinel-finding",
      label: reason.label,
      points: Math.round(reason.points),
    })),
  };
}

async function callAegis(payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(`${AEGIS_URL}/walker/evaluate_sentinel_api`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload }),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw Object.assign(new Error(`AEGIS responded with HTTP ${response.status}`), { status: 502 });
    }
    const envelope = await response.json();
    const report = envelope?.data?.reports?.[0];
    if (!report || report.engine !== "AEGIS_FORKGUARD") {
      throw Object.assign(new Error("AEGIS returned an invalid report"), { status: 502 });
    }
    return report;
  } catch (error) {
    if (error.name === "AbortError") {
      throw Object.assign(new Error("AEGIS timed out"), { status: 504 });
    }
    if (error.status) throw error;
    throw Object.assign(
      new Error("AEGIS is unavailable. Start the full stack with npm run start:full."),
      { status: 503 },
    );
  } finally {
    clearTimeout(timeout);
  }
}

router.get("/health", async (_req, res) => {
  try {
    const response = await fetch(`${AEGIS_URL}/healthz`, { signal: AbortSignal.timeout(2500) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    res.json({ status: "ok", engine: "AEGIS_FORKGUARD", url: AEGIS_URL });
  } catch {
    res.status(503).json({ status: "offline", engine: "AEGIS_FORKGUARD", url: AEGIS_URL });
  }
});

router.post("/evaluate", async (req, res, next) => {
  const validationError = validateForkGuardRequest(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  try {
    const report = await callAegis(sanitizedPayload(req.body));
    res.json(report);
  } catch (error) {
    next(error);
  }
});

module.exports = { router, validateForkGuardRequest, sanitizedPayload, callAegis };
