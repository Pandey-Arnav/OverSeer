"use strict";

const express = require("express");
const { generateExplanation } = require("../services/ai-explanation");

const router = express.Router();

const VALID_EVENT_TYPES = new Set([
  "fetch_request",
  "xhr_request",
  "send_beacon",
  "form_submission",
  "redirect",
  "history_change",
  "clipboard_access",
  "hidden_iframe",
]);

/** Rejects anything that isn't the sanitized metadata shape we expect. */
function validateExplainRequest(body) {
  if (!body || typeof body !== "object") return "Request body must be a JSON object";
  if (typeof body.eventType !== "string" || !VALID_EVENT_TYPES.has(body.eventType)) {
    return `eventType must be one of: ${[...VALID_EVENT_TYPES].join(", ")}`;
  }
  if (typeof body.score !== "number" || body.score < 0 || body.score > 100) {
    return "score must be a number between 0 and 100";
  }
  if (body.reasons !== undefined && !Array.isArray(body.reasons)) {
    return "reasons must be an array";
  }
  // Defense in depth: never let obviously sensitive keys through, even
  // though the extension should never send them.
  const forbiddenKeys = ["password", "cookie", "cookies", "token", "authorization", "formData", "rawBody"];
  for (const key of forbiddenKeys) {
    if (Object.prototype.hasOwnProperty.call(body, key)) {
      return `Request must not include a "${key}" field`;
    }
  }
  return null;
}

router.post("/", async (req, res, next) => {
  const validationError = validateExplainRequest(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  try {
    const explanation = await generateExplanation({
      eventType: req.body.eventType,
      pageOrigin: req.body.pageOrigin,
      destinationOrigin: req.body.destinationOrigin,
      method: req.body.method,
      payloadSize: req.body.payloadSize,
      score: req.body.score,
      reasons: req.body.reasons || [],
    });
    res.json(explanation);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
