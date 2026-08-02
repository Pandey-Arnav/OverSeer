"use strict";

/**
 * Generates a plain-English explanation for a Sentinel incident.
 *
 * Works in two modes:
 *   - Mock mode (default, no OPENAI_API_KEY): deterministic, rule-driven
 *     explanation built directly from the reasons already computed by the
 *     extension's risk engine. No network call, no API key needed.
 *   - Live mode (OPENAI_API_KEY set): calls an OpenAI-compatible
 *     chat-completions endpoint via plain `fetch` (no SDK dependency, to
 *     keep the server's dependency list minimal) and falls back to the
 *     mock explanation on any failure — a flaky/misconfigured AI call
 *     should never break the feature.
 *
 * The incoming `payload` is already the sanitized, metadata-only shape
 * the extension sends (see routes/explain.js validation) — no raw
 * request bodies, form values, or credentials ever reach this file.
 */

const OPENAI_BASE_URL = process.env.OPENAI_BASE_URL || "https://api.openai.com/v1";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

function severityWord(score) {
  if (score >= 70) return "high";
  if (score >= 40) return "moderate";
  return "low";
}

function buildMockExplanation(payload) {
  const { eventType, pageOrigin, destinationOrigin, score, reasons } = payload;
  const severity = severityWord(score);
  const reasonLabels = (reasons || []).map((r) => r.label);

  const destinationClause =
    destinationOrigin && destinationOrigin !== pageOrigin
      ? ` to a different site (${destinationOrigin})`
      : "";

  const summary = `This ${eventType.replace(/_/g, " ")} on ${pageOrigin || "this page"} sent data${destinationClause}, which Sentinel scored as ${severity} risk (${score}/100).`;

  const technicalExplanation = reasonLabels.length
    ? `Triggered rules: ${reasonLabels.join("; ")}.`
    : "No individual detection rules triggered, but the combined context was still logged for review.";

  const recommendation =
    score >= 70
      ? "Avoid continuing unless you specifically recognize and trust this destination."
      : score >= 40
        ? "Proceed with caution — double-check that this destination is one you expect this site to contact."
        : "No action needed; this looks like typical page behavior.";

  return { summary, technicalExplanation, recommendation };
}

async function callOpenAiCompatible(payload) {
  const prompt = `You are a browser security analyst. Given this sanitized incident metadata (no sensitive values, only sizes/origins/rule findings), return a JSON object with exactly these keys: "summary" (one plain-English sentence a non-technical user can understand), "technicalExplanation" (1-2 sentences on the specific signals involved), and "recommendation" (one short actionable sentence).

Incident:
${JSON.stringify(payload, null, 2)}

Respond with ONLY the JSON object, no markdown fences.`;

  const response = await fetch(`${OPENAI_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    throw new Error(`OpenAI-compatible API responded ${response.status}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content;
  if (!text) throw new Error("OpenAI-compatible API returned no content");

  const parsed = JSON.parse(text.trim().replace(/^```json\s*|\s*```$/g, ""));
  if (!parsed.summary || !parsed.technicalExplanation || !parsed.recommendation) {
    throw new Error("OpenAI-compatible API response missing required fields");
  }
  return parsed;
}

async function generateExplanation(payload) {
  if (!process.env.OPENAI_API_KEY) {
    return buildMockExplanation(payload);
  }

  try {
    return await callOpenAiCompatible(payload);
  } catch (err) {
    console.error("[sentinel-server] AI explanation call failed, falling back to mock:", err.message);
    return buildMockExplanation(payload);
  }
}

module.exports = { generateExplanation, buildMockExplanation };
