/**
 * Generates a plain-English explanation for a Sentinel Agent incident.
 * Same two-mode design as the original browser-extension prototype's
 * server: deterministic mock by default, live OpenAI-compatible call
 * when OPENAI_API_KEY is set, always falling back to the mock on any
 * failure so a flaky AI call never breaks the dashboard.
 */
import { OPENAI_BASE_URL, OPENAI_MODEL } from "../shared/constants.ts";
import type { AIExplanation, Incident } from "../shared/types.ts";

function severityWord(score: number): string {
  if (score >= 70) return "high";
  if (score >= 40) return "moderate";
  return "low";
}

export function buildMockExplanation(incident: Pick<Incident, "category" | "summary" | "score" | "reasons">): AIExplanation {
  const severity = severityWord(incident.score);
  const reasonLabels = incident.reasons.map((r) => r.label);
  const kind = incident.category.replace(/_/g, " ");

  const summary = `Sentinel observed ${kind} activity (${incident.summary}), scored as ${severity} risk (${incident.score}/100).`;

  const technicalExplanation = reasonLabels.length
    ? `Triggered rules: ${reasonLabels.join("; ")}.`
    : "No individual detection rules triggered, but the event was still logged for review.";

  const recommendation =
    incident.score >= 70
      ? "Review this activity now — a remediation action may be available in the dashboard."
      : incident.score >= 40
        ? "Worth a look — confirm this is activity you recognize."
        : "No action needed; this looks like typical activity.";

  return { summary, technicalExplanation, recommendation };
}

interface OpenAiChatCompletionResponse {
  choices?: { message?: { content?: string } }[];
}

async function callOpenAiCompatible(incident: Pick<Incident, "category" | "summary" | "score" | "reasons">): Promise<AIExplanation> {
  const prompt = `You are a host-based intrusion detection analyst. Given this sanitized incident metadata (no sensitive values, only category/summary/score/rule findings), return a JSON object with exactly these keys: "summary" (one plain-English sentence a non-technical user can understand), "technicalExplanation" (1-2 sentences on the specific signals involved), and "recommendation" (one short actionable sentence).

Incident:
${JSON.stringify(incident, null, 2)}

Respond with ONLY the JSON object, no markdown fences.`;

  const response = await fetch(`${OPENAI_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env["OPENAI_API_KEY"]}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
    }),
  });

  if (!response.ok) throw new Error(`OpenAI-compatible API responded ${response.status}`);

  const data = (await response.json()) as OpenAiChatCompletionResponse;
  const text = data.choices?.[0]?.message?.content;
  if (!text) throw new Error("OpenAI-compatible API returned no content");

  const parsed = JSON.parse(text.trim().replace(/^```json\s*|\s*```$/g, "")) as Partial<AIExplanation>;
  if (!parsed.summary || !parsed.technicalExplanation || !parsed.recommendation) {
    throw new Error("OpenAI-compatible API response missing required fields");
  }
  return parsed as AIExplanation;
}

export async function generateExplanation(incident: Pick<Incident, "category" | "summary" | "score" | "reasons">): Promise<AIExplanation> {
  if (!process.env["OPENAI_API_KEY"]) return buildMockExplanation(incident);

  try {
    return await callOpenAiCompatible(incident);
  } catch (err) {
    console.error("[sentinel-agent] AI explanation call failed, falling back to mock:", (err as Error).message);
    return buildMockExplanation(incident);
  }
}
