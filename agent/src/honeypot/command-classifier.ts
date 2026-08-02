/**
 * Sentinel Agent — BadUSB honeypot command classifier.
 *
 * Layer 2 of the honeypot gate (see keystroke-honeypot.ts for layer 1):
 * a command that types at human-plausible speed still gets judged for
 * malicious intent before it's allowed to actually execute. Reuses the
 * same OpenAI-compatible credentials as server/ai-explanation.ts
 * (OPENAI_API_KEY/OPENAI_MODEL/OPENAI_BASE_URL) rather than requiring a
 * second API key — deterministic mock by default, live call when
 * OPENAI_API_KEY is set, falling back to the mock heuristics on any API
 * failure so a flaky call never wedges the honeypot. The mock is a much
 * coarser net than a live model call — the hard-coded
 * CATASTROPHIC_COMMAND_PATTERNS backstop in honeypot/executor.ts is what
 * actually fails closed on the worst cases regardless of which path
 * classified the command.
 */
import { OPENAI_BASE_URL, OPENAI_MODEL } from "../shared/constants.ts";

export interface CommandVerdict {
  malicious: boolean;
  findings: string[];
}

const MOCK_MALICIOUS_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /\bcurl\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b/i, label: "pipes a remote download directly into a shell" },
  { pattern: /\bcat\s+.*\.(ssh|aws|netrc)\b/i, label: "reads credential/key material" },
  { pattern: /\b(scp|curl|wget|nc)\b.*\b(ssh|aws|password|credential|token|secret)\w*\b/i, label: "appears to exfiltrate credentials over the network" },
  { pattern: /\bsudo\s+rm\b/i, label: "elevated destructive delete" },
  { pattern: /\bchmod\s+777\b/i, label: "removes filesystem permission boundaries" },
  { pattern: /\bbase64\s+-d\b.*\|\s*(ba)?sh\b/i, label: "decodes and executes an obfuscated payload" },
  { pattern: /\bosascript\b.*\b(keystroke|System Events)\b/i, label: "scripts further keyboard/UI automation" },
];

export function buildMockVerdict(commandText: string): CommandVerdict {
  const findings = MOCK_MALICIOUS_PATTERNS.filter((m) => m.pattern.test(commandText)).map((m) => m.label);
  return { malicious: findings.length > 0, findings };
}

interface OpenAiChatCompletionResponse {
  choices?: { message?: { content?: string } }[];
}

async function callOpenAiCompatible(commandText: string): Promise<CommandVerdict> {
  const prompt = `You are a host-based intrusion detection analyst reviewing one shell command typed into a honeypot terminal that a suspected BadUSB device (a USB device impersonating a keyboard) is interacting with. Judge whether the command is malicious: credential theft, destructive/irreversible actions, unauthorized network exfiltration, disabling security controls, or automating a fraudulent financial transaction. Ordinary commands (ls, cd, git, npm, editing a file, checking system status) are not malicious.

Command:
${commandText}

Respond with ONLY a JSON object with exactly these keys: "malicious" (boolean) and "findings" (array of short strings, empty if not malicious). No markdown fences, no other text.`;

  const response = await fetch(`${OPENAI_BASE_URL}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env["OPENAI_API_KEY"]}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      messages: [{ role: "user", content: prompt }],
      temperature: 0,
    }),
  });

  if (!response.ok) throw new Error(`OpenAI-compatible API responded ${response.status}`);

  const data = (await response.json()) as OpenAiChatCompletionResponse;
  const text = data.choices?.[0]?.message?.content;
  if (!text) throw new Error("OpenAI-compatible API returned no content");

  const parsed = JSON.parse(text.trim().replace(/^```json\s*|\s*```$/g, "")) as Partial<CommandVerdict>;
  if (typeof parsed.malicious !== "boolean" || !Array.isArray(parsed.findings)) {
    throw new Error("OpenAI-compatible API response missing required fields");
  }
  return { malicious: parsed.malicious, findings: parsed.findings };
}

export async function classifyCommand(commandText: string): Promise<CommandVerdict> {
  if (!process.env["OPENAI_API_KEY"]) return buildMockVerdict(commandText);

  try {
    return await callOpenAiCompatible(commandText);
  } catch (err) {
    console.error("[sentinel-agent] command classification call failed, falling back to mock:", (err as Error).message);
    return buildMockVerdict(commandText);
  }
}
