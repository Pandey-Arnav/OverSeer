import { RULES } from "./rules.js";

export function calculateRisk(findings) {
  const detectedRules = findings.map((finding) => RULES[finding]).filter(Boolean);
  const fraudRisk = Math.min(100, detectedRules.reduce((sum, rule) => sum + rule.points, 0));
  return { fraudRisk, detectedRules };
}

export function riskLevel(score) { return score >= 70 ? "critical" : score >= 40 ? "warning" : "safe"; }
