import React from "react";

export function SecurityBanner({ incident }) {
  if (!incident) return null;
  return <div className="security-banner"><strong>Transaction Frozen</strong><span>Potential financial fraud detected.</span><small>Risk {incident.fraudRisk}/100 · {incident.detectedRules.map((rule) => rule.label).join(" · ")} · {incident.actionTaken}</small></div>;
}
