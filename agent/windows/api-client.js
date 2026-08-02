"use strict";

class GhostShieldApiClient {
  constructor(baseUrl = process.env.GHOSTSHIELD_API_URL || "http://127.0.0.1:4000") {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async post(path, body, timeoutMs = 15_000) {
    const headers = { "Content-Type": "application/json" };
    if (process.env.GHOSTSHIELD_AGENT_TOKEN) {
      headers["X-GhostShield-Agent-Token"] = process.env.GHOSTSHIELD_AGENT_TOKEN;
    }
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `GhostShield API responded ${response.status}`);
    return result;
  }

  heartbeat(body) {
    return this.post("/api/hardware/heartbeat", body, 5_000);
  }

  reportIncident(body) {
    return this.post("/api/hardware/incidents", body, 30_000);
  }
}

module.exports = { GhostShieldApiClient };
