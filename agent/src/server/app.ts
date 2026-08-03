import "dotenv/config";

import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import { SERVER_HOST, SERVER_PORT } from "../shared/constants.ts";
import { clearIncidents, getIncidents, getSettings, updateIncident, updateSettings } from "../storage/store.ts";
import { generateExplanation } from "./ai-explanation.ts";
import { ejectUsbDevice, terminateProcess } from "../remediation/actions.ts";
import { evaluateIncidentWithAegis, getAegisHealth } from "../aegis/client.ts";
import { handleHoneypotCommand } from "../honeypot/session.ts";
import { buildSecurityInsights } from "../insights/security-insights.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export function createApp() {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "50kb" }));

  app.get("/health", async (_req, res) => {
    const settings = await getSettings();
    res.json({ status: "ok", protectionEnabled: settings.protectionEnabled, mockAiMode: !process.env["OPENAI_API_KEY"] });
  });

  app.get("/api/incidents", async (_req, res) => {
    res.json(await getIncidents());
  });

  app.get("/api/insights", async (_req, res) => {
    res.json(buildSecurityInsights(await getIncidents()));
  });

  app.get("/api/aegis/health", async (_req, res) => {
    const health = await getAegisHealth();
    res.status(health.status === "ok" ? 200 : 503).json(health);
  });

  app.post("/api/incidents/:id/aegis", async (req, res, next) => {
    try {
      const incidents = await getIncidents();
      const incident = incidents.find((item) => item.id === req.params.id);
      if (!incident) {
        res.status(404).json({ error: "Incident not found" });
        return;
      }
      const aegisReport = await evaluateIncidentWithAegis(incident);
      await updateIncident(incident.id, { aegisReport });
      res.json(aegisReport);
    } catch (err) {
      next(err);
    }
  });

  app.post("/api/incidents/clear", async (_req, res) => {
    await clearIncidents();
    res.json({ ok: true });
  });

  app.get("/api/settings", async (_req, res) => {
    res.json(await getSettings());
  });

  app.post("/api/settings", async (req, res) => {
    const patch: Record<string, unknown> = {};
    if (typeof req.body.protectionEnabled === "boolean") patch["protectionEnabled"] = req.body.protectionEnabled;
    if (typeof req.body.aiExplanationsEnabled === "boolean") patch["aiExplanationsEnabled"] = req.body.aiExplanationsEnabled;
    if (typeof req.body.honeypotArmed === "boolean") patch["honeypotArmed"] = req.body.honeypotArmed;
    res.json(await updateSettings(patch));
  });

  app.post("/api/honeypot/command", async (req, res, next) => {
    try {
      const commandText = req.body.commandText;
      const keyTimestamps = req.body.keyTimestamps;
      if (typeof commandText !== "string" || !commandText.trim()) {
        res.status(400).json({ error: "commandText is required" });
        return;
      }
      if (!Array.isArray(keyTimestamps) || !keyTimestamps.every((t) => typeof t === "number")) {
        res.status(400).json({ error: "keyTimestamps must be an array of numbers" });
        return;
      }
      const rawContext = req.body.deviceContext;
      const boundedString = (value: unknown, max: number): string | undefined =>
        typeof value === "string" && value.length > 0 && value.length <= max ? value : undefined;
      const deviceKey = rawContext && typeof rawContext === "object" ? boundedString(rawContext.deviceKey, 300) : undefined;
      const deviceName = rawContext && typeof rawContext === "object" ? boundedString(rawContext.deviceName, 200) : undefined;
      const deviceContext =
        deviceKey && deviceName
          ? {
              deviceKey,
              deviceName,
              vendorId: boundedString(rawContext.vendorId, 16),
              productId: boundedString(rawContext.productId, 16),
            }
          : undefined;
      const result = await handleHoneypotCommand(commandText, keyTimestamps, deviceContext);
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  app.post("/api/incidents/explain", async (req, res, next) => {
    try {
      const body = req.body as Record<string, unknown>;
      const summary = typeof body.summary === "string" ? body.summary.slice(0, 1000) : "";
      const score = typeof body.score === "number" ? Math.min(100, Math.max(0, body.score)) : NaN;
      const rawReasons = Array.isArray(body.reasons) ? body.reasons.slice(0, 30) : [];
      const reasons = rawReasons.flatMap((value, index) => {
        if (!value || typeof value !== "object") return [];
        const finding = value as Record<string, unknown>;
        if (typeof finding.label !== "string") return [];
        return [{
          ruleId: typeof finding.ruleId === "string" ? finding.ruleId.slice(0, 100) : `frontend-${index + 1}`,
          label: finding.label.slice(0, 500),
          points: typeof finding.points === "number" ? Math.min(100, Math.max(0, finding.points)) : 0,
        }];
      });
      if (body.category !== "transaction_tampering" || !summary || !Number.isFinite(score)) {
        res.status(400).json({ error: "A valid transaction-tampering incident is required" });
        return;
      }
      res.json(await generateExplanation({ category: "transaction_tampering", summary, score, reasons }));
    } catch (err) {
      next(err);
    }
  });

  app.post("/api/incidents/:id/explain", async (req, res, next) => {
    try {
      const incidents = await getIncidents();
      const incident = incidents.find((i) => i.id === req.params.id);
      if (!incident) {
        res.status(404).json({ error: "Incident not found" });
        return;
      }
      const explanation = await generateExplanation(incident);
      await updateIncident(incident.id, { explanation });
      res.json(explanation);
    } catch (err) {
      next(err);
    }
  });

  app.post("/api/incidents/:id/remediate", async (req, res, next) => {
    try {
      const incidents = await getIncidents();
      const incident = incidents.find((i) => i.id === req.params.id);
      if (!incident) {
        res.status(404).json({ error: "Incident not found" });
        return;
      }
      if (!incident.remediation?.available || incident.remediation.applied) {
        res.status(400).json({ error: "No pending remediation available for this incident" });
        return;
      }

      let result: { ok: boolean; message: string };
      if (incident.remediation.action === "terminate_process" && incident.remediation.pid) {
        result = await terminateProcess(incident.remediation.pid);
      } else if (incident.remediation.action === "eject_device" && incident.remediation.bsdName) {
        result = await ejectUsbDevice(incident.remediation.bsdName);
      } else {
        res.status(400).json({ error: "Remediation action is missing required target information" });
        return;
      }

      const updated = await updateIncident(incident.id, {
        remediation: { ...incident.remediation, applied: result.ok, appliedAt: result.ok ? new Date().toISOString() : null },
      });
      res.json({ ...result, incident: updated });
    } catch (err) {
      next(err);
    }
  });

  app.use(express.static(path.join(__dirname, "../../public")));
  app.use("/demo", express.static(path.join(__dirname, "../../demo")));

  app.use((req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  app.use((err: Error, req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(`[sentinel-agent] ${req.method} ${req.path} -> 500: ${err.message}`);
    res.status(500).json({ error: err.message || "Internal server error" });
  });

  return app;
}

export function startServer() {
  const app = createApp();
  app.listen(SERVER_PORT, SERVER_HOST, () => {
    console.log(`GhostShield command center: http://${SERVER_HOST}:${SERVER_PORT}`);
  });
  return app;
}
