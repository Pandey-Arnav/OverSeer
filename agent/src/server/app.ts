import "dotenv/config";

import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import { SERVER_PORT } from "../shared/constants.ts";
import { addIncident, clearIncidents, getIncidents, getSettings, updateIncident, updateSettings } from "../storage/store.ts";
import { generateExplanation } from "./ai-explanation.ts";
import { ejectUsbDevice, terminateProcess } from "../remediation/actions.ts";
import { evaluateRisk, buildIncident } from "../risk/engine.ts";
import type { EventCategory, SentinelEvent } from "../shared/types.ts";

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
    res.json(await updateSettings(patch));
  });

  // Categories external sources (the browser extension, the dashboard's
  // own keystroke honeypot) are allowed to report. network_connection and
  // usb_* are deliberately excluded — those only ever come from this
  // agent's own monitors, which have real OS-level evidence behind them;
  // accepting them here would let anything on localhost forge incidents
  // for categories it has no way to actually observe.
  const REPORTABLE_CATEGORIES = new Set<EventCategory>(["transaction_tampering", "suspicious_script", "usb_badusb_keystroke"]);

  function validateReportedEvent(body: unknown): string | null {
    if (!body || typeof body !== "object") return "Request body must be a JSON object";
    const b = body as Record<string, unknown>;
    if (typeof b["category"] !== "string" || !REPORTABLE_CATEGORIES.has(b["category"] as EventCategory)) {
      return `category must be one of: ${[...REPORTABLE_CATEGORIES].join(", ")}`;
    }
    if (b["category"] === "transaction_tampering" && typeof b["pageOrigin"] !== "string") {
      return "pageOrigin is required for transaction_tampering events";
    }
    return null;
  }

  app.post("/api/report-event", async (req, res, next) => {
    try {
      const validationError = validateReportedEvent(req.body);
      if (validationError) {
        res.status(400).json({ error: validationError });
        return;
      }

      const settings = await getSettings();
      if (!settings.protectionEnabled) {
        res.json({ score: 0, severity: "low", decision: "allow", reasons: [], incidentId: null });
        return;
      }

      const event: SentinelEvent = { ...req.body, timestamp: Date.now() };
      const evaluation = evaluateRisk(event, {}, true);
      const incident = buildIncident(event, evaluation, null, randomUUID(), new Date().toISOString());
      await addIncident(incident);

      res.json({ score: evaluation.score, severity: evaluation.severity, decision: evaluation.decision, reasons: evaluation.reasons, incidentId: incident.id });
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

  // Serves the demo pages (../../demo/*.html) so the whole demo runs off
  // one `npm start` — http://localhost:4100/demo/bank-transfer-test.html
  app.use("/demo", express.static(path.join(__dirname, "../../../demo")));

  app.use(express.static(path.join(__dirname, "../../public")));

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
  app.listen(SERVER_PORT, () => {
    console.log(`Sentinel Agent dashboard: http://localhost:${SERVER_PORT}`);
  });
  return app;
}
