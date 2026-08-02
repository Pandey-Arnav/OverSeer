"use strict";

require("dotenv").config();

const path = require("node:path");
const express = require("express");
const cors = require("cors");
const explainRouter = require("./routes/explain");
const { router: forkGuardRouter } = require("./routes/forkguard");
const { router: hardwareRouter } = require("./routes/hardware");
const { errorHandler } = require("./middleware/error-handler");

const app = express();

function isAllowedOrigin(origin) {
  if (!origin) return true;
  if (origin.startsWith("chrome-extension://")) return true;
  try {
    const parsed = new URL(origin);
    return parsed.protocol === "http:" && ["127.0.0.1", "localhost"].includes(parsed.hostname);
  } catch {
    return false;
  }
}

app.use(cors({ origin: (origin, callback) => callback(null, isAllowedOrigin(origin)) }));
app.use(express.json({ limit: "100kb" })); // incident payloads are metadata-only; small cap on purpose

app.get("/health", (req, res) => {
  res.json({ status: "ok", mockMode: !process.env.OPENAI_API_KEY });
});

app.use("/api/explain", explainRouter);
app.use("/api/forkguard", forkGuardRouter);
app.use("/api/hardware", hardwareRouter);

app.use("/ghostshield", express.static(path.join(__dirname, "../../extension")));
app.get("/ghostshield", (_req, res) => {
  res.redirect("/ghostshield/dashboard/dashboard.html");
});

// Serves the demo pages (demo/*.html) so the whole demo runs off one
// `npm start` — http://localhost:PORT/demo/safe-test.html etc.
app.use("/demo", express.static(path.join(__dirname, "../../demo")));

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use(errorHandler);

const PORT = process.env.PORT || 4000;

if (require.main === module) {
  app.listen(PORT, "127.0.0.1", () => {
    console.log(`Sentinel server listening on http://127.0.0.1:${PORT}`);
    console.log(`Mode: ${process.env.OPENAI_API_KEY ? "live AI explanations" : "mock explanations (no OPENAI_API_KEY set)"}`);
  });
}

module.exports = app;
module.exports.isAllowedOrigin = isAllowedOrigin;
