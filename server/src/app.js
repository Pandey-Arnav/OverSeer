"use strict";

require("dotenv").config();

const path = require("node:path");
const express = require("express");
const cors = require("cors");
const explainRouter = require("./routes/explain");
const { errorHandler } = require("./middleware/error-handler");

const app = express();

app.use(cors());
app.use(express.json({ limit: "100kb" })); // incident payloads are metadata-only; small cap on purpose

app.get("/health", (req, res) => {
  res.json({ status: "ok", mockMode: !process.env.OPENAI_API_KEY });
});

app.use("/api/explain", explainRouter);

// Serves the demo pages (demo/*.html) so the whole demo runs off one
// `npm start` — http://localhost:PORT/demo/safe-test.html etc.
app.use("/demo", express.static(path.join(__dirname, "../../demo")));

app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use(errorHandler);

const PORT = process.env.PORT || 4000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Sentinel server listening on http://localhost:${PORT}`);
    console.log(`Mode: ${process.env.OPENAI_API_KEY ? "live AI explanations" : "mock explanations (no OPENAI_API_KEY set)"}`);
  });
}

module.exports = app;
