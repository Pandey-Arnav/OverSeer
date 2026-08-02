"use strict";

/**
 * Centralized Express error handler. Logs enough to debug locally without
 * ever echoing the raw request body (which could, in principle, carry
 * more than the extension is supposed to send — defense in depth).
 */
function errorHandler(err, req, res, _next) {
  const status = err.status || 500;
  console.error(`[sentinel-server] ${req.method} ${req.path} -> ${status}: ${err.message}`);
  res.status(status).json({ error: err.message || "Internal server error" });
}

module.exports = { errorHandler };
