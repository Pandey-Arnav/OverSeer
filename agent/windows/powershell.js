"use strict";

const { execFile } = require("node:child_process");

function runPowerShell(script, options = {}) {
  const command = [
    "$ErrorActionPreference = 'Stop'",
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
    script,
  ].join("\n");
  const encoded = Buffer.from(command, "utf16le").toString("base64");

  return new Promise((resolve, reject) => {
    execFile(
      "powershell.exe",
      ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
      {
        windowsHide: true,
        timeout: options.timeoutMs || 30_000,
        maxBuffer: options.maxBuffer || 4 * 1024 * 1024,
        encoding: "utf8",
      },
      (error, stdout, stderr) => {
        if (error) {
          error.message = `PowerShell command failed (${error.code || "unknown"})`;
          error.stderr = String(stderr || "").slice(0, 500);
          reject(error);
          return;
        }
        resolve(String(stdout || "").trim());
      },
    );
  });
}

async function runPowerShellJson(script, options) {
  const output = await runPowerShell(script, options);
  if (!output) return null;
  const jsonStart = Math.min(
    ...[output.lastIndexOf("\n{"), output.lastIndexOf("\n[")]
      .filter((index) => index >= 0)
      .map((index) => index + 1),
    output.startsWith("{") || output.startsWith("[") ? 0 : Number.POSITIVE_INFINITY,
  );
  const candidate = Number.isFinite(jsonStart) ? output.slice(jsonStart) : output;
  return JSON.parse(candidate);
}

function quotePowerShell(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

module.exports = { runPowerShell, runPowerShellJson, quotePowerShell };
