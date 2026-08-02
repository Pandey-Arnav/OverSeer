"use strict";

const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");

const serverRoot = path.resolve(__dirname, "..");
const aegisRoot = path.join(serverRoot, "aegis");
const projectRoot = path.resolve(serverRoot, "..");
const usbAgentPath = path.join(projectRoot, "agent", "windows", "usb-agent.js");
const jacExecutable = process.env.JAC_EXECUTABLE || (process.platform === "win32" ? "jac.exe" : "jac");
const sharedEnvironment = {
  ...process.env,
  GHOSTSHIELD_AGENT_TOKEN: process.env.GHOSTSHIELD_AGENT_TOKEN || crypto.randomBytes(32).toString("hex"),
};
const children = [];
const startupTimers = [];

function start(label, command, args, options = {}) {
  const child = spawn(command, args, {
    cwd: options.cwd || serverRoot,
    env: { ...sharedEnvironment, ...(options.env || {}), PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("error", (error) => {
    console.error(`[ghostshield] Could not start ${label}: ${error.message}`);
    shutdown(1);
  });
  child.on("exit", (code, signal) => {
    if (signal || code === 0) return;
    console.error(`[ghostshield] ${label} exited with code ${code}`);
    shutdown(code || 1);
  });
  children.push(child);
  return child;
}

function shutdown(exitCode = 0) {
  for (const timer of startupTimers) clearTimeout(timer);
  for (const child of children) {
    if (!child.killed) child.kill();
  }
  setTimeout(() => process.exit(exitCode), 50).unref();
}

console.log("[ghostshield] Starting AEGIS ForkGuard on http://127.0.0.1:8012");
start("AEGIS ForkGuard", jacExecutable, ["start", "main.jac", "--port", "8012", "--no_client"], {
  cwd: aegisRoot,
});

console.log("[ghostshield] Starting Sentinel API on http://127.0.0.1:4000");
start("Sentinel API", process.execPath, [path.join(__dirname, "app.js")]);

if (process.platform === "win32" && process.env.GHOSTSHIELD_USB_AGENT !== "0") {
  startupTimers.push(setTimeout(() => {
    console.log("[ghostshield] Starting Windows USB monitor");
    start("Windows USB monitor", process.execPath, [usbAgentPath]);
  }, 750));
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
