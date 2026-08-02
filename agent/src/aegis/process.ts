import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type ChildProcess } from "node:child_process";

let child: ChildProcess | null = null;

function jacExecutable(): string {
  if (process.env["JAC_EXECUTABLE"]) return process.env["JAC_EXECUTABLE"];
  if (process.platform === "win32" && process.env["LOCALAPPDATA"]) {
    const installed = path.join(process.env["LOCALAPPDATA"], "GhostShield", "venv", "Scripts", "jac.exe");
    if (existsSync(installed)) return installed;
  }
  return process.platform === "win32" ? "jac.exe" : "jac";
}

export function startAegisService(): ChildProcess | null {
  if (process.env["GHOSTSHIELD_AEGIS_DISABLED"] === "1") return null;
  const moduleDir = path.dirname(fileURLToPath(import.meta.url));
  const aegisRoot = path.resolve(moduleDir, "../../aegis");

  child = spawn(jacExecutable(), ["start", "main.jac", "--port", "8012", "--no_client"], {
    cwd: aegisRoot,
    env: { ...process.env, PYTHONUTF8: "1", PYTHONIOENCODING: "utf-8" },
    stdio: "inherit",
    windowsHide: true,
  });
  child.on("error", (error) => {
    console.warn(`[GhostShield] AEGIS could not start: ${error.message}. Sentinel monitoring will continue.`);
  });
  child.on("exit", (code) => {
    if (code && code !== 0) console.warn(`[GhostShield] AEGIS exited with code ${code}. Sentinel monitoring remains active.`);
  });
  return child;
}

export function stopAegisService(): void {
  if (child && !child.killed) child.kill();
  child = null;
}
