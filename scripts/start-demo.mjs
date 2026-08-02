import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const processes = [
  spawn("npm", ["start"], { cwd: path.join(projectRoot, "agent"), stdio: "inherit" }),
  spawn("npm", ["run", "dev", "--", "--port", "4173"], { cwd: path.join(projectRoot, "apps", "demo-bank"), stdio: "inherit" }),
];

let stopping = false;

function stopAll(signal = "SIGTERM") {
  if (stopping) return;
  stopping = true;
  for (const child of processes) {
    if (!child.killed) child.kill(signal);
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    stopAll(signal);
    process.exit(0);
  });
}

for (const child of processes) {
  child.on("error", (error) => {
    console.error(`Unable to start demo service: ${error.message}`);
    stopAll();
    process.exitCode = 1;
  });
  child.on("exit", (code, signal) => {
    if (stopping) return;
    console.error(`A demo service stopped (${signal ?? `exit ${code ?? 1}`}); shutting down the other service.`);
    stopAll();
    process.exitCode = code ?? 1;
  });
}

console.log("OverSeer demo starting:");
console.log("  Northstar Bank: http://127.0.0.1:4173/demo-bank/");
console.log("  Command Center: http://127.0.0.1:4100/");
