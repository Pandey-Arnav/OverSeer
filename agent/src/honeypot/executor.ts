/**
 * Sentinel Agent — BadUSB honeypot command executor.
 *
 * Runs a command that has cleared both honeypot checks (human-plausible
 * timing, classifier says not malicious) for real, on the real machine,
 * as the current user — this is a deliberate design choice: the
 * honeypot is a gate in front of a real shell, not a pure decoy, so
 * legitimate fast typing or automation isn't broken.
 * CATASTROPHIC_COMMAND_PATTERNS is a hard-coded backstop that blocks
 * unconditionally regardless of what the timing/classifier checks
 * concluded, since a command that passes both now really executes.
 */
import { exec } from "node:child_process";
import os from "node:os";
import { CATASTROPHIC_COMMAND_PATTERNS } from "../shared/constants.ts";

export function isCatastrophicCommand(commandText: string): boolean {
  return CATASTROPHIC_COMMAND_PATTERNS.some((pattern) => pattern.test(commandText));
}

export interface ExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/** Runs commandText for real via the user's shell. Never call this without checking isCatastrophicCommand() first. */
export function executeHoneypotCommand(commandText: string): Promise<ExecutionResult> {
  return new Promise((resolve) => {
    exec(commandText, { cwd: os.homedir(), timeout: 15_000, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      const code = (err as NodeJS.ErrnoException | null)?.code;
      const exitCode = !err ? 0 : typeof code === "number" ? code : null;
      resolve({ stdout, stderr: stderr || (err ? err.message : ""), exitCode });
    });
  });
}
