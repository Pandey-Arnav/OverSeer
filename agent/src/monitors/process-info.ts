/**
 * Process introspection: resolves a PID to its executable path, code-
 * signing status, and whether it's running from a suspicious location.
 *
 * `codesign -dv` was verified directly against this machine before
 * relying on it: a normally-signed app (e.g. Zoom) exits 0 with an
 * `Authority=` line; a locally-compiled, never-signed binary exits 0 but
 * shows `flags=...(adhoc,linker-signed)` and no `Authority=` (this is the
 * macOS-standard state for ad-hoc/dev binaries since Apple Silicon
 * requires *some* signature to execute at all — NOT inherently
 * suspicious on its own); a binary with its signature stripped exits
 * non-zero with "code object is not signed at all" on stderr — that's
 * the real "unsigned" signal.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { CRITICAL_PROCESS_NAMES, TUNING } from "../shared/constants.ts";
import type { ProcessInfo } from "../shared/types.ts";

const execFileAsync = promisify(execFile);

export function isSuspiciousPath(execPath: string | null): boolean {
  if (!execPath) return false;
  return TUNING.SUSPICIOUS_PATH_PATTERNS.some((re) => re.test(execPath));
}

async function resolveExecPath(pid: number): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("ps", ["-o", "comm=", "-p", String(pid)]);
    const path = stdout.trim();
    return path || null;
  } catch {
    return null; // process likely exited between the lsof snapshot and now
  }
}

interface SignatureStatus {
  signed: boolean | null;
  adhoc: boolean;
}

async function checkSignature(execPath: string): Promise<SignatureStatus> {
  try {
    const { stdout } = await execFileAsync("codesign", ["-dv", "--verbose=2", execPath]);
    return { signed: true, adhoc: /flags=.*adhoc/.test(stdout) };
  } catch (err) {
    const stderr = String((err as { stderr?: string }).stderr || "");
    if (/not signed at all/.test(stderr)) {
      return { signed: false, adhoc: false };
    }
    // Couldn't determine (permissions, race with process exit, etc.) —
    // don't guess; absence of evidence isn't evidence of tampering.
    return { signed: null, adhoc: false };
  }
}

export async function getProcessInfo(pid: number, name: string, user: string): Promise<ProcessInfo> {
  const execPath = await resolveExecPath(pid);
  const sig: SignatureStatus = execPath ? await checkSignature(execPath) : { signed: null, adhoc: false };

  return {
    pid,
    name,
    user,
    execPath,
    signed: sig.signed,
    signedAdhoc: sig.adhoc,
    suspiciousPath: isSuspiciousPath(execPath),
  };
}

/**
 * Whether it's safe to offer "terminate process" as a remediation for
 * this process at all. Root-owned and known-critical system processes
 * are never offered — killing them can crash the session or the
 * machine, and that blast radius is not worth an automated security
 * tool ever risking, even behind a manual confirmation click.
 */
export function isSafeToTerminate(process: ProcessInfo): { safe: boolean; reason: string } {
  if (process.user === "root") {
    return { safe: false, reason: "Process runs as root — terminating system-privileged processes is not offered." };
  }
  if (CRITICAL_PROCESS_NAMES.has(process.name)) {
    return { safe: false, reason: `"${process.name}" is a critical system process — terminating it could crash your session.` };
  }
  return { safe: true, reason: "Process runs under your user account and is not a recognized critical system process." };
}
