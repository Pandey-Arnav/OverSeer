/**
 * Sentinel Agent — remediation actions.
 *
 * Two real, verified interventions, both requiring an explicit dashboard
 * click — nothing here ever runs automatically. Killing a process or
 * ejecting a drive is much higher-stakes than the browser prototype's
 * "block one HTTP request", so this project deliberately has no
 * auto-block tier at all: every "blocked" decision means "a safe
 * remediation is available and awaiting your confirmation," not "already
 * done."
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function terminateProcess(pid: number): Promise<{ ok: boolean; message: string }> {
  try {
    process.kill(pid, "SIGTERM");
    return { ok: true, message: `Sent SIGTERM to process ${pid}.` };
  } catch (err) {
    return { ok: false, message: `Could not terminate process ${pid}: ${(err as Error).message}` };
  }
}

export async function ejectUsbDevice(bsdName: string): Promise<{ ok: boolean; message: string }> {
  try {
    if (process.platform === "win32") {
      if (!/^[A-Za-z]:$/.test(bsdName)) return { ok: false, message: "Invalid removable-drive identifier." };
      const script = `$drive = (New-Object -ComObject Shell.Application).NameSpace(17).ParseName('${bsdName}'); if (-not $drive) { throw 'Drive not found' }; $drive.InvokeVerb('Eject')`;
      await execFileAsync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], { windowsHide: true });
    } else {
      await execFileAsync("diskutil", ["eject", bsdName]);
    }
    return { ok: true, message: `Ejected ${bsdName}.` };
  } catch (err) {
    const stderr = String((err as { stderr?: string }).stderr || (err as Error).message);
    return { ok: false, message: `Could not eject ${bsdName}: ${stderr.trim()}` };
  }
}
