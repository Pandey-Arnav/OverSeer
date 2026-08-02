import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface WindowsProcessSnapshot {
  pid: number;
  name: string;
}

const SUSPICIOUS_HID_CHILDREN = new Set([
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "certutil.exe",
  "bitsadmin.exe",
  "reg.exe",
  "schtasks.exe",
]);

function parseTasklistCsvLine(line: string): string[] {
  const fields: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < line.length; index++) {
    const character = line[index]!;
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        field += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (character === "," && !quoted) {
      fields.push(field);
      field = "";
    } else {
      field += character;
    }
  }
  fields.push(field);
  return fields;
}

export function parseTasklistCsv(stdout: string): WindowsProcessSnapshot[] {
  const processes: WindowsProcessSnapshot[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const fields = parseTasklistCsvLine(line);
    const pid = Number(fields[1]);
    if (!fields[0] || !Number.isInteger(pid) || pid <= 0) continue;
    processes.push({ name: fields[0], pid });
  }
  return processes;
}

export function isSuspiciousHidSpawn(processName: string): boolean {
  return SUSPICIOUS_HID_CHILDREN.has(processName.toLowerCase());
}

let scanInFlight: Promise<WindowsProcessSnapshot[]> | null = null;

export async function listWindowsProcesses(): Promise<WindowsProcessSnapshot[]> {
  if (process.platform !== "win32") return [];
  if (scanInFlight) return scanInFlight;
  scanInFlight = execFileAsync("tasklist.exe", ["/fo", "csv", "/nh"], {
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
  }).then(({ stdout }) => parseTasklistCsv(stdout));
  try {
    return await scanInFlight;
  } finally {
    scanInFlight = null;
  }
}
