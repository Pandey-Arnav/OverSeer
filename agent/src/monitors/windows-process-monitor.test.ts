import test from "node:test";
import assert from "node:assert/strict";
import { isSuspiciousHidSpawn, parseTasklistCsv } from "./windows-process-monitor.ts";

test("tasklist CSV parser extracts image name and PID", () => {
  const processes = parseTasklistCsv([
    '"explorer.exe","4242","Console","1","120,000 K"',
    '"powershell.exe","9001","Console","1","42,000 K"',
  ].join("\r\n"));

  assert.deepEqual(processes, [
    { name: "explorer.exe", pid: 4242 },
    { name: "powershell.exe", pid: 9001 },
  ]);
});

test("shell and script hosts are suspicious immediately after HID attachment", () => {
  for (const name of ["cmd.exe", "PowerShell.exe", "pwsh.exe", "wscript.exe", "mshta.exe", "rundll32.exe"]) {
    assert.equal(isSuspiciousHidSpawn(name), true, name);
  }
});

test("ordinary desktop processes are not called harmful", () => {
  for (const name of ["notepad.exe", "explorer.exe", "msedge.exe"]) {
    assert.equal(isSuspiciousHidSpawn(name), false, name);
  }
});
