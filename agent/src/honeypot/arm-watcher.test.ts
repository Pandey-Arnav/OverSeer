import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { windowsEdgeCandidates } from "./arm-watcher.ts";

test("Windows honeypot launcher checks system and per-user Edge locations", () => {
  const candidates = windowsEdgeCandidates({
    "ProgramFiles(x86)": "C:\\Program Files (x86)",
    ProgramFiles: "C:\\Program Files",
    LOCALAPPDATA: "C:\\Users\\tester\\AppData\\Local",
  });

  assert.deepEqual(candidates, [
    path.join("C:\\Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
    path.join("C:\\Program Files", "Microsoft", "Edge", "Application", "msedge.exe"),
    path.join("C:\\Users\\tester\\AppData\\Local", "Microsoft", "Edge", "Application", "msedge.exe"),
    "msedge.exe",
  ]);
});

test("Windows honeypot launcher always retains the PATH fallback", () => {
  assert.deepEqual(windowsEdgeCandidates({}), ["msedge.exe"]);
});
