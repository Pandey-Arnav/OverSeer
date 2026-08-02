"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { UsbAgent } = require("./usb-agent");

test("scans a newly discovered USB once and posts only the summarized report", async () => {
  const reports = [];
  const heartbeats = [];
  const device = {
    deviceIdHash: "b".repeat(64),
    driveLetter: "E:\\",
    displayName: "Test USB",
    fileSystem: "NTFS",
    sizeBytes: 4096,
    busType: "USB",
  };
  const client = {
    heartbeat: async (value) => heartbeats.push(value),
    reportIncident: async (value) => {
      reports.push(value);
      return { incident: { score: 0, decision: "allow" } };
    },
  };
  const agent = new UsbAgent({
    identity: "a".repeat(64),
    client,
    discover: async () => [device],
    inventory: async () => ({
      totalFiles: 3,
      executableCount: 0,
      scriptCount: 0,
      shortcutCount: 0,
      archiveCount: 0,
      autorunPresent: false,
      truncated: false,
    }),
    scan: async () => ({
      available: true,
      completed: true,
      threatCount: 0,
      remediationSuccessful: true,
      status: "completed",
    }),
  });

  await agent.start({ once: true });
  assert.equal(reports.length, 1);
  assert.equal(reports[0].device.driveLetter, "E:\\");
  assert.equal(reports[0].inventory.totalFiles, 3);
  assert.equal(Object.hasOwn(reports[0], "files"), false);
  assert.ok(heartbeats.length >= 2);
});
