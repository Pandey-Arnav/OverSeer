"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { validateHardwareReport, sanitizedHardwareReport, requireAgentToken } = require("./hardware");

function validReport() {
  return {
    agentId: "a".repeat(64),
    device: {
      deviceIdHash: "b".repeat(64),
      driveLetter: "E:\\",
      displayName: "Demo USB",
      fileSystem: "NTFS",
      sizeBytes: 4096,
    },
    inventory: {
      totalFiles: 4,
      executableCount: 1,
      scriptCount: 0,
      shortcutCount: 0,
      archiveCount: 0,
      autorunPresent: false,
      truncated: false,
    },
    defender: {
      available: true,
      completed: true,
      threatCount: 0,
      remediationSuccessful: true,
      status: "completed",
    },
  };
}

test("accepts bounded privacy-preserving USB scan summaries", () => {
  assert.equal(validateHardwareReport(validReport()), null);
});

test("rejects raw file paths and device serial numbers", () => {
  assert.match(validateHardwareReport({ ...validReport(), paths: ["E:\\private.txt"] }), /must not include/);
  assert.match(validateHardwareReport({ ...validReport(), device: { ...validReport().device, serialNumber: "secret" } }), /must not include/);
});

test("sanitizes hardware metadata and never forwards unexpected keys", () => {
  const sanitized = sanitizedHardwareReport({ ...validReport(), unexpected: "drop-me" });
  assert.equal(sanitized.device.busType, "USB");
  assert.equal(Object.hasOwn(sanitized, "unexpected"), false);
});

test("requires the per-run USB agent token when configured", () => {
  const previous = process.env.GHOSTSHIELD_AGENT_TOKEN;
  process.env.GHOSTSHIELD_AGENT_TOKEN = "expected-secret";
  let nextCalled = false;
  let responseStatus = null;
  const response = {
    status(value) { responseStatus = value; return this; },
    json() { return this; },
  };
  try {
    requireAgentToken({ get: () => "wrong-secret" }, response, () => { nextCalled = true; });
    assert.equal(responseStatus, 401);
    assert.equal(nextCalled, false);
    requireAgentToken({ get: () => "expected-secret" }, response, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
  } finally {
    if (previous === undefined) delete process.env.GHOSTSHIELD_AGENT_TOKEN;
    else process.env.GHOSTSHIELD_AGENT_TOKEN = previous;
  }
});
