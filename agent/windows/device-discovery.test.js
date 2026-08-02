"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { normalizeVolumes } = require("./device-discovery");

test("normalizes USB volumes and hashes the raw hardware identity", () => {
  const volumes = normalizeVolumes([{
    rawIdentity: "SERIAL-SECRET|disk-4|partition-1",
    driveLetter: "e:\\",
    volumeLabel: "Demo USB",
    fileSystem: "NTFS",
    sizeBytes: 1024,
    manufacturer: "Example",
    model: "Flash Drive",
  }]);

  assert.equal(volumes.length, 1);
  assert.equal(volumes[0].driveLetter, "E:\\");
  assert.equal(volumes[0].displayName, "Demo USB");
  assert.match(volumes[0].deviceIdHash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(volumes[0]), /SERIAL-SECRET/);
});

test("drops malformed non-root drive values", () => {
  assert.deepEqual(normalizeVolumes([{ driveLetter: "C:\\Users", rawIdentity: "bad" }]), []);
});
