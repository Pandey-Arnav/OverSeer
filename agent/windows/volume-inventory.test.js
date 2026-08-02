"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyName } = require("./volume-inventory");

test("classifies executable, script, shortcut, archive, and autorun names", () => {
  assert.equal(classifyName("installer.EXE").executable, true);
  assert.equal(classifyName("setup.ps1").script, true);
  assert.equal(classifyName("invoice.lnk").shortcut, true);
  assert.equal(classifyName("payload.zip").archive, true);
  assert.equal(classifyName("AUTORUN.INF").autorun, true);
  assert.deepEqual(classifyName("photo.jpg"), {
    executable: false,
    script: false,
    shortcut: false,
    archive: false,
    autorun: false,
  });
});
