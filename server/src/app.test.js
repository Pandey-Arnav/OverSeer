"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isAllowedOrigin } = require("./app");

test("allows only local dashboards, extension origins, and non-browser clients", () => {
  assert.equal(isAllowedOrigin(undefined), true);
  assert.equal(isAllowedOrigin("http://127.0.0.1:4000"), true);
  assert.equal(isAllowedOrigin("http://localhost:8020"), true);
  assert.equal(isAllowedOrigin("chrome-extension://abcdefghijklmnop"), true);
  assert.equal(isAllowedOrigin("https://attacker.example"), false);
  assert.equal(isAllowedOrigin("null"), false);
});
