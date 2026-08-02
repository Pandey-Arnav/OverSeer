import test from "node:test";
import assert from "node:assert/strict";
import { computeKeystrokeStats, isBotLikeTiming } from "./keystroke-honeypot.ts";

test("computeKeystrokeStats returns null with fewer than 2 timestamps", () => {
  assert.equal(computeKeystrokeStats([]), null);
  assert.equal(computeKeystrokeStats([100]), null);
});

test("computeKeystrokeStats computes mean and stddev of intervals", () => {
  // Perfectly uniform 10ms intervals across 5 keys.
  const stats = computeKeystrokeStats([0, 10, 20, 30, 40]);
  assert.ok(stats);
  assert.equal(stats!.keyCount, 5);
  assert.equal(stats!.meanIntervalMs, 10);
  assert.equal(stats!.stdDevMs, 0);
});

test("isBotLikeTiming flags fast, uniform scripted-looking input", () => {
  const stats = computeKeystrokeStats([0, 15, 30, 45, 60, 75, 90]); // 7 keys, 15ms apart, zero jitter
  assert.ok(stats);
  assert.equal(isBotLikeTiming(stats!), true);
});

test("isBotLikeTiming does not flag realistic human typing", () => {
  // Human-ish: ~150ms apart with real jitter.
  const timestamps = [0, 140, 310, 460, 620, 800];
  const stats = computeKeystrokeStats(timestamps);
  assert.ok(stats);
  assert.equal(isBotLikeTiming(stats!), false);
});

test("isBotLikeTiming does not judge on too few keys even if fast and uniform", () => {
  const stats = computeKeystrokeStats([0, 10, 20]); // only 3 keys
  assert.ok(stats);
  assert.equal(isBotLikeTiming(stats!), false);
});
