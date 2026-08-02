/**
 * Sentinel Agent — BadUSB honeypot keystroke timing analysis.
 *
 * Pure, side-effect-free functions so they're independently testable —
 * same philosophy as risk/rules.ts. The honeypot terminal (public/
 * honeypot.html) captures a keydown timestamp for every key in one
 * submitted line and posts the array here; this module decides whether
 * that timing is human-plausible or looks like scripted HID injection
 * (a Flipper Zero / Rubber Ducky-style BadUSB replaying a fixed-delay
 * script) before the command is ever allowed to run for real.
 */
import { TUNING } from "../shared/constants.ts";

export interface KeystrokeStats {
  meanIntervalMs: number;
  stdDevMs: number;
  keyCount: number;
}

/** Computes timing stats from an ordered list of keydown timestamps (ms). Returns null if there are fewer than 2 keys (no intervals to measure). */
export function computeKeystrokeStats(timestamps: number[]): KeystrokeStats | null {
  if (!Array.isArray(timestamps) || timestamps.length < 2) return null;

  const intervals: number[] = [];
  for (let i = 1; i < timestamps.length; i++) {
    intervals.push(timestamps[i]! - timestamps[i - 1]!);
  }

  const mean = intervals.reduce((sum, v) => sum + v, 0) / intervals.length;
  const variance = intervals.reduce((sum, v) => sum + (v - mean) ** 2, 0) / intervals.length;

  return {
    meanIntervalMs: mean,
    stdDevMs: Math.sqrt(variance),
    keyCount: timestamps.length,
  };
}

/**
 * A scripted HID injection tool replays a pre-programmed sequence at a
 * near-uniform, very fast rate — human typing has natural jitter and
 * rarely sustains sub-30ms average keystroke intervals. Requires a
 * minimum sample size so a short burst (e.g. "ls") doesn't get judged.
 */
export function isBotLikeTiming(stats: KeystrokeStats): boolean {
  return (
    stats.keyCount >= TUNING.BADUSB_MIN_KEY_COUNT &&
    stats.meanIntervalMs <= TUNING.BADUSB_MAX_MEAN_INTERVAL_MS &&
    stats.stdDevMs <= TUNING.BADUSB_MAX_STDDEV_MS
  );
}
