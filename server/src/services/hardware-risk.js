"use strict";

const WARN_THRESHOLD = 40;
const CONTAIN_THRESHOLD = 70;
const MAX_SCORE = 100;

function count(value) {
  return Number.isInteger(value) && value > 0 ? value : 0;
}

function evaluateHardwareRisk(report) {
  const inventory = report?.inventory || {};
  const defender = report?.defender || {};
  const reasons = [];

  if (count(defender.threatCount) > 0) {
    reasons.push({
      ruleId: "defender-threat-detected",
      label: `Microsoft Defender reported ${count(defender.threatCount)} threat detection(s) on the USB volume`,
      points: 100,
    });
  } else if (defender.available === false || defender.completed === false) {
    reasons.push({
      ruleId: "defender-scan-unavailable",
      label: "Microsoft Defender could not complete the USB scan",
      points: 40,
    });
  }

  if (inventory.autorunPresent === true) {
    reasons.push({ ruleId: "usb-autorun-present", label: "The USB root contains an autorun.inf file", points: 30 });
  }
  if (count(inventory.shortcutCount) > 0) {
    reasons.push({ ruleId: "usb-shortcut-files", label: `The USB contains ${count(inventory.shortcutCount)} Windows shortcut file(s)`, points: 15 });
  }
  if (count(inventory.executableCount) > 0) {
    reasons.push({ ruleId: "usb-executable-files", label: `The USB contains ${count(inventory.executableCount)} executable file(s)`, points: 10 });
  }
  if (count(inventory.scriptCount) > 0) {
    reasons.push({ ruleId: "usb-script-files", label: `The USB contains ${count(inventory.scriptCount)} script file(s)`, points: 10 });
  }
  if (inventory.truncated === true) {
    reasons.push({
      ruleId: "usb-inventory-truncated",
      label: "The privacy-preserving inventory reached its safety limit before examining every entry",
      points: 5,
    });
  }

  const score = Math.min(MAX_SCORE, reasons.reduce((total, reason) => total + reason.points, 0));
  const severity = score >= CONTAIN_THRESHOLD ? "high" : score >= WARN_THRESHOLD ? "medium" : "low";
  const decision = score >= CONTAIN_THRESHOLD
    ? "detected_not_blocked"
    : score >= WARN_THRESHOLD
      ? "warn"
      : "allow";

  return { score, severity, decision, reasons };
}

module.exports = { evaluateHardwareRisk };
