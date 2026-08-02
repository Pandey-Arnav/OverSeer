"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const EXECUTABLE_EXTENSIONS = new Set([".exe", ".dll", ".com", ".msi", ".scr", ".cpl"]);
const SCRIPT_EXTENSIONS = new Set([".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta"]);
const ARCHIVE_EXTENSIONS = new Set([".zip", ".rar", ".7z", ".iso", ".img", ".cab"]);

function classifyName(name) {
  const normalized = String(name || "").toLowerCase();
  const extension = path.extname(normalized);
  return {
    executable: EXECUTABLE_EXTENSIONS.has(extension),
    script: SCRIPT_EXTENSIONS.has(extension),
    shortcut: extension === ".lnk",
    archive: ARCHIVE_EXTENSIONS.has(extension),
    autorun: normalized === "autorun.inf",
  };
}

async function inventoryVolume(root, options = {}) {
  if (!/^[A-Z]:\\$/i.test(root)) throw new Error("Inventory root must be a drive root");
  const maxFiles = options.maxFiles || 25_000;
  const maxDepth = options.maxDepth || 12;
  const maxDurationMs = options.maxDurationMs || 120_000;
  const startedAt = Date.now();
  const stack = [{ directory: root, depth: 0 }];
  const result = {
    totalFiles: 0,
    executableCount: 0,
    scriptCount: 0,
    shortcutCount: 0,
    archiveCount: 0,
    autorunPresent: false,
    truncated: false,
  };

  while (stack.length) {
    if (result.totalFiles >= maxFiles || Date.now() - startedAt >= maxDurationMs) {
      result.truncated = true;
      break;
    }
    const current = stack.pop();
    let entries;
    try {
      entries = await fs.readdir(current.directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (current.depth < maxDepth) {
          stack.push({ directory: path.join(current.directory, entry.name), depth: current.depth + 1 });
        } else {
          result.truncated = true;
        }
        continue;
      }
      if (!entry.isFile()) continue;
      result.totalFiles += 1;
      const classification = classifyName(entry.name);
      if (classification.executable) result.executableCount += 1;
      if (classification.script) result.scriptCount += 1;
      if (classification.shortcut) result.shortcutCount += 1;
      if (classification.archive) result.archiveCount += 1;
      if (current.depth === 0 && classification.autorun) result.autorunPresent = true;
      if (result.totalFiles >= maxFiles) {
        result.truncated = true;
        break;
      }
    }
  }

  return result;
}

module.exports = { inventoryVolume, classifyName };
