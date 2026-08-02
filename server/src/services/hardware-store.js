"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");

const DEFAULT_LIMIT = 500;
const MAX_FILE_BYTES = 5 * 1024 * 1024;

class HardwareStore {
  constructor(options = {}) {
    const dataDirectory = options.dataDirectory
      || process.env.GHOSTSHIELD_DATA_DIR
      || path.resolve(__dirname, "../../.data");
    this.filePath = path.join(dataDirectory, "hardware-incidents.jsonl");
    this.limit = options.limit || DEFAULT_LIMIT;
  }

  async append(incident) {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.appendFile(this.filePath, `${JSON.stringify(incident)}\n`, "utf8");
    await this.compactIfNeeded();
    return incident;
  }

  async list(limit = this.limit) {
    let contents;
    try {
      contents = await fs.readFile(this.filePath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw error;
    }

    return contents
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-Math.max(1, Math.min(limit, this.limit)))
      .reverse()
      .map((line) => JSON.parse(line));
  }

  async clear() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, "", "utf8");
  }

  async compactIfNeeded() {
    const stat = await fs.stat(this.filePath);
    if (stat.size <= MAX_FILE_BYTES) return;
    const incidents = (await this.list(this.limit)).reverse();
    const compacted = incidents.map((incident) => JSON.stringify(incident)).join("\n");
    await fs.writeFile(this.filePath, compacted ? `${compacted}\n` : "", "utf8");
  }
}

module.exports = { HardwareStore };
