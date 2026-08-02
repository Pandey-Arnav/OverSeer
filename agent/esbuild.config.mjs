import * as esbuild from "esbuild";
import { fileURLToPath } from "node:url";

const watch = process.argv.includes("--watch");

// Only browser-side entry points need bundling — the daemon itself
// (src/index.ts and everything it imports) runs directly via Node's
// native TypeScript support, no build step required.
const config = {
  entryPoints: [
    { in: fileURLToPath(new URL("./src/dashboard/dashboard.ts", import.meta.url)), out: "dashboard" },
    { in: fileURLToPath(new URL("./src/honeypot/terminal-client.ts", import.meta.url)), out: "honeypot" },
  ],
  outdir: fileURLToPath(new URL("./public", import.meta.url)),
  bundle: true,
  format: "iife",
  target: "es2022",
  sourcemap: true,
  logLevel: "info",
};

if (watch) {
  const ctx = await esbuild.context(config);
  await ctx.watch();
  console.log("Watching dashboard for changes...");
} else {
  await esbuild.build(config);
}
