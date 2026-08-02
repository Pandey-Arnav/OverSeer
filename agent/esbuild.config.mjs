import * as esbuild from "esbuild";
import { fileURLToPath } from "node:url";

const watch = process.argv.includes("--watch");

// Only the dashboard runs in a real browser and needs bundling — the
// daemon itself (src/index.ts and everything it imports) runs directly
// via Node's native TypeScript support, no build step required.
const config = {
  entryPoints: [fileURLToPath(new URL("./src/dashboard/dashboard.ts", import.meta.url))],
  outfile: fileURLToPath(new URL("./public/dashboard.js", import.meta.url)),
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
