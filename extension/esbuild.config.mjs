import * as esbuild from "esbuild";

const watch = process.argv.includes("--watch");

const commonOptions = {
  bundle: true,
  format: "iife",
  target: "chrome111",
  sourcemap: true,
  logLevel: "info",
};

const builds = [
  { ...commonOptions, entryPoints: ["src/background/service-worker.ts"], outfile: "dist/background.js" },
  { ...commonOptions, entryPoints: ["src/content/content-script.ts"], outfile: "dist/content.js" },
];

if (watch) {
  const contexts = await Promise.all(builds.map((cfg) => esbuild.context(cfg)));
  await Promise.all(contexts.map((ctx) => ctx.watch()));
  console.log("Watching for changes...");
} else {
  for (const cfg of builds) await esbuild.build(cfg);
}
