import { build } from "esbuild";

await build({
  entryPoints: {
    "app.bundle": "app.js",
    "extension/popup.bundle": "extension/popup.js",
  },
  bundle: true,
  format: "esm",
  target: ["chrome114", "safari16", "firefox115"],
  sourcemap: false,
  outdir: ".",
  logLevel: "info",
});
