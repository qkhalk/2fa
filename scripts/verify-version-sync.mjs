import { readFile } from "node:fs/promises";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const extensionManifest = JSON.parse(await readFile(new URL("../extension/manifest.json", import.meta.url), "utf8"));

if (!packageJson.version) {
  console.error("package.json is missing a version field");
  process.exit(1);
}

if (packageJson.version !== extensionManifest.version) {
  console.error(`Version mismatch: package.json=${packageJson.version}, extension/manifest.json=${extensionManifest.version}`);
  process.exit(1);
}

console.log(`Version sync OK: ${packageJson.version}`);
