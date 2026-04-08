import { readFile, writeFile } from "node:fs/promises";

const nextVersion = process.argv[2];

if (!nextVersion) {
  console.error("Usage: npm run release:prepare -- <version>");
  process.exit(1);
}

const versionPattern = /^\d+\.\d+\.\d+$/;
if (!versionPattern.test(nextVersion)) {
  console.error(`Invalid version '${nextVersion}'. Use semver like 1.2.3`);
  process.exit(1);
}

const packagePath = new URL("../package.json", import.meta.url);
const manifestPath = new URL("../extension/manifest.json", import.meta.url);

const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
const extensionManifest = JSON.parse(await readFile(manifestPath, "utf8"));

packageJson.version = nextVersion;
extensionManifest.version = nextVersion;

await writeFile(packagePath, `${JSON.stringify(packageJson, null, 2)}\n`);
await writeFile(manifestPath, `${JSON.stringify(extensionManifest, null, 2)}\n`);

console.log(`Prepared release version ${nextVersion}`);
