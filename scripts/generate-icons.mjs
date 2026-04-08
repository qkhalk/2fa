import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

import sharp from "sharp";

const source = resolve("icon.svg");
const appOut = resolve("icons");
const extensionOut = resolve("extension", "icons");

await mkdir(appOut, { recursive: true });
await mkdir(extensionOut, { recursive: true });

await Promise.all([
  sharp(source).resize(192, 192).png().toFile(resolve(appOut, "icon-192.png")),
  sharp(source).resize(512, 512).png().toFile(resolve(appOut, "icon-512.png")),
  sharp(source).resize(180, 180).png().toFile(resolve(appOut, "apple-touch-icon.png")),
  sharp(source).resize(32, 32).png().toFile(resolve(appOut, "favicon-32x32.png")),
  sharp(source).resize(16, 16).png().toFile(resolve(appOut, "favicon-16x16.png")),
  sharp(source).resize(16, 16).png().toFile(resolve(extensionOut, "icon-16.png")),
  sharp(source).resize(32, 32).png().toFile(resolve(extensionOut, "icon-32.png")),
  sharp(source).resize(48, 48).png().toFile(resolve(extensionOut, "icon-48.png")),
  sharp(source).resize(128, 128).png().toFile(resolve(extensionOut, "icon-128.png")),
]);

console.log("Generated raster icons for PWA and extension");
