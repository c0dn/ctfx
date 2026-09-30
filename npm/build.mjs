#!/usr/bin/env node
// Builds the @c0dn/ctfx npm package into dist/npm/ctfx. It contains only the
// launcher; the binary is downloaded from the matching GitHub Release on first
// run, so the release assets must be published before the npm package.
// Usage: node npm/build.mjs <version> [--pack]
import { execFileSync } from "node:child_process";
import { cpSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const version = args.find((a) => !a.startsWith("--"))?.replace(/^v/, "");
if (!version) {
  console.error("usage: node npm/build.mjs <version> [--pack]");
  process.exit(2);
}
const out = join(root, "dist", "npm");
const dir = join(out, "ctfx");
rmSync(out, { recursive: true, force: true });
cpSync(join(root, "npm/ctfx"), dir, { recursive: true });
cpSync(join(root, "README.md"), join(dir, "README.md"));
cpSync(join(root, "LICENSE"), join(dir, "LICENSE"));
const pkg = JSON.parse(readFileSync(join(root, "npm/ctfx/package.json"), "utf8"));
pkg.version = version;
writeFileSync(join(dir, "package.json"), JSON.stringify(pkg, null, 2) + "\n");
console.log(`built @c0dn/ctfx ${version}`);
if (args.includes("--pack")) {
  execFileSync("npm", ["pack", "--pack-destination", out], { cwd: dir, stdio: ["ignore", "ignore", "inherit"] });
  console.log(`packed into ${out}`);
}
