#!/usr/bin/env node
// Launcher for the ctfx Go binary. On first run it downloads the release
// binary for this platform from GitHub Releases, verifies it against the
// release checksums.txt, and caches it per version.
"use strict";
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { version } = require("../package.json");
const isWindows = process.platform === "win32";
const goos = { linux: "linux", darwin: "darwin", win32: "windows" }[process.platform];
const goarch = { x64: "amd64", arm64: "arm64" }[process.arch];

function cacheDir() {
  if (process.env.CTFX_CACHE_DIR) return process.env.CTFX_CACHE_DIR;
  if (isWindows) return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "ctfx", "cache");
  if (process.platform === "darwin") return path.join(os.homedir(), "Library", "Caches", "ctfx");
  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "ctfx");
}

async function fetchBytes(url) {
  if (url.startsWith("file://")) return fs.readFileSync(new URL(url));
  const res = await fetch(url, { headers: { "User-Agent": `ctfx-npm/${version}` }, redirect: "follow" });
  if (!res.ok) throw new Error(`GET ${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function download(target) {
  if (!goos || !goarch) {
    throw new Error(`no prebuilt binary for ${process.platform}-${process.arch}; use \`go install github.com/c0dn/ctfx/cmd/ctfx@latest\``);
  }
  const base = process.env.CTFX_DOWNLOAD_BASE || `https://github.com/c0dn/ctfx/releases/download/v${version}`;
  const asset = `ctfx_${goos}_${goarch}${isWindows ? ".exe" : ""}`;
  process.stderr.write(`ctfx: downloading ${asset} v${version}...\n`);
  const [binary, sums] = await Promise.all([fetchBytes(`${base}/${asset}`), fetchBytes(`${base}/checksums.txt`)]);
  const expected = sums
    .toString("utf8")
    .split("\n")
    .map((line) => line.trim().split(/\s+/))
    .find(([, name]) => name === asset)?.[0];
  const actual = crypto.createHash("sha256").update(binary).digest("hex");
  if (!expected || expected !== actual) {
    throw new Error(`checksum mismatch for ${asset} (expected ${expected ?? "none"}, got ${actual})`);
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  // Write then rename so concurrent first runs never see a partial binary.
  const tmp = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, binary, { mode: 0o755 });
  fs.renameSync(tmp, target);
}

async function main() {
  let bin = process.env.CTFX_BINARY;
  if (!bin) {
    bin = path.join(cacheDir(), version, isWindows ? "ctfx.exe" : "ctfx");
    if (!fs.existsSync(bin)) {
      try {
        await download(bin);
      } catch (err) {
        console.error(
          `ctfx: ${err.message}\n` +
            "Download a release from https://github.com/c0dn/ctfx/releases and set CTFX_BINARY to its path,\n" +
            "or behind a proxy run with NODE_USE_ENV_PROXY=1 and HTTPS_PROXY set.",
        );
        process.exit(1);
      }
    }
  }
  const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
  if (result.error) {
    console.error(`ctfx: ${result.error.message}`);
    process.exit(1);
  }
  if (result.signal) process.kill(process.pid, result.signal);
  process.exit(result.status ?? 1);
}

main();
