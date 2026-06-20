#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Keeps the per-platform binary packages under sdk/node/platform-packages/* version-
// locked to the meta package (sdk/node/package.json).
//
//   node scripts/sync-platform-package-versions.js          # stamp to meta version
//   node scripts/sync-platform-package-versions.js --check   # verify, exit 1 on drift
//
// The platform packages are pinned with EXACT versions in the meta package's
// optionalDependencies, so any drift breaks `require.resolve` of the optional
// dependency. The --check mode is wired into CI to fail fast on drift.
//
// The core logic is the exported `syncPlatformPackageVersions({ repoRoot, check })`
// function, which is pure with respect to process state (it never calls
// process.exit and returns a structured result), so it can be unit-tested
// against a temp fixture. `process.exit` / console output live only in the CLI
// wrapper at the bottom.

const { readFileSync, writeFileSync, readdirSync, existsSync } = require("fs");
const { join } = require("path");

/** Platform package directory names we manage: `<os>-<arch>`. */
const PLATFORM_DIR_RE = /^(win32|linux|darwin)-(x64|arm64)$/;

/**
 * Permissive semver check (x.y.z with optional -prerelease / +build). Avoids a
 * dependency on the `semver` package, which this scripts/ tree does not carry.
 */
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Validate and (optionally) stamp the platform package versions against the meta
 * version. Reads/writes files under `repoRoot` but never calls process.exit.
 *
 * Two-pass: everything is read and validated before any write, so a validation
 * failure can never leave the tree in a torn, partially-stamped state.
 *
 * @param {{ repoRoot: string, check?: boolean }} opts
 * @returns {{ ok: boolean, metaVersion: (string|null), errors: string[],
 *             drifted: string[], stamped: string[], checked: number }}
 */
function syncPlatformPackageVersions({ repoRoot, check = false }) {
  const result = {
    ok: false,
    metaVersion: null,
    errors: [],
    drifted: [],
    stamped: [],
    checked: 0,
  };

  const sdkDir = join(repoRoot, "sdk", "node");
  const platformPackagesDir = join(sdkDir, "platform-packages");
  const metaPkgPath = join(sdkDir, "package.json");

  let metaVersion;
  try {
    metaVersion = JSON.parse(readFileSync(metaPkgPath, "utf8")).version;
  } catch (e) {
    result.errors.push(`Cannot read ${metaPkgPath}: ${e.message}`);
    return result;
  }
  if (typeof metaVersion !== "string" || metaVersion.length === 0) {
    result.errors.push("sdk/node/package.json has no version field");
    return result;
  }
  if (!VERSION_RE.test(metaVersion)) {
    result.errors.push(`Meta version "${metaVersion}" is not a valid semver`);
    return result;
  }
  result.metaVersion = metaVersion;

  if (!existsSync(platformPackagesDir)) {
    result.errors.push(`${platformPackagesDir} does not exist`);
    return result;
  }

  // The filesystem is the source of truth: any subdirectory whose package.json
  // names an @microsoft/mxc-sdk-* package is a platform package, regardless of
  // its directory name. This avoids a hardcoded os/arch regex silently skipping
  // a future platform dir (the exact drift hazard the sync is meant to kill),
  // while still ignoring tooling/metadata folders (.git, node_modules) — they
  // carry no such package.json.
  const dirs = readdirSync(platformPackagesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();

  // Pass 1: read + validate everything (no writes).
  const pending = [];
  for (const name of dirs) {
    const pkgPath = join(platformPackagesDir, name, "package.json");
    if (!existsSync(pkgPath)) {
      // Not a platform package (e.g. a tooling/metadata dir) — skip silently.
      continue;
    }
    let raw;
    let pkg;
    try {
      raw = readFileSync(pkgPath, "utf8");
      pkg = JSON.parse(raw);
    } catch (e) {
      result.errors.push(`${name}: cannot parse package.json: ${e.message}`);
      continue;
    }
    if (typeof pkg.name !== "string" || !pkg.name.startsWith("@microsoft/mxc-sdk-")) {
      // A package.json that isn't one of ours — not a platform package.
      continue;
    }
    if (typeof pkg.version !== "string" || !VERSION_RE.test(pkg.version)) {
      result.errors.push(
        `${pkg.name || name}: version "${pkg.version}" is not a valid semver`,
      );
      continue;
    }
    pending.push({ name, path: pkgPath, raw, pkg });
  }
  result.checked = pending.length;

  // Do not write anything if any package failed validation.
  if (result.errors.length > 0) {
    return result;
  }

  // Pass 2: detect drift; stamp when not in check mode.
  for (const item of pending) {
    if (item.pkg.version === metaVersion) {
      continue;
    }
    result.drifted.push(item.pkg.name);
    if (!check) {
      item.pkg.version = metaVersion;
      // Preserve the original trailing-newline style.
      const trailing = item.raw.endsWith("\n") ? "\n" : "";
      writeFileSync(item.path, JSON.stringify(item.pkg, null, 2) + trailing);
      result.stamped.push(item.pkg.name);
    }
  }

  // In check mode, any drift is failure; in stamp mode, success once written.
  result.ok = check ? result.drifted.length === 0 : true;
  return result;
}

module.exports = { syncPlatformPackageVersions };

// CLI wrapper — the only place that performs I/O side effects (console/exit).
if (require.main === module) {
  const check = process.argv.includes("--check");
  const repoRoot = join(__dirname, "..");
  const result = syncPlatformPackageVersions({ repoRoot, check });

  for (const e of result.errors) {
    console.error(`ERROR: ${e}`);
  }
  if (result.errors.length > 0) {
    process.exit(1);
  }

  if (check) {
    if (result.drifted.length > 0) {
      for (const name of result.drifted) {
        console.error(`DRIFT: ${name} != meta version ${result.metaVersion}`);
      }
      console.error(
        `\n${result.drifted.length} platform package version(s) drifted from ` +
          `meta version ${result.metaVersion}.`,
      );
      console.error("Run: node scripts/sync-platform-package-versions.js");
      process.exit(1);
    }
    console.log(
      `Platform package versions OK: ${result.checked} package(s) match ` +
        `meta version ${result.metaVersion}`,
    );
  } else {
    for (const name of result.stamped) {
      console.log(`Stamped ${name} -> ${result.metaVersion}`);
    }
    console.log(
      `Done: ${result.stamped.length} stamped to ${result.metaVersion} ` +
        `(${result.checked} platform package(s) checked)`,
    );
  }
}
