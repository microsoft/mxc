#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Keeps the per-platform binary packages under sdk/platform-packages/* version-
// locked to the meta package (sdk/package.json).
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
    pinDrift: [],
    pinStamped: [],
    checked: 0,
  };

  const sdkDir = join(repoRoot, "sdk");
  const platformPackagesDir = join(sdkDir, "platform-packages");
  const metaPkgPath = join(sdkDir, "package.json");

  let metaRaw;
  let metaPkg;
  try {
    metaRaw = readFileSync(metaPkgPath, "utf8");
    metaPkg = JSON.parse(metaRaw);
  } catch (e) {
    result.errors.push(`Cannot read ${metaPkgPath}: ${e.message}`);
    return result;
  }
  const metaVersion = metaPkg.version;
  if (typeof metaVersion !== "string" || metaVersion.length === 0) {
    result.errors.push("sdk/package.json has no version field");
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

  // Reconcile the meta package's optionalDependencies. It must pin EXACTLY the
  // on-disk platform packages, each at the meta version. The filesystem is the
  // single source of truth, so a missing pin (deleted/empty block), a stale
  // "zombie" pin with no backing package, a wrong version, or a non-exact range
  // are all flagged — not merely value drift among whichever keys happen to
  // already exist.
  const SCOPE_RE = /^@microsoft\/mxc-sdk-/;
  const optDeps = metaPkg.optionalDependencies || {};
  const expectedNames = pending.map((p) => p.pkg.name).sort();
  let metaDirty = false;

  // Missing or mis-pinned expected packages (exact pin required).
  for (const name of expectedNames) {
    if (optDeps[name] === metaVersion) {
      continue;
    }
    if (check) {
      result.pinDrift.push(
        optDeps[name] === undefined
          ? `optionalDependencies is missing "${name}" (expected exact "${metaVersion}")`
          : `optionalDependencies["${name}"] is "${optDeps[name]}" but expected exact "${metaVersion}"`,
      );
    } else {
      optDeps[name] = metaVersion;
      metaDirty = true;
      result.pinStamped.push(name);
    }
  }

  // Stale/zombie @microsoft/mxc-sdk-* pins not backed by a platform package dir.
  for (const name of Object.keys(optDeps)) {
    if (SCOPE_RE.test(name) && !expectedNames.includes(name)) {
      if (check) {
        result.pinDrift.push(
          `optionalDependencies has stale pin "${name}" with no platform package`,
        );
      } else {
        delete optDeps[name];
        metaDirty = true;
        result.pinStamped.push(`-${name}`);
      }
    }
  }

  if (metaDirty) {
    metaPkg.optionalDependencies = optDeps;
    const trailing = metaRaw.endsWith("\n") ? "\n" : "";
    writeFileSync(metaPkgPath, JSON.stringify(metaPkg, null, 2) + trailing);
  }

  // In check mode, any version or pin drift is failure; in stamp mode, success
  // once the writes are applied.
  result.ok = check
    ? result.drifted.length === 0 && result.pinDrift.length === 0
    : true;
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
    const issues = result.drifted.length + result.pinDrift.length;
    for (const name of result.drifted) {
      console.error(`DRIFT: ${name} != meta version ${result.metaVersion}`);
    }
    for (const msg of result.pinDrift) {
      console.error(`DRIFT: ${msg}`);
    }
    if (issues > 0) {
      console.error(
        `\n${issues} version/pin issue(s) vs meta version ${result.metaVersion}.`,
      );
      console.error("Run: node scripts/sync-platform-package-versions.js");
      process.exit(1);
    }
    console.log(
      `Platform package versions OK: ${result.checked} package(s) and the meta ` +
        `optionalDependencies pins all match ${result.metaVersion}`,
    );
  } else {
    for (const name of result.stamped) {
      console.log(`Stamped ${name} -> ${result.metaVersion}`);
    }
    for (const name of result.pinStamped) {
      console.log(`Stamped optionalDependencies ${name} -> ${result.metaVersion}`);
    }
    const changed = result.stamped.length + result.pinStamped.length;
    console.log(
      `Done: ${changed} change(s) at ${result.metaVersion} ` +
        `(${result.checked} platform package(s) checked)`,
    );
    if (changed > 0) {
      console.warn(
        "Note: sdk/package.json changed — run `npm install --package-lock-only` " +
          "in sdk/ to refresh package-lock.json.",
      );
    }
  }
}
