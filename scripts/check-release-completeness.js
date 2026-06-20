#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Release-completeness gate. The on-disk platform-packages directory is the
// single canonical source of truth. The gate asserts:
//   - the expected set is non-empty (a missing/corrupt set can't pass silently);
//   - the meta package pins EXACTLY those packages at their versions (no missing,
//     wrong, or zombie optionalDependencies);
//   - every expected platform tarball was produced (no MISSING); and
//   - the tarball output dir contains ONLY expected tarballs (no stray/EXTRA
//     `.tgz` — including non-mxc ones — gets handed to `npm publish`).
//
//   META_PKG=<sdk/package.json> PLATFORM_PACKAGES_DIR=<sdk/platform-packages> \
//   TARBALL_DIR=<dir of *.tgz> node scripts/check-release-completeness.js
//
// The core is the exported `checkReleaseCompleteness()` (injectable fs for tests).

const fs = require("fs");
const { join } = require("path");
const { payloadFiles } = require("./platform-package-payload");

/**
 * Recursively collect every `.tgz` under `dir`, returned as paths relative to
 * `dir` using forward slashes (so a top-level file is just its filename and a
 * nested one is `sub/dir/file.tgz`).
 */
function walkTarballs(
  dir,
  { readdirSync = fs.readdirSync, statSync = fs.statSync, existsSync = fs.existsSync } = {},
  prefix = "",
) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const rel = prefix ? `${prefix}/${entry}` : entry;
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      isDir = false;
    }
    if (isDir) {
      out.push(...walkTarballs(full, { readdirSync, statSync, existsSync }, rel));
    } else if (entry.endsWith(".tgz")) {
      out.push(rel);
    }
  }
  return out;
}

/**
 * @param {{ metaPkgPath: string, platformPackagesDir: string, tarballDir: string,
 *           readFileSync?: Function, readdirSync?: Function, existsSync?: Function }} opts
 * @returns {{ ok: boolean, missing: string[], extra: string[], pinIssues: string[],
 *             malformed: string[], payloadMissing: string[], expected: number }}
 */
function checkReleaseCompleteness({
  metaPkgPath,
  platformPackagesDir,
  tarballDir,
  readFileSync = fs.readFileSync,
  readdirSync = fs.readdirSync,
  statSync = fs.statSync,
  existsSync = fs.existsSync,
}) {
  const result = {
    ok: false,
    missing: [],
    extra: [],
    pinIssues: [],
    malformed: [],
    payloadMissing: [],
    expected: 0,
  };

  const opt =
    (JSON.parse(readFileSync(metaPkgPath, "utf8")).optionalDependencies) || {};

  // Expected tarballs derived from the on-disk platform packages (canonical).
  const expected = new Map(); // tarball filename -> { name, version }
  const dirs = existsSync(platformPackagesDir) ? readdirSync(platformPackagesDir) : [];
  for (const d of dirs) {
    const pj = join(platformPackagesDir, d, "package.json");
    if (!existsSync(pj)) continue;
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(pj, "utf8"));
    } catch {
      // A directory under platform-packages/ with an UNPARSEABLE package.json is
      // a corrupt platform package, not a thing to skip silently: if we dropped
      // it, its absent tarball would never be reported MISSING and a broken set
      // could pass the gate. Treat it as a hard failure.
      result.malformed.push(`${d}/package.json`);
      continue;
    }
    if (typeof pkg.name !== "string" || !pkg.name.startsWith("@microsoft/mxc-sdk-")) {
      continue;
    }
    const tarball = `${pkg.name.replace("@microsoft/", "microsoft-")}-${pkg.version}.tgz`;
    expected.set(tarball, { name: pkg.name, version: pkg.version });
    // The meta package must pin this platform package at exactly its version.
    if (opt[pkg.name] !== pkg.version) {
      result.pinIssues.push(
        `${pkg.name}: meta pins "${opt[pkg.name]}" but the package is "${pkg.version}"`,
      );
    }
    // Every build-artifact entry of the package's `files` allowlist must be
    // present ON DISK in the package dir. `npm pack` silently omits absent
    // allowlisted files, so a producer that fails to stage part of the payload
    // (e.g. an official build that copies only its primary executor and not the
    // micro-VM nanvixd.exe / kernel snapshots) would otherwise publish a
    // binary-deficient package that this name-only gate never catches.
    for (const f of payloadFiles(pj, { readFileSync })) {
      if (!existsSync(join(platformPackagesDir, d, f))) {
        result.payloadMissing.push(`${d}/${f}`);
      }
    }
  }

  // The meta must not pin a platform package that has no on-disk source (zombie).
  const expectedNames = new Set([...expected.values()].map((e) => e.name));
  for (const name of Object.keys(opt)) {
    if (name.startsWith("@microsoft/mxc-sdk-") && !expectedNames.has(name)) {
      result.pinIssues.push(`${name}: pinned by meta but no platform package on disk`);
    }
  }

  // Recursively collect every .tgz under tarballDir (relative path from
  // tarballDir). The release upload publishes the WHOLE folder, so a nested
  // stray tarball must be caught too — not just top-level ones.
  const tarballs = walkTarballs(tarballDir, { readdirSync, statSync, existsSync });
  for (const t of expected.keys()) {
    if (!tarballs.includes(t)) result.missing.push(t);
  }
  // Reject ANY tarball whose relative path isn't exactly an expected top-level
  // filename — a stray .tgz (even non-mxc, even nested in a subdir) must not be
  // published under release credentials.
  for (const t of tarballs) {
    if (!expected.has(t)) result.extra.push(t);
  }

  result.expected = expected.size;
  result.ok =
    expected.size >= 1 &&
    result.missing.length === 0 &&
    result.extra.length === 0 &&
    result.pinIssues.length === 0 &&
    result.malformed.length === 0 &&
    result.payloadMissing.length === 0;
  return result;
}

module.exports = { checkReleaseCompleteness };

if (require.main === module) {
  const metaPkgPath = process.env.META_PKG;
  const platformPackagesDir = process.env.PLATFORM_PACKAGES_DIR;
  const tarballDir = process.env.TARBALL_DIR;
  if (!metaPkgPath || !platformPackagesDir || !tarballDir) {
    console.error(
      "check-release-completeness: META_PKG, PLATFORM_PACKAGES_DIR and TARBALL_DIR are required",
    );
    process.exit(2);
  }
  const r = checkReleaseCompleteness({ metaPkgPath, platformPackagesDir, tarballDir });
  for (const p of r.pinIssues) console.error(`PIN: ${p}`);
  for (const m of r.malformed) console.error(`MALFORMED platform manifest: ${m}`);
  for (const m of r.missing) console.error(`MISSING platform tarball: ${m}`);
  for (const p of r.payloadMissing) console.error(`MISSING payload file (not staged): ${p}`);
  for (const e of r.extra) console.error(`EXTRA (unexpected) tarball: ${e}`);
  if (r.expected === 0) {
    console.error("EMPTY: no platform packages found on disk — refusing an empty release.");
  }
  if (!r.ok) {
    console.error(
      `\nRelease completeness FAILED (${r.expected} expected, ${r.missing.length} missing, ` +
        `${r.payloadMissing.length} payload missing, ${r.malformed.length} malformed, ` +
        `${r.extra.length} extra, ${r.pinIssues.length} pin issue(s)).`,
    );
    process.exit(1);
  }
  console.log(
    `Release completeness OK: ${r.expected} platform package(s), each pinned and packed, no strays.`,
  );
}
