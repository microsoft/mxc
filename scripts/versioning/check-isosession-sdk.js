#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Fast, unzip-free consistency gate for the committed IsolationSession SDK
// NuGet under external/windows-sdk/isolation-session/. It asserts:
//   1. exactly one *.nupkg is committed;
//   2. the package filename is the canonical {id}.{version}.nupkg;
//   3. the committed GENERATION_INFO.toml carries `instance` and
//      `target_windows_crate`;
//   4. the `instance` (dot-stripped) equals the minor field of the package
//      version (the package version is 0.<instance-without-dots>.0, e.g.
//      instance "2026.06" -> version 0.202606.0).
//
// The deeper, package-internal gates (nuspec<->filename<->instance triangulation
// and winmd_sha256 verification) live in the bindings crate's build.rs, which
// can unzip the package. This script gives cross-platform CI fast feedback on
// the most common drift -- a bumped nupkg with a stale committed provenance --
// without needing a zip dependency.
//
//   node scripts/versioning/check-isosession-sdk.js

const { readFileSync, readdirSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const sdkDir = join(repoRoot, "external", "windows-sdk", "isolation-session");
const PACKAGE_ID = "Microsoft.Windows.AI.IsolationSession.SDK";

const errors = [];

// Minimal top-level `key = "value"` reader matching the bindings build.rs
// parser: exact key match (so `winmd` != `winmd_sha256`), comments ignored.
function parseTomlValue(contents, key) {
  for (const raw of contents.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("#")) continue;
    if (!line.startsWith(key)) continue;
    const rest = line.slice(key.length).trimStart();
    if (!rest.startsWith("=")) continue;
    return rest.slice(1).trim().replace(/^"|"$/g, "");
  }
  return undefined;
}

// (1) exactly one nupkg
let nupkgs = [];
try {
  nupkgs = readdirSync(sdkDir).filter((f) => f.toLowerCase().endsWith(".nupkg"));
} catch (e) {
  errors.push(`Cannot read ${sdkDir}: ${e.message}`);
}

if (nupkgs.length === 0) {
  errors.push(`No *.nupkg found in ${sdkDir} (expected exactly one).`);
} else if (nupkgs.length > 1) {
  errors.push(
    `Expected exactly one *.nupkg in ${sdkDir}, found ${nupkgs.length}: ${nupkgs.join(", ")}.`
  );
}

let instance;
let version;

if (nupkgs.length === 1) {
  const fileName = nupkgs[0];

  // (2) canonical {id}.{version}.nupkg
  const match = fileName.match(/^(.*)\.(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\.nupkg$/);
  if (!match) {
    errors.push(`nupkg filename '${fileName}' is not '{id}.{version}.nupkg'.`);
  } else {
    const [, id, ver] = match;
    version = ver;
    if (id !== PACKAGE_ID) {
      errors.push(
        `nupkg id '${id}' does not match expected '${PACKAGE_ID}' (filename '${fileName}').`
      );
    }
  }

  // (3) committed provenance carries instance + target_windows_crate
  let toml = "";
  try {
    toml = readFileSync(join(sdkDir, "GENERATION_INFO.toml"), "utf8");
  } catch (e) {
    errors.push(`Cannot read committed GENERATION_INFO.toml: ${e.message}`);
  }
  instance = parseTomlValue(toml, "instance");
  const targetCrate = parseTomlValue(toml, "target_windows_crate");
  if (!instance) {
    errors.push("Committed GENERATION_INFO.toml is missing `instance`.");
  }
  if (!targetCrate) {
    errors.push("Committed GENERATION_INFO.toml is missing `target_windows_crate`.");
  }

  // (4) instance (dot-stripped) == version minor
  if (instance && version) {
    const minor = version.split(".")[1];
    const instanceKey = instance.replace(/\./g, "");
    if (minor !== instanceKey) {
      errors.push(
        `Drift: GENERATION_INFO.toml instance='${instance}' (dot-stripped ` +
          `'${instanceKey}') but the package version is '${version}' (minor ` +
          `'${minor}'). Bump them in lockstep.`
      );
    }
  }
}

if (errors.length) {
  console.error("IsolationSession SDK check FAILED:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}

console.log(
  `IsolationSession SDK OK (package version ${version}, instance ${instance}).`
);
