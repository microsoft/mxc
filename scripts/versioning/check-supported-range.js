#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// A single current wire model parses every version in [min, maxSupported].
// Therefore a stable release may keep older lines in that range only when the
// new generated schema remains backward compatible with them. A breaking
// release must advance min to its own major.minor line.

const { resolve } = require("path");
const {
  readFileAtCommit,
  resolveBaseCommit,
} = require("./lib/git-base");
const { detectBreaking } = require("./lib/schema-compatibility");
const {
  evaluateSupportedRange,
  validateGeneratedStableFloor,
  validateMinHistory,
} = require("./lib/supported-range-contract");
const { compareVersions, parseVersion } = require("./lib/version");

const repoRoot = resolve(__dirname, "..", "..");

function fail(errors, breaks = []) {
  console.error("Supported schema range check FAILED:");
  for (const error of errors) console.error(`  - ${error}`);
  for (const detail of breaks.slice(0, 20)) console.error(`  - ${detail}`);
  if (breaks.length > 20) {
    console.error(`  - ...and ${breaks.length - 20} more breaking change(s)`);
  }
  process.exit(1);
}

function jsonAt(commit, path) {
  const content = readFileAtCommit(repoRoot, commit, path);
  if (content === null) fail([`${path} is missing at ${commit}`]);
  return JSON.parse(content);
}

let base;
try {
  base = resolveBaseCommit(repoRoot);
} catch (error) {
  fail([error.message]);
}

const previousVersions = jsonAt(base.commit, "schemas/schema-version.json");
const currentVersions = jsonAt("HEAD", "schemas/schema-version.json");
const floorErrors = validateGeneratedStableFloor(
  previousVersions.generatedStableFloor,
  currentVersions.generatedStableFloor
);
if (floorErrors.length) fail(floorErrors);
const minErrors = validateMinHistory(
  previousVersions.min,
  currentVersions.min
);
if (minErrors.length) fail(minErrors);

if (previousVersions.stableLatest === currentVersions.stableLatest) {
  console.log(
    `Supported schema range OK against ${base.ref} (${base.commit.slice(0, 8)}): no new stable release.`
  );
  process.exit(0);
}

const previous = parseVersion(previousVersions.stableLatest);
const generatedFloor = parseVersion(currentVersions.generatedStableFloor);
if (!previous || !generatedFloor) {
  fail(["stableLatest or generatedStableFloor is not valid semver"]);
}

let breaks = [];
if (compareVersions(previous, generatedFloor) >= 0) {
  const previousPath =
    `schemas/stable/mxc-config.schema.${previousVersions.stableLatest}.json`;
  const nextPath =
    `schemas/stable/mxc-config.schema.${currentVersions.stableLatest}.json`;
  const previousSchema = jsonAt(base.commit, previousPath);
  const nextSchema = jsonAt("HEAD", nextPath);
  breaks = detectBreaking(previousSchema, nextSchema);
}

const result = evaluateSupportedRange({
  previousVersion: previousVersions.stableLatest,
  newVersion: currentVersions.stableLatest,
  minVersion: currentVersions.min,
  generatedStableFloor: currentVersions.generatedStableFloor,
  breaks,
});
if (result.errors.length) fail(result.errors, breaks);

if (result.mode === "legacy-boundary") {
  console.log(
    `Supported schema range OK: first generated stable release ${currentVersions.stableLatest} ` +
      `advances the floor to ${currentVersions.min}.`
  );
} else if (breaks.length) {
  console.log(
    `Supported schema range OK: ${currentVersions.stableLatest} has ${breaks.length} breaking change(s) ` +
      `and advances the floor to ${currentVersions.min}.`
  );
} else {
  console.log(
    `Supported schema range OK: ${previousVersions.stableLatest} remains compatible with ` +
      `${currentVersions.stableLatest}; floor ${currentVersions.min} may remain supported.`
  );
}
