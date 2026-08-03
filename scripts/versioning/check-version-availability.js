#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Version-availability oracle gate.
//
// A `since` annotation is a claim about history, and the frozen stable schemas
// record which fields existed when — so it is checked rather than trusted. A
// mistyped bound would otherwise silently start rejecting configs that were
// always valid.
//
//   * `x-mxc-since: S` — the field's first appearance must be exactly S.
//   * `x-mxc-until: U` — the field must exist at U. (An upper bound is not
//     derivable from presence: a retired field stays in the dev schema on
//     purpose, since one dev schema validates every supported version.)
//
// Ranges are read from the generated dev schema, not `wire.rs`: they are
// emitted there from the same derive the parser enforces, and
// `check-schema-codegen.js` fails if the two drift.
//
// Run from anywhere (paths are resolved relative to the repo root):
//   node scripts/versioning/check-version-availability.js

const { readFileSync, readdirSync } = require("fs");
const { join, resolve } = require("path");
const { parseMajorMinor, compareMajorMinor, majorMinor } = require("./lib/version.js");
const {
  SINCE_KEY,
  UNTIL_KEY,
  collectPropertyPaths,
  collectDeclaredAvailability,
  checkAvailability,
} = require("./lib/version-availability.js");

const repoRoot = resolve(__dirname, "..", "..");

function readJson(...parts) {
  return JSON.parse(readFileSync(join(repoRoot, ...parts), "utf8"));
}

const schemaVer = readJson("schemas", "schema-version.json");

// Derived from the canonical version file plus the stable schemas on disk: a
// hard-coded timeline would attach a stale label to a bumped dev schema.
function discoverTimeline() {
  const stableDir = join(repoRoot, "schemas", "stable");
  const floor = parseMajorMinor(majorMinor(schemaVer.min));
  if (!floor) {
    throw new Error(`schema-version.json: 'min' (${schemaVer.min}) is not a version`);
  }

  const stable = readdirSync(stableDir)
    .map((name) => /^mxc-config\.schema\.(.+)\.json$/.exec(name))
    .filter(Boolean)
    .map((m) => ({ file: join("schemas", "stable", m[0]), label: majorMinor(m[1]) }))
    .filter((entry) => entry.label !== null)
    .map((entry) => ({ ...entry, version: parseMajorMinor(entry.label) }))
    // Below the floor a schema can no longer be used by any config.
    .filter((entry) => entry.version && compareMajorMinor(entry.version, floor) >= 0);

  const devLabel = majorMinor(schemaVer.maxSupported);
  const devVersion = parseMajorMinor(devLabel);
  if (!devVersion) {
    throw new Error(
      `schema-version.json: 'maxSupported' (${schemaVer.maxSupported}) is not a version`
    );
  }
  const dev = {
    file: join("schemas", "dev", `mxc-config.schema.${schemaVer.devSchemaFile}.json`),
    label: devLabel,
    version: devVersion,
  };

  // One entry per version line, preferring the in-progress dev schema.
  const entries = [...stable.filter((e) => e.label !== dev.label), dev];
  entries.sort((a, b) => compareMajorMinor(a.version, b.version));
  return entries;
}

const timeline = discoverTimeline().map((entry) => ({
  ...entry,
  paths: collectPropertyPaths(readJson(entry.file)),
}));

if (timeline.length < 2) {
  console.error(
    "ERROR: need at least two schemas to derive a first appearance, found " +
      timeline.map((t) => t.label).join(", ")
  );
  process.exit(1);
}

const devSchema = readJson(timeline[timeline.length - 1].file);
const declared = collectDeclaredAvailability(devSchema);

let result;
try {
  result = checkAvailability({ declared, timeline, compareMajorMinor });
} catch (e) {
  console.error("Version-availability oracle check FAILED:");
  console.error(`  - ${e.message}`);
  process.exit(1);
}
const { errors, checked } = result;

if (errors.length > 0) {
  console.error("Version-availability oracle check FAILED:");
  for (const e of errors) console.error(`  - ${e}`);
  console.error(
    `\n${errors.length} problem(s). Availability ranges are declared with #[mxc_version(...)] in ` +
      `src/core/wxc_common/src/wire.rs and published into the dev schema as ` +
      `${SINCE_KEY} / ${UNTIL_KEY}.`
  );
  process.exit(1);
}

console.log(
  `Version-availability oracle OK: ${checked} declared availability range(s) agree with the ` +
    `${timeline.map((t) => t.label).join(" / ")} schemas.`
);
