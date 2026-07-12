#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Breaking-change guard (Phase 5b): a stable schema change must use a version
// gap that permits breaking the config contract. Pre-1.0 that means at least a
// minor bump; at and after 1.0 it means a major bump. Same-line transitions are
// structurally compared with the shared compatibility detector.

const { readFileSync, readdirSync } = require("fs");
const { join, resolve } = require("path");
const { detectBreaking } = require("./lib/schema-compatibility");
const {
  compareVersions,
  parseVersion,
} = require("./lib/version");

const repoRoot = resolve(__dirname, "..", "..");
const readJson = (...parts) =>
  JSON.parse(readFileSync(join(repoRoot, ...parts), "utf8"));
const STABLE_DIR = join("schemas", "stable");
const FILE_RE = /^mxc-config\.schema\.(.+)\.json$/;

function fail(lines) {
  console.error("Breaking-change guard FAILED:");
  for (const line of lines) console.error(`  - ${line}`);
  process.exit(1);
}

const schemaVersion = readJson("schemas", "schema-version.json");
const latest = parseVersion(schemaVersion.stableLatest);
if (!latest) {
  fail([
    `schema-version.json stableLatest "${schemaVersion.stableLatest}" is not parseable semver.`,
  ]);
}

const versions = readdirSync(join(repoRoot, STABLE_DIR))
  .map((file) => FILE_RE.exec(file))
  .filter(Boolean)
  .map((match) => parseVersion(match[1]))
  .filter(Boolean)
  .sort(compareVersions);

const current = versions.find((version) => version.raw === latest.raw);
if (!current) fail([`no stable schema file for stableLatest "${latest.raw}".`]);

const below = versions.filter(
  (version) => compareVersions(version, current) < 0
);
if (below.length === 0) {
  console.log(
    `Breaking-change guard: no prior stable schema below ${latest.raw}; nothing to compare.`
  );
  process.exit(0);
}
const previous = below[below.length - 1];

const breakingAllowed =
  current.major === 0
    ? current.minor !== previous.minor
    : current.major !== previous.major;
if (breakingAllowed) {
  console.log(
    `Breaking-change guard: ${previous.raw} -> ${current.raw} is a ` +
      `${current.major === 0 ? "minor" : "major"} bump; breaking changes permitted. Skipped.`
  );
  process.exit(0);
}

const previousSchema = readJson(
  STABLE_DIR,
  `mxc-config.schema.${previous.raw}.json`
);
const currentSchema = readJson(
  STABLE_DIR,
  `mxc-config.schema.${current.raw}.json`
);
const breaks = detectBreaking(previousSchema, currentSchema);
if (breaks.length) {
  fail([
    `${previous.raw} -> ${current.raw} is only a patch/pre-release change but contains breaking schema change(s):`,
    ...breaks,
    `A breaking change requires at least a ${current.major === 0 ? "minor" : "major"} version bump.`,
  ]);
}

console.log(
  `Breaking-change guard OK: ${previous.raw} -> ${current.raw} ` +
    `(same ${current.major}.${current.minor}) has no breaking schema changes.`
);
