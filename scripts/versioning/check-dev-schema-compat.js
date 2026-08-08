#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Dev-schema compatibility gate.
//
// Every other breaking-change guard in this directory compares RELEASED stable
// schemas, and only at release time. That leaves the surface a pull request
// actually edits -- the dev schema -- unguarded: a PR can delete a stable field,
// regenerate the schema and the SDK types, migrate the fixtures, and merge
// green. PR #676 did exactly that.
//
// This gate closes that hole by comparing the dev schema at the pull request
// base against the dev schema at HEAD and blocking any structural restriction
// of the accepted instance set.
//
// There is deliberately no per-field escape hatch. A field may not simply
// disappear: the supported-availability range is what allows surface to end, so
// until a change moves that window the only correct answer is to keep accepting
// what the base accepted.
//
//   node scripts/versioning/check-dev-schema-compat.js
//   node scripts/versioning/check-dev-schema-compat.js --base-ref origin/main

const { resolve } = require("path");
const { readFileAtCommit, resolveBaseCommit } = require("./lib/git-base");
const { detectBreaking } = require("./lib/schema-compatibility");

const repoRoot = resolve(__dirname, "..", "..");

function fail(lines) {
  console.error("Dev schema compatibility FAILED:");
  for (const line of lines) console.error(`  - ${line}`);
  process.exit(1);
}

function jsonAtCommit(commit, path) {
  const content = readFileAtCommit(repoRoot, commit, path);
  if (content === null) return null;
  try {
    return JSON.parse(content);
  } catch (error) {
    fail([`${path} at ${commit} is not valid JSON: ${error.message}`]);
  }
}

let base;
try {
  base = resolveBaseCommit(repoRoot);
} catch (error) {
  fail([error.message]);
}

const devSchemaPath = (versions) =>
  `schemas/dev/mxc-config.schema.${versions.devSchemaFile}.json`;

const baseVersions = jsonAtCommit(base.commit, "schemas/schema-version.json");
const headVersions = jsonAtCommit("HEAD", "schemas/schema-version.json");
if (!baseVersions || !headVersions) {
  fail(["schemas/schema-version.json is missing at the base or at HEAD"]);
}
for (const [label, versions] of [
  [base.ref, baseVersions],
  ["HEAD", headVersions],
]) {
  if (typeof versions.devSchemaFile !== "string" || !versions.devSchemaFile) {
    fail([`schemas/schema-version.json at ${label} has no devSchemaFile`]);
  }
}

// Each side is read at its own declared dev line. Opening a new dev line copies
// the outgoing one, so the two documents stay the same lineage and the
// structural comparison remains meaningful across that transition. Skipping the
// comparison when the line moves -- or resolving both sides at the base path --
// would let a pull request escape the gate by editing one line of
// schemas/schema-version.json.
const basePath = devSchemaPath(baseVersions);
const headPath = devSchemaPath(headVersions);
const baseSchema = jsonAtCommit(base.commit, basePath);
const headSchema = jsonAtCommit("HEAD", headPath);
if (!baseSchema) fail([`${basePath} is missing at ${base.ref}`]);
if (!headSchema) fail([`${headPath} is missing at HEAD`]);

const moved =
  baseVersions.devSchemaFile === headVersions.devSchemaFile
    ? ""
    : ` (dev line moved ${baseVersions.devSchemaFile} -> ${headVersions.devSchemaFile})`;

const findings = detectBreaking(baseSchema, headSchema);

if (findings.length > 0) {
  fail([
    `the dev schema removes or restricts surface that callers may already ` +
      `depend on, compared against ${base.ref} ` +
      `${base.commit.slice(0, 8)}${moved}:`,
    ...findings,
    `Configs declaring an already-supported version must keep parsing. Add ` +
      `surface instead of removing it, or move the supported-availability range ` +
      `in the same change.`,
  ]);
}

console.log(
  `Dev schema compatibility OK against ${base.ref} ` +
    `(${base.commit.slice(0, 8)})${moved}: no breaking change.`
);
