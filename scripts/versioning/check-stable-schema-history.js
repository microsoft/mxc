#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// History guard for released stable schemas. Existing files are immutable and
// undeletable. A release change may add exactly one generated stable schema,
// advance stableLatest to that version, and must keep the dev inputs frozen for
// the duration of the release change.

const { execFileSync } = require("child_process");
const { join, resolve, basename } = require("path");
const {
  listFilesAtCommit,
  readFileAtCommit,
  resolveBaseCommit,
} = require("./lib/git-base");
const { validateStableHistory } = require("./lib/stable-schema-history");

const repoRoot = resolve(__dirname, "..", "..");
const STABLE_DIR = "schemas/stable";

function jsonAt(commit, path) {
  const content = readFileAtCommit(repoRoot, commit, path);
  if (content === null) throw new Error(`${path} is missing at ${commit}`);
  return JSON.parse(content);
}

function filesAt(commit) {
  return new Map(
    listFilesAtCommit(repoRoot, commit, STABLE_DIR).map((path) => [
      basename(path),
      readFileAtCommit(repoRoot, commit, path),
    ])
  );
}

function fail(errors) {
  console.error("Stable schema history check FAILED:");
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

let base;
try {
  base = resolveBaseCommit(repoRoot);
} catch (error) {
  fail([error.message]);
}

const baseSchemaVersion = jsonAt(base.commit, "schemas/schema-version.json");
const currentSchemaVersion = jsonAt("HEAD", "schemas/schema-version.json");
const baseDevPath = `schemas/dev/mxc-config.schema.${baseSchemaVersion.devSchemaFile}.json`;
const currentDevPath = `schemas/dev/mxc-config.schema.${currentSchemaVersion.devSchemaFile}.json`;

const result = validateStableHistory({
  baseFiles: filesAt(base.commit),
  currentFiles: filesAt("HEAD"),
  baseSchemaVersion,
  currentSchemaVersion,
  baseDevSchemaContent: readFileAtCommit(repoRoot, base.commit, baseDevPath),
  currentDevSchemaContent: readFileAtCommit(repoRoot, "HEAD", currentDevPath),
  baseStabilityContent: readFileAtCommit(
    repoRoot,
    base.commit,
    "schemas/config-stability.json"
  ),
  currentStabilityContent: readFileAtCommit(
    repoRoot,
    "HEAD",
    "schemas/config-stability.json"
  ),
});

if (result.errors.length) fail(result.errors);

if (result.newVersion) {
  try {
    execFileSync(
      process.execPath,
      [
        join(__dirname, "freeze-stable-schema.js"),
        "--check-release",
        result.newVersion.raw,
      ],
      { cwd: repoRoot, stdio: "inherit" }
    );
  } catch {
    process.exit(1);
  }
  console.log(
    `Stable schema history OK against ${base.ref} (${base.commit.slice(0, 8)}): ` +
      `added generated release ${result.newVersion.raw}.`
  );
} else {
  console.log(
    `Stable schema history OK against ${base.ref} (${base.commit.slice(0, 8)}): ` +
      "released schemas are unchanged."
  );
}
