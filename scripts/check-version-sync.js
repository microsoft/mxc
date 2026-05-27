#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that the workspace Cargo.toml version and sdk/package.json version
// are in sync.  Run from the repository root:
//
//   node scripts/check-version-sync.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..");

const cargoToml = readFileSync(join(repoRoot, "src", "Cargo.toml"), "utf8");
const cargoMatch = cargoToml.match(
  /\[workspace\.package\]\s*\n\s*version\s*=\s*"([^"]+)"/
);
if (!cargoMatch) {
  console.error(
    "ERROR: Could not find [workspace.package] version in src/Cargo.toml"
  );
  process.exit(1);
}
const cargoVersion = cargoMatch[1];

const packageJson = JSON.parse(
  readFileSync(join(repoRoot, "sdk", "package.json"), "utf8")
);
const npmVersion = packageJson.version;

if (cargoVersion !== npmVersion) {
  console.error(
    `ERROR: Version mismatch — src/Cargo.toml has "${cargoVersion}" but sdk/package.json has "${npmVersion}"`
  );
  process.exit(1);
}

console.log(`Version sync OK: ${cargoVersion}`);
