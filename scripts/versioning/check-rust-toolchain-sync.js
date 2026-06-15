#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that src/rust-toolchain.toml (`channel = "1.<N>"`) matches the
// `ms-prod-1.<N>` pin in every ADO job template that uses templateContext.rust.
// The ADO official build installs Microsoft's internal Rust toolchain from
// Mxc-Azure-Feed; keeping it in sync with the public rustup channel used by
// the repo (and all other CI) prevents the official build from compiling
// against a different Rust version than dev / GitHub Actions.
//
//   node scripts/versioning/check-rust-toolchain-sync.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const adoTemplates = [
  ".azure-pipelines/templates/Rust.Build.Job.yml",
  ".azure-pipelines/templates/Mac.Build.Job.yml",
];

const read = (relPath) => readFileSync(join(repoRoot, relPath), "utf8");
const errors = [];

const channel = read("src/rust-toolchain.toml").match(/^\s*channel\s*=\s*"([^"]+)"/m)?.[1];
if (!channel) errors.push("Missing `channel = \"...\"` in src/rust-toolchain.toml");

const adoPins = adoTemplates.map((path) => {
  const version = read(path).match(/^\s*version:\s*['"]?ms-prod-(\d+\.\d+(?:\.\d+)?)['"]?\s*$/m)?.[1];
  if (!version) errors.push(`Missing \`version: 'ms-prod-<version>'\` in ${path}`);
  return { path, version };
});

if (channel) {
  for (const { path, version } of adoPins) {
    if (version && version !== channel) {
      errors.push(
        `Drift: src/rust-toolchain.toml channel="${channel}" but ${path} pins ` +
        `"ms-prod-${version}". Bump both in the same commit.`
      );
    }
  }
}

if (errors.length) {
  console.error("Rust toolchain sync check FAILED:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}

const pinSummary = adoPins.map((p) => `${p.path}=ms-prod-${p.version}`).join(", ");
console.log(`Rust toolchain sync OK (channel ${channel}; ${pinSummary})`);
