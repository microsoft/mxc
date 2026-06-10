#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that the Rust toolchain pin in src/rust-toolchain.toml matches
// the `rustVersion` default in .azure-pipelines/templates/Rust.Build.Steps.Official.yml.
// The ADO official build installs `ms-prod-1.<N>` from the Mxc-Azure-Feed;
// the rustup file pins `channel = "1.<N>"`. They must move together.
//
//   node scripts/versioning/check-rust-toolchain-sync.js

const { readFileSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

function read(...parts) {
  return readFileSync(join(repoRoot, ...parts), "utf8");
}

const toolchainToml = read("src", "rust-toolchain.toml");
const channelMatch = toolchainToml.match(/^\s*channel\s*=\s*"([^"]+)"/m);
if (!channelMatch) {
  errors.push("Could not find `channel = \"...\"` in src/rust-toolchain.toml");
}
const rustupChannel = channelMatch ? channelMatch[1] : null;

const adoTemplate = read(".azure-pipelines", "templates", "Rust.Build.Steps.Official.yml");
const adoMatch = adoTemplate.match(/default:\s*'ms-prod-(\d+\.\d+(?:\.\d+)?)'/);
if (!adoMatch) {
  errors.push("Could not find `default: 'ms-prod-<version>'` in .azure-pipelines/templates/Rust.Build.Steps.Official.yml");
}
const adoVersion = adoMatch ? adoMatch[1] : null;

if (rustupChannel && adoVersion && rustupChannel !== adoVersion) {
  errors.push(
    `Rust toolchain drift: src/rust-toolchain.toml channel="${rustupChannel}" ` +
    `but .azure-pipelines/templates/Rust.Build.Steps.Official.yml pins "ms-prod-${adoVersion}". ` +
    `Bump both in the same commit.`
  );
}

if (errors.length > 0) {
  console.error("Rust toolchain sync check FAILED:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}

console.log(`Rust toolchain sync OK (${rustupChannel} == ms-prod-${adoVersion})`);
