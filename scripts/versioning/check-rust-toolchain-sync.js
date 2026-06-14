#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates that the Rust toolchain pin in src/rust-toolchain.toml matches
// the `ms-prod-1.<N>` version pinned in each ADO job that drives the 1ES
// Rust virtual tasks (Rust.Build.Job.yml and Mac.Build.Job.yml). The rustup
// file pins `channel = "1.<N>"`; the ADO templates pin the matching
// internal toolchain from Mxc-Azure-Feed. All three must move together.
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

const adoTemplates = [
  [".azure-pipelines", "templates", "Rust.Build.Job.yml"],
  [".azure-pipelines", "templates", "Mac.Build.Job.yml"],
];

const adoPins = [];
for (const parts of adoTemplates) {
  const relPath = parts.join("/");
  const content = read(...parts);
  const match = content.match(/version:\s*'ms-prod-(\d+\.\d+(?:\.\d+)?)'/);
  if (!match) {
    errors.push(`Could not find \`version: 'ms-prod-<version>'\` in ${relPath}`);
    continue;
  }
  adoPins.push({ relPath, version: match[1] });
}

if (rustupChannel) {
  for (const { relPath, version } of adoPins) {
    if (version !== rustupChannel) {
      errors.push(
        `Rust toolchain drift: src/rust-toolchain.toml channel="${rustupChannel}" ` +
        `but ${relPath} pins "ms-prod-${version}". Bump both in the same commit.`
      );
    }
  }
}

if (errors.length > 0) {
  console.error("Rust toolchain sync check FAILED:");
  for (const e of errors) console.error("  - " + e);
  process.exit(1);
}

const summary = adoPins.map(p => `${p.relPath}=ms-prod-${p.version}`).join(", ");
console.log(`Rust toolchain sync OK (rustup channel ${rustupChannel}; ${summary})`);
