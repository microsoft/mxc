#!/usr/bin/env node
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Validates the SCHEMA version constants — the Rust parser, the SDK, and the
// schema filenames must all agree with the canonical source of truth at
// schemas/schema-version.json. This tracks the config wire format and is
// deliberately separate from the PRODUCT version (Cargo / npm package), which
// is checked by scripts/check-version-sync.js.
//
// Run from anywhere (paths are resolved relative to the repo root):
//
//   node scripts/versioning/check-schema-versions.js

const { readFileSync, existsSync } = require("fs");
const { join } = require("path");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

function read(...parts) {
  return readFileSync(join(repoRoot, ...parts), "utf8");
}

// ---------------------------------------------------------------------------
// Schema version constants vs canonical source
// ---------------------------------------------------------------------------
const schemaVer = JSON.parse(read("schemas", "schema-version.json"));
const { min, maxSupported, stateAware, stableLatest, devSchemaFile } = schemaVer;

// major.minor of a semver-ish "X.Y.Z[-pre]" string.
function majorMinor(v) {
  const m = /^(\d+)\.(\d+)\./.exec(v);
  return m ? `${m[1]}.${m[2]}` : null;
}

// Assert a regex captures exactly `expected` in `text`.
function expectConst(file, text, label, regex, expected) {
  const m = regex.exec(text);
  if (!m) {
    errors.push(`${file}: could not find ${label} (pattern ${regex})`);
    return;
  }
  if (m[1] !== expected) {
    errors.push(
      `${file}: ${label} is "${m[1]}" but canonical schema-version expects "${expected}"`
    );
  }
}

// -- Rust parser (src/core/wxc_common/src/config_parser.rs) --
const parser = read("src", "core", "wxc_common", "src", "config_parser.rs");
expectConst(
  "config_parser.rs",
  parser,
  "CURRENT_SCHEMA_VERSION",
  /const CURRENT_SCHEMA_VERSION:\s*&str\s*=\s*"([^"]+)"/,
  maxSupported
);
// SUPPORTED_VERSION is a semver range like ">=0.4, <=0.7"; its bounds must
// match the canonical min/maxSupported major.minor.
const supMatch = /const SUPPORTED_VERSION:\s*&str\s*=\s*">=([^,]+),\s*<=([^"]+)"/.exec(
  parser
);
if (!supMatch) {
  errors.push("config_parser.rs: could not find SUPPORTED_VERSION range");
} else {
  if (supMatch[1].trim() !== majorMinor(min)) {
    errors.push(
      `config_parser.rs: SUPPORTED_VERSION lower bound ">=${supMatch[1].trim()}" but canonical min is ${min} (${majorMinor(min)})`
    );
  }
  if (supMatch[2].trim() !== majorMinor(maxSupported)) {
    errors.push(
      `config_parser.rs: SUPPORTED_VERSION upper bound "<=${supMatch[2].trim()}" but canonical maxSupported is ${maxSupported} (${majorMinor(maxSupported)})`
    );
  }
}

// -- SDK (sdk/src/sandbox.ts, sdk/src/state-aware-helper.ts) --
const sandboxTs = read("sdk", "src", "sandbox.ts");
expectConst(
  "sandbox.ts",
  sandboxTs,
  "SUPPORTED_VERSION",
  /const SUPPORTED_VERSION\s*=\s*'([^']+)'/,
  maxSupported
);
expectConst(
  "sandbox.ts",
  sandboxTs,
  "MIN_VERSION",
  /const MIN_VERSION\s*=\s*'([^']+)'/,
  min
);
const stateAwareTs = read("sdk", "src", "state-aware-helper.ts");
expectConst(
  "state-aware-helper.ts",
  stateAwareTs,
  "STATE_AWARE_VERSION",
  /const STATE_AWARE_VERSION\s*=\s*'([^']+)'/,
  stateAware
);

// -- Schema files exist for the declared stable + dev versions --
const stablePath = join(
  "schemas",
  "stable",
  `mxc-config.schema.${stableLatest}.json`
);
if (!existsSync(join(repoRoot, stablePath))) {
  errors.push(`Missing stable schema file for stableLatest "${stableLatest}": ${stablePath}`);
}
const devPath = join("schemas", "dev", `mxc-config.schema.${devSchemaFile}.json`);
if (!existsSync(join(repoRoot, devPath))) {
  errors.push(`Missing dev schema file for devSchemaFile "${devSchemaFile}": ${devPath}`);
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------
if (errors.length > 0) {
  console.error("Schema version sync FAILED:");
  for (const e of errors) console.error(`  - ${e}`);
  console.error(
    "\nFix the offending constant, or update schemas/schema-version.json if the canonical value changed."
  );
  process.exit(1);
}

console.log(`Schema version sync OK: maxSupported ${maxSupported} (min ${min}, state-aware ${stateAware}, stable ${stableLatest})`);
