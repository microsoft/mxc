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

const { readFileSync, existsSync, readdirSync } = require("fs");
const { join } = require("path");
const {
  compareMajorMinor,
  compareVersions,
  majorMinor,
  parseVersion,
} = require("./lib/version");
const {
  validatePreFloorDevLine,
} = require("./lib/supported-range-contract");

const repoRoot = join(__dirname, "..", "..");
const errors = [];

function read(...parts) {
  return readFileSync(join(repoRoot, ...parts), "utf8");
}

// ---------------------------------------------------------------------------
// Schema version constants vs canonical source
// ---------------------------------------------------------------------------
const schemaVer = JSON.parse(read("schemas", "schema-version.json"));
const {
  min,
  maxSupported,
  stateAware,
  stableLatest,
  generatedStableFloor,
  devSchemaFile,
} = schemaVer;

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
// SUPPORTED_VERSION is a semver range like ">=0.6, <=0.8"; its bounds must
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

// -- SDK (sdk/node/src/sandbox.ts, sdk/node/src/state-aware-helper.ts) --
const sandboxTs = read("sdk", "node", "src", "sandbox.ts");
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
const stateAwareTs = read("sdk", "node", "src", "state-aware-helper.ts");
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

// -- Semantic ordering of the canonical version fields --
const parsed = {
  min: parseVersion(min),
  maxSupported: parseVersion(maxSupported),
  stateAware: parseVersion(stateAware),
  stableLatest: parseVersion(stableLatest),
  generatedStableFloor: parseVersion(generatedStableFloor),
  devSchemaFile: parseVersion(devSchemaFile),
};
for (const [name, value] of Object.entries(parsed)) {
  if (!value) errors.push(`schema-version.json ${name} is not valid semver`);
}
if (Object.values(parsed).every(Boolean)) {
  errors.push(
    ...validatePreFloorDevLine(
      stableLatest,
      maxSupported,
      generatedStableFloor
    )
  );
  if (compareVersions(parsed.min, parsed.stableLatest) > 0) {
    errors.push(`schema-version.json min ${min} is newer than stableLatest ${stableLatest}`);
  }
  if (compareVersions(parsed.stableLatest, parsed.maxSupported) > 0) {
    errors.push(
      `schema-version.json stableLatest ${stableLatest} is newer than maxSupported ${maxSupported}`
    );
  }
  if (
    compareVersions(parsed.stateAware, parsed.min) < 0 ||
    compareVersions(parsed.stateAware, parsed.maxSupported) > 0
  ) {
    errors.push(
      `schema-version.json stateAware ${stateAware} must be within [${min}, ${maxSupported}]`
    );
  }
  if (compareVersions(parsed.generatedStableFloor, parsed.maxSupported) > 0) {
    errors.push(
      `schema-version.json generatedStableFloor ${generatedStableFloor} is newer than maxSupported ${maxSupported}`
    );
  }
  if (
    compareVersions(parsed.stableLatest, parsed.generatedStableFloor) >= 0
  ) {
    const generatedFloorPath = join(
      "schemas",
      "stable",
      `mxc-config.schema.${generatedStableFloor}.json`
    );
    if (!existsSync(join(repoRoot, generatedFloorPath))) {
      errors.push(
        `Missing first generated stable schema "${generatedStableFloor}": ${generatedFloorPath}`
      );
    }
    if (compareMajorMinor(parsed.min, parsed.generatedStableFloor) < 0) {
      errors.push(
        `schema-version.json min ${min} cannot remain below generatedStableFloor ${generatedStableFloor} once that release exists`
      );
    }
  }
  if (majorMinor(parsed.devSchemaFile) !== majorMinor(parsed.maxSupported)) {
    errors.push(
      `devSchemaFile ${devSchemaFile} must share maxSupported's ${majorMinor(parsed.maxSupported)} line`
    );
  }
}

const stableVersions = readdirSync(join(repoRoot, "schemas", "stable"))
  .map((file) => /^mxc-config\.schema\.(.+)\.json$/.exec(file))
  .filter(Boolean)
  .map((match) => parseVersion(match[1]))
  .filter(Boolean)
  .sort(compareVersions);
const highestStable = stableVersions[stableVersions.length - 1];
if (highestStable && highestStable.raw !== stableLatest) {
  errors.push(
    `stableLatest ${stableLatest} is not the highest stable schema file (${highestStable.raw})`
  );
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
